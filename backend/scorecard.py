"""可配置风险评分卡（Scorecard）：因子分档 + 加权求和 + 等级映射。

评分卡 JSON 结构约定：
{
  "id": "sc_payment_risk",
  "name": "支付交易评分卡",
  "description": "支付/转账类事件的综合风险评分",
  "enabled": true,
  "apply_when": [{"field": "type", "op": "in", "value": ["payment", "transfer"]}],
  "base_score": 0,            # 基础分（所有命中事件先加上的底分）
  "max_score": 100,           # 总分上限（clamp）
  "factors": [
    {
      "id": "f_amount", "name": "交易金额", "field": "amount", "weight": 1.0,
      "when": [],              # 可选：因子生效条件（不满足则跳过该因子）
      "missing_score": 0,      # 字段缺失时得分
      "default_score": 0,      # 未命中任何分档时得分
      "tiers": [               # 数值区间档：min 含、max 不含，缺省表示无界
        {"max": 1000, "score": 5, "label": "小额"},
        {"min": 1000, "max": 10000, "score": 20},
        {"min": 10000, "score": 80, "label": "大额"}
      ]
    },
    {
      "id": "f_country", "name": "所属地区", "field": "country", "weight": 1.0,
      "tiers": [               # 条件档：op + value，按顺序首个命中生效
        {"op": "in", "value": ["RU", "BR", "NG"], "score": 60, "label": "高风险地区"},
        {"op": "==", "value": "CN", "score": 5}
      ],
      "default_score": 20
    },
    {
      "id": "f_freq", "name": "操作频率", "weight": 1.2,
      "agg": {"window_sec": 300, "key_field": "user_id", "agg_type": "count"},
      "tiers": [{"max": 3, "score": 0}, {"min": 3, "max": 10, "score": 30},
                {"min": 10, "score": 70}]
    }
  ],
  "levels": [                  # 综合分 → 风险等级 / 建议动作（min 含、max 不含）
    {"name": "低", "min": 0, "max": 30, "action": "pass"},
    {"name": "中", "min": 30, "max": 60, "action": "alert"},
    {"name": "高", "min": 60, "max": 85, "action": "review"},
    {"name": "严重", "min": 85, "action": "reject"}
  ]
}

评分计算：
- 因子取值：普通因子按 field 点路径取事件字段；聚合因子（agg）由滑动窗口求值；
- 每个因子命中一个分档得到档位分，加权分 = 档位分 × weight；
- 综合分 = clamp(base_score + Σ 加权分, 0, max_score)，再映射到等级与建议动作。

存储与热更新：与规则注册表同一模式——不可变编译快照 + 单引用原子替换；
每次保存追加版本历史（scorecard_versions/{id}.json），回滚以更高版本号重新发布。
"""
import os
import threading
import time

from backend import config
from backend.storage import atomic_write_json, read_json
from backend.engine.rule_parser import _get_field, compile_condition, compare_value


class ScorecardValidationError(ValueError):
    """评分卡校验失败。"""


# ---------------------------------------------------------------------------
# 因子编译
# ---------------------------------------------------------------------------
class FactorAgg:
    """聚合因子的窗口规格（如 5 分钟内同用户操作次数）。"""

    __slots__ = ("window_sec", "key_field", "agg_type", "value_field")

    def __init__(self, agg, factor_id):
        if not isinstance(agg, dict):
            raise ScorecardValidationError(f"因子 {factor_id} 的 agg 必须是对象")
        self.window_sec = int(agg.get("window_sec", 60))
        if self.window_sec <= 0:
            raise ScorecardValidationError(f"因子 {factor_id} 的 window_sec 必须为正数")
        self.key_field = agg.get("key_field") or "ip"
        self.agg_type = agg.get("agg_type", "count")
        if self.agg_type not in config.AGG_TYPES:
            raise ScorecardValidationError(
                f"因子 {factor_id} 聚合类型非法: {self.agg_type}")
        self.value_field = agg.get("value_field")

    def to_dict(self):
        return {"window_sec": self.window_sec, "key_field": self.key_field,
                "agg_type": self.agg_type, "value_field": self.value_field}


def _to_number(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


class CompiledTier:
    """一个分档：数值区间档（min/max）或条件档（op/value）。"""

    __slots__ = ("kind", "min", "max", "op", "value", "score", "label", "raw")

    def __init__(self, tier, factor_id, index):
        if not isinstance(tier, dict):
            raise ScorecardValidationError(f"因子 {factor_id} 第 {index + 1} 档必须是对象")
        if "score" not in tier:
            raise ScorecardValidationError(f"因子 {factor_id} 第 {index + 1} 档缺少 score")
        self.score = _to_number(tier.get("score"), 0.0)
        self.label = tier.get("label") or ""
        self.raw = tier
        if "min" in tier or "max" in tier:
            self.kind = "range"
            self.min = tier.get("min")
            self.max = tier.get("max")
            self.op = None
            self.value = None
            if self.min is not None and self.max is not None:
                if _to_number(self.min) > _to_number(self.max):
                    raise ScorecardValidationError(
                        f"因子 {factor_id} 第 {index + 1} 档 min 大于 max")
        elif "op" in tier:
            self.kind = "cond"
            self.op = tier.get("op")
            if self.op not in config.CONDITION_OPS:
                raise ScorecardValidationError(
                    f"因子 {factor_id} 第 {index + 1} 档操作符非法: {self.op}")
            self.value = tier.get("value")
            self.min = None
            self.max = None
        else:
            raise ScorecardValidationError(
                f"因子 {factor_id} 第 {index + 1} 档需要 min/max 区间或 op/value 条件")

    def match(self, value):
        if self.kind == "range":
            try:
                v = float(value)
            except (TypeError, ValueError):
                return False
            if self.min is not None and v < _to_number(self.min):
                return False
            if self.max is not None and v >= _to_number(self.max):
                return False
            return True
        return compare_value(value, self.op, self.value)

    def describe(self):
        if self.kind == "range":
            lo = "-∞" if self.min is None else self.min
            hi = "+∞" if self.max is None else self.max
            return f"[{lo}, {hi})"
        return f"{self.op} {self.value}"


class CompiledFactor:
    """编译后的评分因子：取值 → 分档 → 档位分 × 权重。"""

    __slots__ = ("id", "name", "field", "weight", "agg", "when_fns",
                 "tiers", "default_score", "missing_score", "raw")

    def __init__(self, factor, card_id, index):
        if not isinstance(factor, dict):
            raise ScorecardValidationError(f"评分卡 {card_id} 第 {index + 1} 个因子必须是对象")
        self.id = factor.get("id") or f"f_{index + 1}"
        self.name = factor.get("name") or self.id
        self.field = factor.get("field")
        self.agg = None
        if factor.get("agg"):
            self.agg = FactorAgg(factor["agg"], self.id)
        if not self.field and self.agg is None:
            raise ScorecardValidationError(
                f"评分卡 {card_id} 因子 {self.id} 需要 field 或 agg")
        self.weight = _to_number(factor.get("weight", 1.0), 1.0)
        if self.weight < 0:
            raise ScorecardValidationError(
                f"评分卡 {card_id} 因子 {self.id} 权重不能为负")
        self.when_fns = []
        when = factor.get("when") or []
        if not isinstance(when, list):
            raise ScorecardValidationError(f"因子 {self.id} 的 when 必须是数组")
        for cond in when:
            _key, fn = compile_condition(cond, self.id)
            self.when_fns.append(fn)
        tiers = factor.get("tiers") or []
        if not isinstance(tiers, list) or not tiers:
            raise ScorecardValidationError(f"因子 {self.id} 至少需要一个分档 tiers")
        self.tiers = [CompiledTier(t, self.id, i) for i, t in enumerate(tiers)]
        self.default_score = _to_number(factor.get("default_score", 0), 0.0)
        self.missing_score = _to_number(factor.get("missing_score", 0), 0.0)
        self.raw = factor

    def applies(self, event):
        for fn in self.when_fns:
            if not fn(event):
                return False
        return True

    def _value_of(self, event, window, ts):
        """取因子原始值；返回 (value, source_desc)。"""
        if self.agg is not None:
            key = _get_field(event, self.agg.key_field)
            desc = (f"{self.agg.agg_type}({self.agg.key_field}"
                    + (f".{self.agg.value_field}" if self.agg.value_field else "")
                    + f", {self.agg.window_sec}s)")
            if key is None:
                return None, desc
            if window is None:
                return 0, desc
            val = window.query(str(key), self.agg.window_sec,
                               self.agg.agg_type, now=ts)
            return val, desc
        return _get_field(event, self.field), self.field

    def evaluate(self, event, window=None, ts=None):
        """对事件求值，返回得分明细字典。"""
        detail = {
            "factor_id": self.id,
            "name": self.name,
            "weight": self.weight,
            "skipped": False,
            "skip_reason": None,
            "value": None,
            "source": self.field,
            "tier_index": None,
            "tier": None,
            "score": 0,
            "weighted": 0.0,
        }
        if not self.applies(event):
            detail["skipped"] = True
            detail["skip_reason"] = "因子生效条件不满足"
            return detail

        value, source = self._value_of(event, window, ts)
        detail["value"] = value
        detail["source"] = source

        if value is None:
            score = self.missing_score
            detail["skip_reason"] = "字段缺失，按 missing_score 计分"
        else:
            tier_index = None
            tier = None
            for i, t in enumerate(self.tiers):
                if t.match(value):
                    tier_index = i
                    tier = t
                    break
            if tier is None:
                score = self.default_score
                detail["skip_reason"] = "未命中分档，按 default_score 计分"
            else:
                score = tier.score
                detail["tier_index"] = tier_index
                detail["tier"] = {
                    "label": tier.label,
                    "range": tier.describe(),
                    "score": tier.score,
                }
        detail["score"] = score
        detail["weighted"] = round(score * self.weight, 2)
        return detail


# ---------------------------------------------------------------------------
# 评分卡编译
# ---------------------------------------------------------------------------
class CompiledScorecard:
    """编译后的评分卡：适用条件 + 因子列表 + 等级映射（不可变）。"""

    __slots__ = ("id", "name", "description", "enabled", "apply_when_fns",
                 "base_score", "max_score", "factors", "levels", "version",
                 "raw", "agg_feeds", "max_window_sec")

    def __init__(self, card, version=None):
        self.id = card.get("id")
        self.name = card.get("name") or self.id
        self.description = card.get("description") or ""
        self.enabled = bool(card.get("enabled", True))
        self.version = version if version is not None else card.get("version", 1)
        self.raw = card

        self.apply_when_fns = []
        apply_when = card.get("apply_when") or []
        if not isinstance(apply_when, list):
            raise ScorecardValidationError(f"评分卡 {self.id} 的 apply_when 必须是数组")
        for cond in apply_when:
            _key, fn = compile_condition(cond, self.id)
            self.apply_when_fns.append(fn)

        self.base_score = _to_number(card.get("base_score", 0), 0.0)
        self.max_score = _to_number(card.get("max_score", 100), 100.0)
        if self.max_score <= 0:
            raise ScorecardValidationError(f"评分卡 {self.id} 的 max_score 必须为正数")

        factors = card.get("factors") or []
        if not isinstance(factors, list) or not factors:
            raise ScorecardValidationError(f"评分卡 {self.id} 至少需要一个评分因子")
        self.factors = [CompiledFactor(f, self.id, i) for i, f in enumerate(factors)]

        self.levels = []
        for lv in card.get("levels") or []:
            if not isinstance(lv, dict) or not lv.get("name"):
                raise ScorecardValidationError(f"评分卡 {self.id} 的等级缺少 name")
            action = lv.get("action", "alert")
            if action not in config.ACTION_TYPES:
                raise ScorecardValidationError(
                    f"评分卡 {self.id} 等级 {lv.get('name')} 动作非法: {action}")
            self.levels.append({
                "name": lv["name"],
                "min": _to_number(lv.get("min", 0), 0.0),
                "max": _to_number(lv["max"], 0.0) if lv.get("max") is not None else None,
                "action": action,
            })
        self.levels.sort(key=lambda l: l["min"])

        # 聚合因子需要的窗口喂入字段与最大窗口
        feeds = []
        seen = set()
        max_window = 0
        for f in self.factors:
            if f.agg is not None:
                key = (f.agg.key_field, f.agg.value_field)
                if key not in seen:
                    seen.add(key)
                    feeds.append(key)
                max_window = max(max_window, f.agg.window_sec)
        self.agg_feeds = feeds
        self.max_window_sec = max_window

    def applies_to(self, event):
        for fn in self.apply_when_fns:
            if not fn(event):
                return False
        return True

    def map_level(self, score):
        """综合分 → (等级名, 建议动作)；未配置等级时返回 (None, None)。"""
        for lv in self.levels:
            if score >= lv["min"] and (lv["max"] is None or score < lv["max"]):
                return lv["name"], lv["action"]
        return None, None

    def evaluate(self, event, window=None, ts=None):
        """对事件评分，返回综合分、等级、建议动作与逐因子明细。"""
        details = [f.evaluate(event, window=window, ts=ts)
                   for f in self.factors]
        total = self.base_score + sum(d["weighted"] for d in details)
        total = max(0.0, min(self.max_score, total))
        total = round(total, 2)
        level, action = self.map_level(total)
        return {
            "scorecard_id": self.id,
            "name": self.name,
            "version": self.version,
            "base_score": self.base_score,
            "total_score": total,
            "max_score": self.max_score,
            "level": level,
            "action": action,
            "factors": details,
        }

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "version": self.version,
            "factor_count": len(self.factors),
            "levels": [lv["name"] for lv in self.levels],
        }


def compile_scorecard(card, version=None):
    """把评分卡 JSON 编译为 CompiledScorecard。"""
    if not isinstance(card, dict):
        raise ScorecardValidationError("评分卡必须是 JSON 对象")
    if not card.get("id"):
        raise ScorecardValidationError("评分卡缺少 id 字段")
    return CompiledScorecard(card, version=version)


def validate_scorecard_json(card):
    """校验评分卡 JSON，抛出 ScorecardValidationError 或返回编译对象。"""
    return compile_scorecard(card)


# ---------------------------------------------------------------------------
# 存储：不可变快照 + 原子热更新 + 版本历史（与 RuleRegistry 同一模式）
# ---------------------------------------------------------------------------
class CompiledScorecardSet:
    """不可变编译快照（仅含启用的评分卡）。"""

    def __init__(self, cards, agg_feeds, max_window_sec, version):
        self.cards = cards
        self.by_id = {c.id: c for c in cards}
        self.agg_feeds = agg_feeds
        self.max_window_sec = max_window_sec
        self.version = version
        self.built_at = time.time()

    def describe(self):
        return {
            "version": self.version,
            "scorecard_count": len(self.cards),
            "agg_feeds": len(self.agg_feeds),
            "max_window_sec": self.max_window_sec,
            "built_at": self.built_at,
        }


def _version_sort_key(h):
    return h.get("version", 0)


class ScorecardStore:
    """评分卡注册表：编译、热更新、版本回滚。多套评分卡并存。"""

    def __init__(self):
        self._cards = {}          # card_id -> card JSON（含 version）
        self._versions = {}       # card_id -> [history...]
        self._lock = threading.RLock()
        self._global_version = 0
        self._current = None
        self._load_all()
        self._rebuild()

    # ------------------------------------------------------------------
    # 加载 / 构建
    # ------------------------------------------------------------------
    def _load_all(self):
        self._cards = {}
        self._versions = {}
        if os.path.isdir(config.SCORECARDS_DIR):
            for fn in sorted(os.listdir(config.SCORECARDS_DIR)):
                if not fn.endswith(".json"):
                    continue
                data = read_json(os.path.join(config.SCORECARDS_DIR, fn), {})
                card = data.get("scorecard") or data
                if not card.get("id"):
                    continue
                self._cards[card["id"]] = card
        if os.path.isdir(config.SCARD_VERSIONS_DIR):
            for fn in sorted(os.listdir(config.SCARD_VERSIONS_DIR)):
                if not fn.endswith(".json"):
                    continue
                cid = fn[:-5]
                hist = read_json(os.path.join(config.SCARD_VERSIONS_DIR, fn),
                                 {"history": []})
                self._versions[cid] = hist.get("history", [])

    def _build(self):
        """旁路构建全新编译快照（不改动当前快照）。"""
        compiled = []
        for card in self._cards.values():
            if not card.get("enabled", True):
                continue
            try:
                compiled.append(compile_scorecard(card, version=card.get("version")))
            except Exception:
                continue
        agg_feeds = []
        seen = set()
        max_window = 0
        for c in compiled:
            for feed in c.agg_feeds:
                if feed not in seen:
                    seen.add(feed)
                    agg_feeds.append(feed)
            max_window = max(max_window, c.max_window_sec)
        self._global_version += 1
        return CompiledScorecardSet(compiled, agg_feeds, max_window,
                                    self._global_version)

    def _rebuild(self):
        new_set = self._build()
        with self._lock:
            self._current = new_set
        return new_set

    @property
    def current(self):
        """返回当前快照引用（不可变，读一次即可）。"""
        return self._current

    # ------------------------------------------------------------------
    # 持久化辅助
    # ------------------------------------------------------------------
    def _persist_card(self, card_id):
        card = self._cards.get(card_id)
        path = os.path.join(config.SCORECARDS_DIR, f"{card_id}.json")
        if card is None:
            if os.path.exists(path):
                os.remove(path)
            return
        atomic_write_json(path, {"scorecard": card})

    def _persist_versions(self, card_id):
        hist = self._versions.get(card_id, [])
        atomic_write_json(os.path.join(config.SCARD_VERSIONS_DIR, f"{card_id}.json"),
                          {"history": hist})

    def _next_version(self, card_id):
        cur = self._cards.get(card_id, {}).get("version", 0)
        return int(cur) + 1

    # ------------------------------------------------------------------
    # CRUD（均触发原子热更新）
    # ------------------------------------------------------------------
    def save_card(self, card_json, author="admin", comment=""):
        """新建或更新评分卡。返回 (card, created)。"""
        card_id = card_json.get("id")
        if not card_id:
            raise ValueError("评分卡缺少 id")
        with self._lock:
            created = card_id not in self._cards
            version = self._next_version(card_id)
            card_json["version"] = version
            card_json["updated_at"] = int(time.time())
            self._cards[card_id] = card_json

            hist = self._versions.setdefault(card_id, [])
            hist.append({
                "version": version,
                "scorecard": card_json,
                "ts": int(time.time()),
                "author": author,
                "comment": comment or ("新建评分卡" if created else "编辑评分卡"),
            })
            self._persist_versions(card_id)
            self._persist_card(card_id)
        self._rebuild()
        return self._cards[card_id], created

    def delete_card(self, card_id):
        with self._lock:
            if card_id not in self._cards:
                return False
            del self._cards[card_id]
            self._persist_card(card_id)
        self._rebuild()
        return True

    def enable_card(self, card_id, enabled):
        with self._lock:
            card = self._cards.get(card_id)
            if card is None:
                return None
            card["enabled"] = bool(enabled)
            card["version"] = self._next_version(card_id)
            card["updated_at"] = int(time.time())
            self._persist_card(card_id)
        self._rebuild()
        return card

    def rollback(self, card_id, target_version, author="admin"):
        """回滚到指定版本：以更高版本号重新发布历史快照。"""
        with self._lock:
            hist = self._versions.get(card_id, [])
            target = None
            for h in hist:
                if h.get("version") == target_version:
                    target = h.get("scorecard")
                    break
            if target is None:
                return False
            card_json = dict(target)
            card_json["version"] = self._next_version(card_id)
            card_json["updated_at"] = int(time.time())
            self._cards[card_id] = card_json
            self._versions.setdefault(card_id, []).append({
                "version": card_json["version"],
                "scorecard": card_json,
                "ts": int(time.time()),
                "author": author,
                "comment": f"回滚自版本 {target_version}",
            })
            self._persist_card(card_id)
            self._persist_versions(card_id)
        self._rebuild()
        return True

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def list_cards(self):
        with self._lock:
            cards = list(self._cards.values())
        cards.sort(key=lambda c: c.get("name", ""))
        return cards

    def get_card(self, card_id):
        with self._lock:
            return self._cards.get(card_id)

    def versions_of(self, card_id):
        """返回版本历史（最新在前）。"""
        with self._lock:
            hist = list(self._versions.get(card_id, []))
        hist.sort(key=_version_sort_key)
        hist.reverse()
        return hist
