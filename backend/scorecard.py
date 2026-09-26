"""评分卡：可配置风险评分模型。

规则的风险分来自规则自身配置（action.risk_score），评分卡则提供一套独立的、
业务可配置的评分模型：一张评分卡由多个「评分因子」组成，每个因子按事件取值
命中分档得到分值，再按权重加权求和得到综合风险分，最后映射到风险等级与建议动作。

评分卡 JSON 结构约定：
{
  "id": "sc_transaction_risk",
  "name": "交易风险评分卡",
  "description": "转账/支付/提现事件的综合风险评分",
  "enabled": true,
  "priority": 100,                # 多张卡同时适用时按优先级排序评估
  "event_types": ["transfer", "payment", "withdraw"],   # 适用事件类型，空 = 全部
  "base_score": 0,                # 基础分（综合分 = 基础分 + Σ 因子分 × 权重）
  "factors": [
    {"name": "交易金额", "type": "range", "field": "amount", "weight": 0.35,
     "bins": [{"max": 1000, "score": 5},
              {"min": 1000, "max": 10000, "score": 20},
              {"min": 10000, "score": 70}],
     "default_score": 0},
    {"name": "高风险地区", "type": "match", "field": "country", "weight": 0.2,
     "cases": [{"op": "in", "value": ["RU", "BR", "NG"], "score": 85}],
     "default_score": 0},
    {"name": "短时操作频率", "type": "agg", "weight": 0.3,
     "agg": {"window_sec": 300, "key_field": "user_id", "agg_type": "count"},
     "bins": [{"max": 2, "score": 5}, {"min": 2, "score": 85}],
     "default_score": 0}
  ],
  "levels": [
    {"level": "低", "min": 0,  "max": 30, "action": "pass"},
    {"level": "中", "min": 30, "max": 55, "action": "alert"},
    {"level": "高", "min": 55, "max": 80, "action": "review"},
    {"level": "严重", "min": 80,           "action": "reject"}
  ]
}

因子类型（type，缺省时按字段自动推断）：
1. range  数值分档：取 field 的事件值，自上而下匹配首个 [min, max] 区间（闭区间，
          min/max 可缺省表示开口），取对应 score；
2. match  条件匹配：按 cases 自上而下用条件算子（== / in / contains ...）匹配，
          首个命中分支的 score 生效；
3. agg    窗口聚合：先由滑动窗口对 key_field 做聚合（count/sum/avg/...），
          聚合值再走 range 分档。

字段缺失 / 未命中任何分档时使用 default_score（默认 0）。
综合分 = base_score + Σ(因子分 × 权重)，再按 levels 自上而下首个命中区间
映射风险等级与建议动作；未命中任何等级区间时等级为 None、动作 pass。

存储与版本：当前卡存 scorecards/{id}.json，每次保存追加版本快照到
scorecard_versions/{id}.json，回滚以更高版本号重新发布——与规则版本管理一致。
"""
import copy
import os
import threading
import time

from backend import config
from backend.storage import atomic_write_json, read_json

FACTOR_TYPES = ["range", "match", "agg"]

# rule_parser 的导入延迟到首次使用：backend.engine 包 __init__ 会反向导入
# 本模块（engine.py -> scorecard），顶层直接导入会形成循环依赖。
_compile_condition = None
_get_field = None


def _ensure_parser():
    global _compile_condition, _get_field
    if _compile_condition is None:
        from backend.engine.rule_parser import compile_condition, _get_field as gf
        _compile_condition = compile_condition
        _get_field = gf


class ScorecardValidationError(ValueError):
    """评分卡校验失败。"""


def _num(v, default=None):
    """尽力转 float，失败返回 default。"""
    if isinstance(v, bool):
        return default
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _validate_bins(bins, card_id, factor_name):
    if not isinstance(bins, list) or not bins:
        raise ScorecardValidationError(
            f"评分卡 {card_id} 因子「{factor_name}」缺少分档 bins")
    out = []
    for b in bins:
        if not isinstance(b, dict):
            raise ScorecardValidationError(
                f"评分卡 {card_id} 因子「{factor_name}」分档必须是对象")
        score = _num(b.get("score"))
        if score is None:
            raise ScorecardValidationError(
                f"评分卡 {card_id} 因子「{factor_name}」分档缺少分值 score")
        out.append({"min": _num(b.get("min")), "max": _num(b.get("max")),
                    "score": score})
    return out


def _bin_desc(b):
    lo = "-∞" if b.get("min") is None else ("%g" % b["min"])
    hi = "+∞" if b.get("max") is None else ("%g" % b["max"])
    return f"[{lo}, {hi}]"


class CompiledFactor:
    """编译后的评分因子。"""

    __slots__ = ("name", "type", "field", "weight", "default_score",
                 "bins", "cases", "agg")

    def __init__(self, factor, card_id, idx):
        if not isinstance(factor, dict):
            raise ScorecardValidationError(f"评分卡 {card_id} 第 {idx + 1} 个因子必须是对象")
        ftype = factor.get("type")
        if not ftype:
            if factor.get("agg"):
                ftype = "agg"
            elif factor.get("cases"):
                ftype = "match"
            else:
                ftype = "range"
        if ftype not in FACTOR_TYPES:
            raise ScorecardValidationError(
                f"评分卡 {card_id} 因子类型非法: {ftype}（可选 {FACTOR_TYPES}）")
        self.type = ftype
        self.field = factor.get("field")
        self.name = factor.get("name") or self.field or f"因子{idx + 1}"

        weight = _num(factor.get("weight"), 1.0)
        if weight is None or weight < 0:
            raise ScorecardValidationError(
                f"评分卡 {card_id} 因子「{self.name}」权重必须是非负数值")
        self.weight = weight
        self.default_score = _num(factor.get("default_score"), 0) or 0

        self.bins = []
        self.cases = []
        self.agg = None

        if self.type == "agg":
            agg = factor.get("agg")
            if not isinstance(agg, dict):
                raise ScorecardValidationError(
                    f"评分卡 {card_id} 因子「{self.name}」缺少 agg 聚合配置")
            key_field = agg.get("key_field")
            if not key_field:
                raise ScorecardValidationError(
                    f"评分卡 {card_id} 因子「{self.name}」agg 缺少 key_field")
            agg_type = agg.get("agg_type", "count")
            if agg_type not in config.AGG_TYPES:
                raise ScorecardValidationError(
                    f"评分卡 {card_id} 因子「{self.name}」聚合类型非法: {agg_type}")
            window_sec = int(agg.get("window_sec", 60))
            if window_sec <= 0:
                raise ScorecardValidationError(
                    f"评分卡 {card_id} 因子「{self.name}」window_sec 必须为正数")
            self.agg = {"window_sec": window_sec, "key_field": key_field,
                        "agg_type": agg_type, "value_field": agg.get("value_field")}
            self.bins = _validate_bins(factor.get("bins"), card_id, self.name)
        elif self.type == "range":
            if not self.field:
                raise ScorecardValidationError(
                    f"评分卡 {card_id} 因子「{self.name}」缺少 field")
            self.bins = _validate_bins(factor.get("bins"), card_id, self.name)
        else:  # match
            if not self.field:
                raise ScorecardValidationError(
                    f"评分卡 {card_id} 因子「{self.name}」缺少 field")
            cases = factor.get("cases")
            if not isinstance(cases, list) or not cases:
                raise ScorecardValidationError(
                    f"评分卡 {card_id} 因子「{self.name}」缺少分支 cases")
            for c in cases:
                if not isinstance(c, dict):
                    raise ScorecardValidationError(
                        f"评分卡 {card_id} 因子「{self.name}」分支必须是对象")
                op = c.get("op", "==")
                if op not in config.CONDITION_OPS:
                    raise ScorecardValidationError(
                        f"评分卡 {card_id} 因子「{self.name}」操作符非法: {op}")
                score = _num(c.get("score"))
                if score is None:
                    raise ScorecardValidationError(
                        f"评分卡 {card_id} 因子「{self.name}」分支缺少分值 score")
                _ensure_parser()
                _key, fn = _compile_condition(
                    {"field": self.field, "op": op, "value": c.get("value")}, card_id)
                self.cases.append({"op": op, "value": c.get("value"),
                                   "score": score, "fn": fn})

    # ------------------------------------------------------------------
    def _value_of(self, event, window, ts):
        """取因子输入值：agg 走滑动窗口，其余走事件字段。"""
        _ensure_parser()
        if self.type == "agg":
            key = _get_field(event, self.agg["key_field"])
            if key is None or window is None:
                return None
            return window.query(str(key), self.agg["window_sec"],
                                self.agg["agg_type"], now=ts)
        return _get_field(event, self.field)

    def evaluate(self, event, window, ts):
        """评估单个因子，返回得分明细。"""
        detail = {"name": self.name, "type": self.type, "field": self.field,
                  "weight": self.weight, "hit": False, "matched": None,
                  "score": self.default_score, "reason": ""}
        value = self._value_of(event, window, ts)
        detail["value"] = value
        if value is None:
            detail["reason"] = "聚合键缺失" if self.type == "agg" else "字段缺失"
            return self._finish(detail)

        if self.type == "match":
            for c in self.cases:
                if c["fn"](event):
                    detail.update(hit=True, score=c["score"],
                                  matched=f"{c['op']} {c['value']}")
                    return self._finish(detail)
            detail["reason"] = "未命中任何分支"
            return self._finish(detail)

        # range / agg：数值分档，自上而下首个命中区间生效
        v = _num(value)
        if v is None:
            detail["reason"] = "取值非数值"
            return self._finish(detail)
        for b in self.bins:
            if (b["min"] is None or v >= b["min"]) and \
               (b["max"] is None or v <= b["max"]):
                detail.update(hit=True, score=b["score"], matched=_bin_desc(b))
                return self._finish(detail)
        detail["reason"] = "未命中任何分档"
        return self._finish(detail)

    def _finish(self, detail):
        detail["weighted"] = round(detail["score"] * self.weight, 2)
        if not detail["hit"] and not detail["reason"]:
            detail["reason"] = "缺省分"
        return detail


class CompiledScorecard:
    """编译后的评分卡：因子闭包 + 等级映射，可重复评估。"""

    def __init__(self, card):
        if not isinstance(card, dict):
            raise ScorecardValidationError("评分卡必须是 JSON 对象")
        self.id = card.get("id")
        if not self.id:
            raise ScorecardValidationError("评分卡缺少 id 字段")
        self.name = card.get("name") or self.id
        self.description = card.get("description", "")
        self.enabled = bool(card.get("enabled", True))
        self.version = card.get("version", 1)
        priority = _num(card.get("priority"), 100)
        self.priority = int(priority) if priority is not None else 100

        event_types = card.get("event_types") or []
        if not isinstance(event_types, list):
            raise ScorecardValidationError(f"评分卡 {self.id} event_types 必须是数组")
        self.event_types = [str(t) for t in event_types]

        self.base_score = _num(card.get("base_score"), 0) or 0

        factors = card.get("factors")
        if not isinstance(factors, list) or not factors:
            raise ScorecardValidationError(f"评分卡 {self.id} 至少需要一个评分因子")
        self.factors = [CompiledFactor(f, self.id, i)
                        for i, f in enumerate(factors)]

        levels = card.get("levels") or []
        if not isinstance(levels, list):
            raise ScorecardValidationError(f"评分卡 {self.id} levels 必须是数组")
        self.levels = []
        for lv in levels:
            if not isinstance(lv, dict) or not lv.get("level"):
                raise ScorecardValidationError(
                    f"评分卡 {self.id} 等级映射缺少 level 名称")
            action = lv.get("action", "pass")
            if action not in config.ACTION_TYPES:
                raise ScorecardValidationError(
                    f"评分卡 {self.id} 等级「{lv.get('level')}」动作非法: {action}")
            self.levels.append({"level": lv["level"],
                                "min": _num(lv.get("min")),
                                "max": _num(lv.get("max")),
                                "action": action})
        self.raw = card

    def applies_to(self, event_type):
        """空 event_types 表示适用全部事件类型。"""
        return not self.event_types or event_type in self.event_types

    def _map_level(self, total):
        for lv in self.levels:
            if (lv["min"] is None or total >= lv["min"]) and \
               (lv["max"] is None or total <= lv["max"]):
                return lv["level"], lv["action"]
        return None, "pass"

    def evaluate(self, event, window=None, ts=None):
        """评估事件，返回综合分、等级、建议动作与逐因子得分明细。"""
        if ts is None:
            ts = event.get("ts") or time.time()
        details = [f.evaluate(event, window, ts) for f in self.factors]
        total = round(self.base_score + sum(d["weighted"] for d in details), 2)
        level, action = self._map_level(total)
        return {
            "scorecard_id": self.id,
            "scorecard_name": self.name,
            "version": self.version,
            "base_score": self.base_score,
            "total_score": total,
            "level": level,
            "action": action,
            "factors": details,
        }


def validate_scorecard(card):
    """校验评分卡 JSON，抛出 ScorecardValidationError 或返回编译对象。"""
    return CompiledScorecard(card)


class ScorecardStore:
    """评分卡存储：CRUD、启停、版本历史与回滚、编译缓存、事件评估。

    与规则注册表同理：所有变更先校验编译、再落盘、最后失效编译缓存；
    评估时按 (id, version) 缓存编译产物，运行期无重复编译开销。
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._cards = {}        # card_id -> card JSON（含 version）
        self._versions = {}     # card_id -> [history...]
        self._compiled = {}     # (card_id, version) -> CompiledScorecard
        self._load_all()

    # ------------------------------------------------------------------
    # 加载 / 持久化
    # ------------------------------------------------------------------
    def _load_all(self):
        self._cards = {}
        self._versions = {}
        if os.path.isdir(config.SCORECARDS_DIR):
            for fn in sorted(os.listdir(config.SCORECARDS_DIR)):
                if not fn.endswith(".json"):
                    continue
                data = read_json(os.path.join(config.SCORECARDS_DIR, fn), {})
                card = data.get("card") or data
                if card.get("id"):
                    self._cards[card["id"]] = card
        if os.path.isdir(config.SCORECARD_VERSIONS_DIR):
            for fn in sorted(os.listdir(config.SCORECARD_VERSIONS_DIR)):
                if not fn.endswith(".json"):
                    continue
                cid = fn[:-5]
                hist = read_json(os.path.join(config.SCORECARD_VERSIONS_DIR, fn),
                                 {"history": []})
                self._versions[cid] = hist.get("history", [])

    def _persist_card(self, card_id):
        card = self._cards.get(card_id)
        path = os.path.join(config.SCORECARDS_DIR, f"{card_id}.json")
        if card is None:
            if os.path.exists(path):
                os.remove(path)
            return
        atomic_write_json(path, {"card": card})

    def _persist_versions(self, card_id):
        hist = self._versions.get(card_id, [])
        atomic_write_json(os.path.join(config.SCORECARD_VERSIONS_DIR, f"{card_id}.json"),
                          {"history": hist})

    def _next_version(self, card_id):
        cur = self._cards.get(card_id, {}).get("version", 0)
        return int(cur) + 1

    # ------------------------------------------------------------------
    # CRUD（保存即校验 + 追加版本快照）
    # ------------------------------------------------------------------
    def save_card(self, card_json, author="admin", comment=""):
        """新建或更新评分卡，返回 (card, created)。"""
        card_id = card_json.get("id")
        if not card_id:
            raise ScorecardValidationError("评分卡缺少 id")
        with self._lock:
            created = card_id not in self._cards
            version = self._next_version(card_id)
            card_json["version"] = version
            card_json["updated_at"] = int(time.time())
            validate_scorecard(card_json)     # 先校验，非法不落盘
            self._cards[card_id] = card_json
            hist = self._versions.setdefault(card_id, [])
            hist.append({
                "version": version,
                "card": copy.deepcopy(card_json),   # 快照与当前卡解耦，避免原地修改污染历史
                "ts": int(time.time()),
                "author": author,
                "comment": comment or ("新建评分卡" if created else "编辑评分卡"),
            })
            self._persist_versions(card_id)
            self._persist_card(card_id)
        return self._cards[card_id], created

    def delete_card(self, card_id):
        with self._lock:
            if card_id not in self._cards:
                return False
            del self._cards[card_id]
            self._compiled = {k: v for k, v in self._compiled.items()
                              if k[0] != card_id}
            self._persist_card(card_id)
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
        return card

    def rollback(self, card_id, target_version, author="admin"):
        """回滚到指定版本：以更高版本号重新发布历史快照。"""
        with self._lock:
            hist = self._versions.get(card_id, [])
            target = None
            for h in hist:
                if h.get("version") == target_version:
                    target = h.get("card")
                    break
            if target is None:
                return False
            card_json = copy.deepcopy(target)
            card_json["version"] = self._next_version(card_id)
            card_json["updated_at"] = int(time.time())
            self._cards[card_id] = card_json

            self._versions.setdefault(card_id, []).append({
                "version": card_json["version"],
                "card": copy.deepcopy(card_json),
                "ts": int(time.time()),
                "author": author,
                "comment": f"回滚自版本 {target_version}",
            })
            self._persist_card(card_id)
            self._persist_versions(card_id)
        return True

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------
    def list_cards(self):
        with self._lock:
            cards = list(self._cards.values())
        cards.sort(key=lambda c: (-int(c.get("priority", 100) or 100),
                                  c.get("name", "")))
        return cards

    def get_card(self, card_id):
        with self._lock:
            return self._cards.get(card_id)

    def versions_of(self, card_id):
        """返回版本历史（最新在前）。"""
        with self._lock:
            hist = list(self._versions.get(card_id, []))
        hist.sort(key=lambda h: h.get("version", 0), reverse=True)
        return hist

    # ------------------------------------------------------------------
    # 编译与评估
    # ------------------------------------------------------------------
    def compile(self, card_id):
        """返回当前版本的编译产物（按版本缓存）；不存在或编译失败返回 None。"""
        card = self.get_card(card_id)
        if card is None:
            return None
        key = (card_id, card.get("version", 1))
        with self._lock:
            cached = self._compiled.get(key)
        if cached is not None:
            return cached
        try:
            compiled = CompiledScorecard(card)
        except ScorecardValidationError:
            return None
        with self._lock:
            self._compiled[key] = compiled
        return compiled

    def compile_adhoc(self, card_json):
        """编译未保存的评分卡草稿（沙箱预览用），非法时抛 ScorecardValidationError。"""
        return CompiledScorecard(card_json)

    def evaluate_card(self, card_id, event, window=None, ts=None):
        compiled = self.compile(card_id)
        if compiled is None:
            return None
        return compiled.evaluate(event, window=window, ts=ts)

    def evaluate_event(self, event, ts=None, window=None):
        """对事件评估所有「启用且适用该事件类型」的评分卡，按优先级排序返回。"""
        if ts is None:
            ts = event.get("ts") or time.time()
        results = []
        with self._lock:
            cards = [dict(c) for c in self._cards.values() if c.get("enabled", True)]
        cards.sort(key=lambda c: -int(c.get("priority", 100) or 100))
        for card in cards:
            compiled = self.compile(card["id"])
            if compiled is None or not compiled.applies_to(event.get("type")):
                continue
            results.append(compiled.evaluate(event, window=window, ts=ts))
        return results
