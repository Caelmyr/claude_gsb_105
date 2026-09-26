"""初始化样例数据：规则（含多版本历史）、数据字典、示例决策流。

仅在 data/rules 为空时执行，保证幂等。
"""
import os

from backend import config
from backend.storage import atomic_write_json


def _rule(rid, name, desc, conditions, action, priority=100, tags=None):
    return {
        "id": rid, "name": name, "description": desc, "enabled": True,
        "priority": priority, "conditions": conditions, "action": action,
        "tags": tags or [],
    }


def seed_rules(registry):
    if registry.list_rules():
        return 0

    rules = [
        _rule("rule_login_freq", "登录高频检测",
              "同一 IP 60 秒内登录次数超过 5 次视为撞库/暴力破解",
              [{"field": "type", "op": "==", "value": "login"},
               {"agg": {"window_sec": 60, "key_field": "ip", "op": ">=", "threshold": 5, "agg_type": "count"}}],
              {"type": "reject", "risk_score": 90, "reason": "登录频率过高", "level": "高"},
              priority=100, tags=["高频", "登录"]),
        _rule("rule_big_transfer", "大额转账检测",
              "单笔转账金额超过 10 万进入人工复核",
              [{"field": "type", "op": "==", "value": "transfer"},
               {"field": "amount", "op": ">", "value": 100000}],
              {"type": "review", "risk_score": 70, "reason": "大额转账需人工复核", "level": "中"},
              priority=90, tags=["金额", "转账"]),
        _rule("rule_huge_amount", "超大额交易拦截",
              "任意类型单笔金额超过 50 万直接拒绝",
              [{"field": "amount", "op": ">", "value": 500000}],
              {"type": "reject", "risk_score": 95, "reason": "单笔金额超过限额", "level": "严重"},
              priority=80, tags=["金额"]),
        _rule("rule_highrisk_country", "高风险国家交易",
              "来自高风险国家/地区的交易转人工复核",
              [{"field": "country", "op": "in", "value": ["RU", "BR", "NG"]},
               {"field": "type", "op": "in", "value": ["payment", "transfer", "withdraw"]}],
              {"type": "review", "risk_score": 60, "reason": "高风险地区交易", "level": "中"},
              priority=70, tags=["地区"]),
        _rule("rule_new_device", "新设备登录预警",
              "新设备登录产生告警",
              [{"field": "type", "op": "==", "value": "login"},
               {"field": "risk_hint", "op": "==", "value": "new_device"}],
              {"type": "alert", "risk_score": 55, "reason": "新设备登录", "level": "低"},
              priority=60, tags=["设备"]),
        _rule("rule_register_freq", "注册高频检测",
              "同一 IP 60 秒内注册超过 3 次视为批量注册",
              [{"field": "type", "op": "==", "value": "register"},
               {"agg": {"window_sec": 60, "key_field": "ip", "op": ">=", "threshold": 3, "agg_type": "count"}}],
              {"type": "reject", "risk_score": 88, "reason": "注册频率过高", "level": "高"},
              priority=85, tags=["高频", "注册"]),
        _rule("rule_withdraw_freq", "提现频率监控",
              "同一用户 5 分钟内提现超过 3 次告警",
              [{"field": "type", "op": "==", "value": "withdraw"},
               {"agg": {"window_sec": 300, "key_field": "user_id", "op": ">=", "threshold": 3, "agg_type": "count"}}],
              {"type": "alert", "risk_score": 65, "reason": "提现过于频繁", "level": "中"},
              priority=75, tags=["高频", "提现"]),
        _rule("rule_sms_bomb", "短信轰炸检测",
              "同一 IP 60 秒内触发短信超过 20 次视为轰炸",
              [{"field": "type", "op": "==", "value": "sms"},
               {"agg": {"window_sec": 60, "key_field": "ip", "op": ">=", "threshold": 20, "agg_type": "count"}}],
              {"type": "reject", "risk_score": 92, "reason": "短信轰炸", "level": "严重"},
              priority=95, tags=["高频", "短信"]),
        _rule("rule_api_freq", "API 调用频率限流",
              "同一 IP 60 秒内 API 调用超过 100 次触发限流告警",
              [{"field": "type", "op": "==", "value": "api"},
               {"agg": {"window_sec": 60, "key_field": "ip", "op": ">=", "threshold": 100, "agg_type": "count"}}],
              {"type": "alert", "risk_score": 50, "reason": "API 调用超频", "level": "低"},
              priority=50, tags=["限流"]),
        _rule("rule_amount_spike", "金额突增检测",
              "交易金额出现突增标记时告警",
              [{"field": "risk_hint", "op": "==", "value": "amount_spike"}],
              {"type": "review", "risk_score": 58, "reason": "金额突增", "level": "中"},
              priority=40, tags=["金额"]),
    ]

    for r in rules:
        registry.save_rule(r, author="system", comment="初始规则")

    # 为「登录高频检测」追加历史版本，演示版本回滚
    login_rule = registry.get_rule("rule_login_freq")
    if login_rule:
        v1 = dict(login_rule)
        v1["conditions"] = [
            {"field": "type", "op": "==", "value": "login"},
            {"agg": {"window_sec": 60, "key_field": "ip", "op": ">=", "threshold": 8, "agg_type": "count"}},
        ]
        v1["description"] = "初始阈值 8 次"
        registry.save_rule(v1, author="system", comment="上调阈值至 8")

        v2 = dict(v1)
        v2["conditions"] = [
            {"field": "type", "op": "==", "value": "login"},
            {"agg": {"window_sec": 120, "key_field": "ip", "op": ">=", "threshold": 6, "agg_type": "count"}},
        ]
        v2["description"] = "窗口放宽到 120 秒、阈值 6"
        registry.save_rule(v2, author="system", comment="放宽窗口")

        # 恢复为当前 5 次/60s
        current = dict(login_rule)
        current["conditions"] = [
            {"field": "type", "op": "==", "value": "login"},
            {"agg": {"window_sec": 60, "key_field": "ip", "op": ">=", "threshold": 5, "agg_type": "count"}},
        ]
        registry.save_rule(current, author="system", comment="最终阈值 5")

    return len(registry.list_rules())


def seed_dict():
    if os.path.exists(config.DICT_FILE):
        return
    data = {
        "categories": ["事件类型", "风险等级", "动作类型", "渠道", "设备类型", "IP 段"],
        "entries": [
            {"id": "dict_ev_login", "category": "事件类型", "key": "login", "value": "登录", "remark": "用户登录事件", "enabled": True},
            {"id": "dict_ev_register", "category": "事件类型", "key": "register", "value": "注册", "remark": "用户注册事件", "enabled": True},
            {"id": "dict_ev_transfer", "category": "事件类型", "key": "transfer", "value": "转账", "remark": "转账交易", "enabled": True},
            {"id": "dict_ev_payment", "category": "事件类型", "key": "payment", "value": "支付", "remark": "支付交易", "enabled": True},
            {"id": "dict_ev_withdraw", "category": "事件类型", "key": "withdraw", "value": "提现", "remark": "提现交易", "enabled": True},
            {"id": "dict_ev_sms", "category": "事件类型", "key": "sms", "value": "短信", "remark": "短信下发", "enabled": True},
            {"id": "dict_ev_api", "category": "事件类型", "key": "api", "value": "接口调用", "remark": "API 调用", "enabled": True},
            {"id": "dict_lv_low", "category": "风险等级", "key": "低", "value": "低", "remark": "低风险", "enabled": True},
            {"id": "dict_lv_mid", "category": "风险等级", "key": "中", "value": "中", "remark": "中风险", "enabled": True},
            {"id": "dict_lv_high", "category": "风险等级", "key": "高", "value": "高", "remark": "高风险", "enabled": True},
            {"id": "dict_lv_crit", "category": "风险等级", "key": "严重", "value": "严重", "remark": "严重风险", "enabled": True},
            {"id": "dict_act_reject", "category": "动作类型", "key": "reject", "value": "拒绝", "remark": "直接拒绝", "enabled": True},
            {"id": "dict_act_review", "category": "动作类型", "key": "review", "value": "人工复核", "remark": "转人工复核", "enabled": True},
            {"id": "dict_act_alert", "category": "动作类型", "key": "alert", "value": "告警", "remark": "仅告警", "enabled": True},
            {"id": "dict_act_pass", "category": "动作类型", "key": "pass", "value": "放行", "remark": "直接放行", "enabled": True},
            {"id": "dict_ch_app", "category": "渠道", "key": "app", "value": "APP", "remark": "移动应用", "enabled": True},
            {"id": "dict_ch_h5", "category": "渠道", "key": "h5", "value": "H5", "remark": "移动网页", "enabled": True},
            {"id": "dict_ch_api", "category": "渠道", "key": "openapi", "value": "开放平台", "remark": "开放 API", "enabled": True},
            {"id": "dict_dev_ios", "category": "设备类型", "key": "ios", "value": "iOS", "remark": "iOS 设备", "enabled": True},
            {"id": "dict_dev_android", "category": "设备类型", "key": "android", "value": "Android", "remark": "Android 设备", "enabled": True},
            {"id": "dict_dev_web", "category": "设备类型", "key": "web", "value": "Web", "remark": "浏览器", "enabled": True},
        ],
    }
    atomic_write_json(config.DICT_FILE, data)


def seed_flow(flow_store):
    if flow_store.list_flows():
        return
    flow = {
        "id": "flow_amount_guard",
        "name": "大额转账守卫",
        "description": "示例决策流：金额超限拒绝，高风险国家复核，否则放行",
        "version": 1,
        "enabled": True,
        "nodes": [
            {"id": "start", "type": "start", "label": "开始", "x": 60, "y": 180},
            {"id": "c1", "type": "condition", "label": "金额 > 100000",
             "data": {"field": "amount", "op": ">", "value": 100000}, "x": 220, "y": 180},
            {"id": "a_reject", "type": "action", "label": "拒绝",
             "data": {"action": "reject", "risk_score": 90, "reason": "金额超限"}, "x": 420, "y": 90},
            {"id": "c2", "type": "condition", "label": "高风险国家",
             "data": {"field": "country", "op": "in", "value": ["RU", "BR", "NG"]}, "x": 420, "y": 240},
            {"id": "a_review", "type": "action", "label": "人工复核",
             "data": {"action": "review", "risk_score": 60, "reason": "高风险地区"}, "x": 620, "y": 200},
            {"id": "a_pass", "type": "action", "label": "放行",
             "data": {"action": "pass", "risk_score": 0, "reason": "正常交易"}, "x": 620, "y": 320},
        ],
        "edges": [
            {"id": "e1", "from": "start", "to": "c1"},
            {"id": "e2", "from": "c1", "to": "a_reject", "label": "true"},
            {"id": "e3", "from": "c1", "to": "c2", "label": "false"},
            {"id": "e4", "from": "c2", "to": "a_review", "label": "true"},
            {"id": "e5", "from": "c2", "to": "a_pass", "label": "false"},
        ],
    }
    flow_store.save_flow(flow)


def seed_scorecards(store):
    """初始化示例评分卡（幂等：已有评分卡时跳过）。"""
    if store.list_cards():
        return 0

    cards = [
        {
            "id": "sc_transaction_risk",
            "name": "交易风险评分卡",
            "description": "转账/支付/提现交易：金额、地区、设备与操作频率加权评分",
            "enabled": True,
            "priority": 100,
            "event_types": ["transfer", "payment", "withdraw", "order"],
            "base_score": 0,
            "factors": [
                {"name": "交易金额", "type": "range", "field": "amount", "weight": 0.35,
                 "bins": [
                     {"max": 1000, "score": 5},
                     {"min": 1000, "max": 10000, "score": 20},
                     {"min": 10000, "max": 100000, "score": 45},
                     {"min": 100000, "max": 500000, "score": 70},
                     {"min": 500000, "score": 95},
                 ],
                 "default_score": 10},
                {"name": "高风险地区", "type": "match", "field": "country", "weight": 0.2,
                 "cases": [
                     {"op": "in", "value": ["RU", "BR", "NG"], "score": 85},
                 ],
                 "default_score": 0},
                {"name": "新设备", "type": "match", "field": "risk_hint", "weight": 0.15,
                 "cases": [
                     {"op": "==", "value": "new_device", "score": 60},
                 ],
                 "default_score": 0},
                {"name": "短时操作频率", "type": "agg", "weight": 0.3,
                 "agg": {"window_sec": 300, "key_field": "user_id", "agg_type": "count"},
                 "bins": [
                     {"max": 2, "score": 5},
                     {"min": 2, "max": 5, "score": 40},
                     {"min": 5, "score": 85},
                 ],
                 "default_score": 0},
            ],
            "levels": [
                {"level": "低", "min": 0, "max": 30, "action": "pass"},
                {"level": "中", "min": 30, "max": 55, "action": "alert"},
                {"level": "高", "min": 55, "max": 80, "action": "review"},
                {"level": "严重", "min": 80, "action": "reject"},
            ],
        },
        {
            "id": "sc_login_risk",
            "name": "登录风险评分卡",
            "description": "登录事件：登录频率、新设备与来源地区加权评分",
            "enabled": True,
            "priority": 90,
            "event_types": ["login"],
            "base_score": 0,
            "factors": [
                {"name": "登录频率", "type": "agg", "weight": 0.45,
                 "agg": {"window_sec": 60, "key_field": "ip", "agg_type": "count"},
                 "bins": [
                     {"max": 3, "score": 5},
                     {"min": 3, "max": 5, "score": 50},
                     {"min": 5, "score": 90},
                 ],
                 "default_score": 0},
                {"name": "新设备", "type": "match", "field": "risk_hint", "weight": 0.3,
                 "cases": [
                     {"op": "==", "value": "new_device", "score": 65},
                 ],
                 "default_score": 0},
                {"name": "高风险地区", "type": "match", "field": "country", "weight": 0.25,
                 "cases": [
                     {"op": "in", "value": ["RU", "BR", "NG"], "score": 80},
                 ],
                 "default_score": 0},
            ],
            "levels": [
                {"level": "低", "min": 0, "max": 30, "action": "pass"},
                {"level": "中", "min": 30, "max": 55, "action": "alert"},
                {"level": "高", "min": 55, "max": 80, "action": "review"},
                {"level": "严重", "min": 80, "action": "reject"},
            ],
        },
    ]

    for c in cards:
        store.save_card(c, author="system", comment="初始评分卡")
    return len(store.list_cards())


def seed_all(engine, flow_store):
    n_rules = seed_rules(engine.registry)
    seed_dict()
    seed_flow(flow_store)
    seed_scorecards(engine.scorecards)
    return {"rules": n_rules}
