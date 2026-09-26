"""评分卡配置与沙箱预览 API。"""
import time

from flask import Blueprint, request, jsonify

from backend import runtime
from backend.auth import login_required, role_required, current_user
from backend.storage import gen_id
from backend.scorecard import validate_scorecard, ScorecardValidationError

bp = Blueprint("scorecards", __name__, url_prefix="/api/scorecards")


def _author():
    u = current_user()
    return u["username"] if u else "anonymous"


def _store():
    return runtime.engine.scorecards


@bp.route("", methods=["GET"])
@login_required
def list_cards():
    cards = [dict(c) for c in _store().list_cards()]
    return jsonify({"ok": True, "scorecards": cards})


@bp.route("/validate", methods=["POST"])
@login_required
def validate():
    """评分卡 JSON 校验（不落库）。"""
    data = request.get_json(force=True, silent=True) or {}
    card = data.get("scorecard", data)
    try:
        compiled = validate_scorecard(card)
        return jsonify({
            "ok": True,
            "valid": True,
            "message": "评分卡配置合法",
            "detail": {
                "factors": len(compiled.factors),
                "levels": len(compiled.levels),
                "event_types": compiled.event_types,
                "base_score": compiled.base_score,
            },
        })
    except ScorecardValidationError as exc:
        return jsonify({"ok": True, "valid": False, "message": str(exc)})
    except Exception as exc:
        return jsonify({"ok": True, "valid": False, "message": f"配置非法: {exc}"})


@bp.route("", methods=["POST"])
@role_required("admin", "analyst", "viewer")
def create_card():
    data = request.get_json(force=True, silent=True) or {}
    card = data.get("scorecard", data)
    if not card.get("id"):
        card["id"] = gen_id("sc_")
    try:
        saved, created = _store().save_card(card, author=_author(),
                                            comment=data.get("comment", ""))
    except ScorecardValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "scorecard": saved, "created": created})


@bp.route("/<card_id>", methods=["GET"])
@login_required
def get_card(card_id):
    card = _store().get_card(card_id)
    if card is None:
        return jsonify({"ok": False, "error": "评分卡不存在"}), 404
    return jsonify({"ok": True, "scorecard": card})


@bp.route("/<card_id>", methods=["PUT"])
@role_required("admin", "analyst", "viewer")
def update_card(card_id):
    data = request.get_json(force=True, silent=True) or {}
    card = data.get("scorecard", data)
    card["id"] = card_id
    if _store().get_card(card_id) is None:
        return jsonify({"ok": False, "error": "评分卡不存在"}), 404
    try:
        saved, _ = _store().save_card(card, author=_author(),
                                      comment=data.get("comment", ""))
    except ScorecardValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "scorecard": saved})


@bp.route("/<card_id>", methods=["DELETE"])
@role_required("admin")
def delete_card(card_id):
    ok = _store().delete_card(card_id)
    return jsonify({"ok": ok})


@bp.route("/<card_id>/enable", methods=["POST"])
@role_required("admin", "analyst", "viewer")
def toggle_card(card_id):
    data = request.get_json(force=True, silent=True) or {}
    enabled = bool(data.get("enabled", True))
    card = _store().enable_card(card_id, enabled)
    if card is None:
        return jsonify({"ok": False, "error": "评分卡不存在"}), 404
    return jsonify({"ok": True, "scorecard": card})


@bp.route("/<card_id>/versions", methods=["GET"])
@login_required
def versions(card_id):
    history = _store().versions_of(card_id)
    return jsonify({"ok": True, "history": history})


@bp.route("/<card_id>/rollback", methods=["POST"])
@role_required("admin")
def rollback(card_id):
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("version")
    if target is None:
        return jsonify({"ok": False, "error": "缺少目标版本号"}), 400
    ok = _store().rollback(card_id, int(target), author=_author())
    if not ok:
        return jsonify({"ok": False, "error": "目标版本不存在"}), 404
    return jsonify({"ok": True, "scorecard": _store().get_card(card_id)})


@bp.route("/preview", methods=["POST"])
@login_required
def preview():
    """沙箱预览：评估某事件在指定评分卡（或全部启用卡）下的得分明细。

    请求体三选一：
    - {"event": {...}, "scorecard_id": "sc_xxx"}  评估已保存的某张卡
    - {"event": {...}, "scorecard": {...}}        直接编译未保存的草稿卡
    - {"event": {...}}                            评估全部启用且适用的卡
    """
    data = request.get_json(force=True, silent=True) or {}
    event = data.get("event")
    if not isinstance(event, dict):
        return jsonify({"ok": False, "error": "事件必须是 JSON 对象"}), 400
    event.setdefault("ts", time.time())
    store = _store()
    window = runtime.engine.window

    draft = data.get("scorecard")
    if isinstance(draft, dict) and draft:
        try:
            compiled = store.compile_adhoc(draft)
        except ScorecardValidationError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        result = compiled.evaluate(event, window=window, ts=event["ts"])
        return jsonify({"ok": True, "results": [result], "event": event})

    card_id = data.get("scorecard_id")
    if card_id:
        result = store.evaluate_card(card_id, event, window=window, ts=event["ts"])
        if result is None:
            return jsonify({"ok": False, "error": "评分卡不存在或编译失败"}), 404
        return jsonify({"ok": True, "results": [result], "event": event})

    results = store.evaluate_event(event, ts=event["ts"], window=window)
    return jsonify({"ok": True, "results": results, "event": event})
