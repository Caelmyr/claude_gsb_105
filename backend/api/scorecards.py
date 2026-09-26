"""评分卡配置、版本管理与沙箱预览 API。"""
from flask import Blueprint, request, jsonify

from backend import runtime
from backend.auth import login_required, role_required, current_user
from backend.storage import gen_id
from backend.scorecard import validate_scorecard_json, ScorecardValidationError

bp = Blueprint("scorecards", __name__, url_prefix="/api/scorecards")


def _author():
    u = current_user()
    return u["username"] if u else "anonymous"


@bp.route("", methods=["GET"])
@login_required
def list_scorecards():
    cards = runtime.engine.scorecards.list_cards()
    out = []
    for c in cards:
        out.append({
            "id": c.get("id"),
            "name": c.get("name"),
            "description": c.get("description", ""),
            "enabled": c.get("enabled", True),
            "version": c.get("version", 1),
            "updated_at": c.get("updated_at"),
            "factor_count": len(c.get("factors") or []),
            "levels": [lv.get("name") for lv in c.get("levels") or []],
        })
    return jsonify({"ok": True, "scorecards": out})


@bp.route("/validate", methods=["POST"])
@login_required
def validate():
    """评分卡 JSON 语法校验（不落库）。"""
    data = request.get_json(force=True, silent=True) or {}
    card = data.get("scorecard", data)
    try:
        compiled = validate_scorecard_json(card)
        return jsonify({
            "ok": True,
            "valid": True,
            "message": "评分卡语法合法",
            "detail": {
                "factors": len(compiled.factors),
                "levels": len(compiled.levels),
                "agg_factors": sum(1 for f in compiled.factors if f.agg is not None),
                "base_score": compiled.base_score,
                "max_score": compiled.max_score,
            },
        })
    except ScorecardValidationError as exc:
        return jsonify({"ok": False, "valid": False, "message": str(exc)}), 200


@bp.route("/preview", methods=["POST"])
@login_required
def preview():
    """沙箱预览：给定事件 + 评分卡（JSON 或 scorecard_id），返回得分明细。

    只读操作：不落盘、不告警、不污染滑动窗口之外的任何状态
    （聚合因子仅查询窗口当前值）。
    """
    data = request.get_json(force=True, silent=True) or {}
    event = data.get("event") or {}
    if not isinstance(event, dict):
        return jsonify({"ok": False, "error": "事件必须是 JSON 对象"}), 400
    card = data.get("scorecard")
    card_id = data.get("scorecard_id")
    if card is None and card_id:
        card = runtime.engine.scorecards.get_card(card_id)
        if card is None:
            return jsonify({"ok": False, "error": "评分卡不存在"}), 404
    if card is None:
        return jsonify({"ok": False, "error": "缺少 scorecard 或 scorecard_id"}), 400
    try:
        result = runtime.engine.preview_scorecard(card, event)
    except ScorecardValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "result": result, "event": event})


@bp.route("", methods=["POST"])
@role_required("admin", "analyst", "viewer")
def create_scorecard():
    data = request.get_json(force=True, silent=True) or {}
    card = data.get("scorecard", data)
    if not card.get("id"):
        card["id"] = gen_id("sc_")
    try:
        validate_scorecard_json(card)
    except ScorecardValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    saved, created = runtime.engine.scorecards.save_card(
        card, author=_author(), comment=data.get("comment", ""))
    return jsonify({"ok": True, "scorecard": saved, "created": created})


@bp.route("/<card_id>", methods=["GET"])
@login_required
def get_scorecard(card_id):
    card = runtime.engine.scorecards.get_card(card_id)
    if card is None:
        return jsonify({"ok": False, "error": "评分卡不存在"}), 404
    return jsonify({"ok": True, "scorecard": card})


@bp.route("/<card_id>", methods=["PUT"])
@role_required("admin", "analyst", "viewer")
def update_scorecard(card_id):
    data = request.get_json(force=True, silent=True) or {}
    card = data.get("scorecard", data)
    card["id"] = card_id
    try:
        validate_scorecard_json(card)
    except ScorecardValidationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    saved, _ = runtime.engine.scorecards.save_card(
        card, author=_author(), comment=data.get("comment", ""))
    return jsonify({"ok": True, "scorecard": saved})


@bp.route("/<card_id>", methods=["DELETE"])
@role_required("admin")
def delete_scorecard(card_id):
    ok = runtime.engine.scorecards.delete_card(card_id)
    return jsonify({"ok": ok})


@bp.route("/<card_id>/enable", methods=["POST"])
@role_required("admin", "analyst", "viewer")
def toggle_scorecard(card_id):
    data = request.get_json(force=True, silent=True) or {}
    enabled = bool(data.get("enabled", True))
    card = runtime.engine.scorecards.enable_card(card_id, enabled)
    if card is None:
        return jsonify({"ok": False, "error": "评分卡不存在"}), 404
    return jsonify({"ok": True, "scorecard": card})


@bp.route("/<card_id>/versions", methods=["GET"])
@login_required
def versions(card_id):
    history = runtime.engine.scorecards.versions_of(card_id)
    return jsonify({"ok": True, "history": history})


@bp.route("/<card_id>/rollback", methods=["POST"])
@role_required("admin")
def rollback(card_id):
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("version")
    if target is None:
        return jsonify({"ok": False, "error": "缺少目标版本号"}), 400
    ok = runtime.engine.scorecards.rollback(card_id, int(target), author=_author())
    if not ok:
        return jsonify({"ok": False, "error": "目标版本不存在"}), 404
    return jsonify({"ok": True, "scorecard": runtime.engine.scorecards.get_card(card_id)})
