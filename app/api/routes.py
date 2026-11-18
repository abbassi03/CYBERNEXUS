import hmac
from flask import Blueprint, current_app, jsonify, request
from ..security import utcnow, audit
from ..services.events import store_event

bp = Blueprint("api", __name__, url_prefix="/api/v1")


@bp.get("/health")
def health():
    return jsonify({"service": "CYBERNEXUS", "status": "ok", "timestamp": utcnow(), "version": "1.0.0"})


@bp.post("/events")
def ingest_event():
    expected = current_app.config.get("INGEST_API_KEY", "")
    supplied = request.headers.get("X-API-Key", "")
    if not expected:
        return jsonify({"error": "Event ingestion API is disabled. Configure CYBERNEXUS_INGEST_KEY."}), 503
    if not supplied or not hmac.compare_digest(expected, supplied):
        return jsonify({"error": "Unauthorized"}), 401
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json."}), 415
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON object required."}), 400
    try:
        row = store_event(payload)
        audit("api_event_ingested", "event", row["id"], f"Source: {row['source']}")
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({
        "id": row["id"], "severity": row["severity"], "risk_score": row["risk_score"],
        "is_anomalous": bool(row["is_anomalous"]), "detection_reason": row["detection_reason"],
    }), 201
