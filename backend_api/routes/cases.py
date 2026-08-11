"""
routes/cases.py
----------------
REST API endpoints for the Backend API (Service 3):
    - Cases            (investigation case management)
    - Evidence Vault    (SHA-256 sealed evidence + chain of custody)
    - Alerts            (signature/AI detections, correlated into cases)

Consumed by frontend_ui: CaseVault.jsx, LiveAlerts.jsx, TrafficGraph.jsx.
"""

import hashlib
import logging

from flask import Blueprint, request, jsonify

from database.db_connection import get_db_cursor

logger = logging.getLogger("routes.cases")
cases_bp = Blueprint("cases_bp", __name__, url_prefix="/api")

VALID_STATUSES = {"Under Investigation", "Escalated", "Closed", "Archived"}


# =============================================================================
# CASES
# =============================================================================

@cases_bp.route("/cases", methods=["GET"])
def list_cases():
    """GET /api/cases?status=&threat_type=&search="""
    status = request.args.get("status")
    threat_type = request.args.get("threat_type")
    search = request.args.get("search")

    query = "SELECT * FROM cases WHERE 1=1"
    params = []

    if status:
        query += " AND status = %s"
        params.append(status)
    if threat_type:
        query += " AND threat_type ILIKE %s"
        params.append(f"%{threat_type}%")
    if search:
        query += " AND (case_number ILIKE %s OR title ILIKE %s OR investigator ILIKE %s)"
        params.extend([f"%{search}%"] * 3)

    query += " ORDER BY opened_at DESC"

    with get_db_cursor() as cur:
        cur.execute(query, params)
        cases = cur.fetchall()

    return jsonify({"count": len(cases), "cases": cases}), 200


@cases_bp.route("/cases", methods=["POST"])
def create_case():
    """POST /api/cases — body: {case_number, investigator, threat_type, title?, summary?, status?}"""
    data = request.get_json(force=True, silent=True) or {}
    required = ["case_number", "investigator", "threat_type"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    with get_db_cursor(commit=True) as cur:
        cur.execute(
            """
            INSERT INTO cases (case_number, title, investigator, threat_type, status, summary)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (
                data["case_number"],
                data.get("title"),
                data["investigator"],
                data["threat_type"],
                data.get("status", "Under Investigation"),
                data.get("summary"),
            ),
        )
        new_case = cur.fetchone()

    return jsonify(new_case), 201


@cases_bp.route("/cases/<int:case_id>", methods=["GET"])
def get_case(case_id):
    """Full case detail: case + alerts + evidence + chain of custody (for CaseVault.jsx)."""
    with get_db_cursor() as cur:
        cur.execute("SELECT * FROM cases WHERE case_id = %s", (case_id,))
        case = cur.fetchone()
        if not case:
            return jsonify({"error": "Case not found"}), 404

        cur.execute("SELECT * FROM alerts WHERE case_id = %s ORDER BY detected_at DESC", (case_id,))
        alerts = cur.fetchall()

        cur.execute("SELECT * FROM evidence_vault WHERE case_id = %s ORDER BY created_at ASC", (case_id,))
        evidence = cur.fetchall()

        evidence_ids = [e["evidence_id"] for e in evidence]
        custody_log = []
        if evidence_ids:
            cur.execute(
                "SELECT * FROM chain_of_custody WHERE evidence_id = ANY(%s) ORDER BY action_at ASC",
                (evidence_ids,),
            )
            custody_log = cur.fetchall()

    case["alerts"] = alerts
    case["evidence"] = evidence
    case["chain_of_custody"] = custody_log
    return jsonify(case), 200


@cases_bp.route("/cases/<int:case_id>", methods=["PATCH"])
def update_case(case_id):
    """Partial update, e.g. {"status": "Closed"}."""
    data = request.get_json(force=True, silent=True) or {}
    allowed_fields = {"title", "investigator", "threat_type", "status", "summary", "closed_at"}
    updates = {k: v for k, v in data.items() if k in allowed_fields}

    if not updates:
        return jsonify({"error": "No valid fields to update"}), 400
    if "status" in updates and updates["status"] not in VALID_STATUSES:
        return jsonify({"error": f"status must be one of {sorted(VALID_STATUSES)}"}), 400

    set_clause = ", ".join(f"{col} = %s" for col in updates)
    params = list(updates.values()) + [case_id]

    with get_db_cursor(commit=True) as cur:
        cur.execute(
            f"UPDATE cases SET {set_clause}, updated_at = NOW() WHERE case_id = %s RETURNING *",
            params,
        )
        updated = cur.fetchone()

    if not updated:
        return jsonify({"error": "Case not found"}), 404
    return jsonify(updated), 200


# =============================================================================
# EVIDENCE VAULT / CHAIN OF CUSTODY
# =============================================================================

@cases_bp.route("/cases/<int:case_id>/evidence", methods=["GET"])
def list_evidence(case_id):
    with get_db_cursor() as cur:
        cur.execute("SELECT * FROM evidence_vault WHERE case_id = %s ORDER BY created_at ASC", (case_id,))
        evidence = cur.fetchall()
    return jsonify({"count": len(evidence), "evidence": evidence}), 200


@cases_bp.route("/cases/<int:case_id>/evidence", methods=["POST"])
def add_evidence(case_id):
    """
    Seals a new evidence item into the vault and opens its chain of custody.

    Accepts either:
      - multipart/form-data with a 'file' part (hash computed here), or
      - application/json with a pre-computed 'sha256_hash' (e.g. sealed
        upstream by processing_engine/utils/legal_hasher.py before this
        call is made).
    """
    with get_db_cursor() as cur:
        cur.execute("SELECT case_id FROM cases WHERE case_id = %s", (case_id,))
        if not cur.fetchone():
            return jsonify({"error": "Case not found"}), 404

    alert_id = request.args.get("alert_id")

    if "file" in request.files:
        file_obj = request.files["file"]
        filename = file_obj.filename
        evidence_type = request.form.get("evidence_type", "packet_capture")
        added_by = request.form.get("added_by", "System")
        file_bytes = file_obj.read()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        file_path = f"/evidence_store/{case_id}/{filename}"
    else:
        data = request.get_json(force=True, silent=True) or {}
        filename = data.get("filename")
        evidence_type = data.get("evidence_type", "packet_capture")
        sha256_hash = data.get("sha256_hash")
        file_path = data.get("file_path")
        added_by = data.get("added_by", "System")
        if not filename or not sha256_hash:
            return jsonify({"error": "filename and sha256_hash are required"}), 400

    with get_db_cursor(commit=True) as cur:
        cur.execute(
            """
            INSERT INTO evidence_vault
                (case_id, alert_id, filename, evidence_type, file_path, sha256_hash, captured_at, added_by, status)
            VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s, 'SEALED')
            RETURNING *
            """,
            (case_id, alert_id, filename, evidence_type, file_path, sha256_hash, added_by),
        )
        evidence = cur.fetchone()

        cur.execute(
            """
            INSERT INTO chain_of_custody (evidence_id, action, actor, notes)
            VALUES (%s, %s, %s, %s)
            """,
            (evidence["evidence_id"], "Evidence captured & hashed", added_by, f"SHA-256: {sha256_hash}"),
        )

    return jsonify(evidence), 201


@cases_bp.route("/evidence/<int:evidence_id>/custody", methods=["POST"])
def add_custody_entry(evidence_id):
    """Appends a manual chain-of-custody entry, e.g. review/transfer/verification."""
    data = request.get_json(force=True, silent=True) or {}
    action = data.get("action")
    actor = data.get("actor")
    if not action or not actor:
        return jsonify({"error": "action and actor are required"}), 400

    with get_db_cursor(commit=True) as cur:
        cur.execute("SELECT evidence_id FROM evidence_vault WHERE evidence_id = %s", (evidence_id,))
        if not cur.fetchone():
            return jsonify({"error": "Evidence item not found"}), 404

        cur.execute(
            """
            INSERT INTO chain_of_custody (evidence_id, action, actor, notes)
            VALUES (%s, %s, %s, %s)
            RETURNING *
            """,
            (evidence_id, action, actor, data.get("notes")),
        )
        entry = cur.fetchone()

    return jsonify(entry), 201


# =============================================================================
# ALERTS
# =============================================================================

@cases_bp.route("/alerts", methods=["GET"])
def list_alerts():
    """GET /api/alerts?severity=&engine=&protocol=&case_id=&limit= (for LiveAlerts.jsx)"""
    severity = request.args.get("severity")
    engine = request.args.get("engine")
    protocol = request.args.get("protocol")
    case_id = request.args.get("case_id")
    limit = min(int(request.args.get("limit", 100)), 500)

    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if severity:
        query += " AND severity = %s"
        params.append(severity.upper())
    if engine:
        query += " AND detection_engine = %s"
        params.append(engine.upper())
    if protocol:
        query += " AND protocol = %s"
        params.append(protocol.upper())
    if case_id:
        query += " AND case_id = %s"
        params.append(case_id)

    query += " ORDER BY detected_at DESC LIMIT %s"
    params.append(limit)

    with get_db_cursor() as cur:
        cur.execute(query, params)
        alerts = cur.fetchall()

    return jsonify({"count": len(alerts), "alerts": alerts}), 200


@cases_bp.route("/alerts/<int:alert_id>", methods=["GET"])
def get_alert(alert_id):
    """Alert detail — backs 'Open Session Replay' in the AI Anomaly Detection panel."""
    with get_db_cursor() as cur:
        cur.execute("SELECT * FROM alerts WHERE alert_id = %s", (alert_id,))
        alert = cur.fetchone()
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(alert), 200


@cases_bp.route("/alerts/<int:alert_id>/assign-case", methods=["POST"])
def assign_alert_to_case(alert_id):
    """Backs the 'Add to Case' button — correlates an alert into an investigation."""
    data = request.get_json(force=True, silent=True) or {}
    case_id = data.get("case_id")
    if not case_id:
        return jsonify({"error": "case_id is required"}), 400

    with get_db_cursor(commit=True) as cur:
        cur.execute("SELECT case_id FROM cases WHERE case_id = %s", (case_id,))
        if not cur.fetchone():
            return jsonify({"error": "Case not found"}), 404

        cur.execute(
            "UPDATE alerts SET case_id = %s, is_reviewed = TRUE WHERE alert_id = %s RETURNING *",
            (case_id, alert_id),
        )
        alert = cur.fetchone()

    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(alert), 200


@cases_bp.route("/alerts/stats", methods=["GET"])
def alert_stats():
    """Aggregate counts for dashboard widgets (TrafficGraph.jsx / heatmaps)."""
    with get_db_cursor() as cur:
        cur.execute("SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity")
        by_severity = cur.fetchall()

        cur.execute("SELECT protocol, COUNT(*) AS count FROM alerts GROUP BY protocol")
        by_protocol = cur.fetchall()

        cur.execute(
            """
            SELECT date_trunc('hour', detected_at) AS hour, COUNT(*) AS count
            FROM alerts
            WHERE detected_at > NOW() - INTERVAL '24 hours'
            GROUP BY hour ORDER BY hour
            """
        )
        by_hour = cur.fetchall()

    return jsonify({
        "by_severity": by_severity,
        "by_protocol": by_protocol,
        "last_24h_by_hour": by_hour,
    }), 200
