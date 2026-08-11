"""
processing_engine/app.py
-------------------------
This is the heart of the Midnight Protocol: Stages 03-08 of the data
workflow diagram.

    ingestion_sensor  --HTTP POST-->  processing_engine  --HTTP/WS-->  backend_api / frontend_ui
    (capture)                         (DPI, features,                 (case mgmt, dashboard)
                                        signature + AI engines,
                                        correlation, evidence hashing)

Responsibilities:
  03  Deep Packet Inspection      -> flows arrive already protocol-decoded
                                      by ingestion_sensor; this service
                                      trusts the flow schema.
  04  Feature Extraction          -> utils/feature_extractor.py
  05  Threat Detection Engine     -> run_signature_engine() + run_ai_engine(),
                                      then correlate_alert()
  06  Dashboard & Visualization   -> GET /api/alerts, GET /api/incidents,
                                      Socket.IO 'new_alert' push
  07  Investigator Workflow       -> handled by backend_api (case mgmt),
                                      this service forwards alerts to it
  08  Evidence Generation         -> utils/legal_hasher.py

Run:
    python app.py
Env vars:
    PORT                    (default 8001)
    BACKEND_API_URL         (default http://backend_api:5000) - best-effort forward
    MODEL_PATH              (default models/anomaly_model.pkl)
    ANOMALY_SCORE_THRESHOLD (default 0.0 -- IsolationForest decision_function < 0 => anomaly)
"""

import os
import threading
import time
from datetime import datetime
from collections import defaultdict, deque

    

import joblib
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO

from utils.feature_extractor import FeatureExtractor
from utils.legal_hasher import LegalHasher

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.environ.get("MODEL_PATH", os.path.join(BASE_DIR, "models", "anomaly_model.pkl"))
RULES_PATH = os.path.join(BASE_DIR, "signature_rules.json")
VAULT_PATH = os.environ.get("EVIDENCE_VAULT_PATH", os.path.join(BASE_DIR, "evidence_vault.json"))
BACKEND_API_URL = os.environ.get("BACKEND_API_URL", "http://backend_api:5000")
ANOMALY_SCORE_THRESHOLD = float(os.environ.get("ANOMALY_SCORE_THRESHOLD", "0.0"))

app = Flask(__name__)
app.config["DEBUG"] = True
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

extractor = FeatureExtractor()
hasher = LegalHasher(vault_path=VAULT_PATH)
SERVICE_START_TIME = time.time()    

import json as _json
with open(RULES_PATH) as f:
    SIGNATURE_RULES = _json.load(f)

# --------------------------------------------------------------------------
# Model loading (fails soft: engine still runs signature-only if no model)
# --------------------------------------------------------------------------
_model_bundle = None
if os.path.exists(MODEL_PATH):
    try:
        _model_bundle = joblib.load(MODEL_PATH)
        print(f"[processing_engine] Loaded AI model from {MODEL_PATH} "
              f"(trained on {_model_bundle.get('trained_on_rows', '?')} rows)")
    except Exception as e:  # noqa: BLE001
        print(f"[processing_engine] WARNING: failed to load model at {MODEL_PATH}: {e}")
else:
    print(f"[processing_engine] WARNING: no model found at {MODEL_PATH}. "
          f"Run `python models/train_model.py` first. Running signature-only.")

# --------------------------------------------------------------------------
# In-memory state (swap for Redis/Kafka in production for multi-worker use)
# --------------------------------------------------------------------------
_state_lock = threading.Lock()
ALERTS = deque(maxlen=5000)                      # newest-first ring buffer
INCIDENTS = defaultdict(list)                    # (src_ip,dst_ip) -> [alert_ids]  (Stage 05 correlation)
PORT_SCAN_TRACKER = defaultdict(lambda: deque())  # src_ip -> deque[(ts, dst_port)]
SYN_TRACKER = defaultdict(lambda: deque())        # src_ip -> deque[ts]


# ==========================================================================
# Signature engine  (Stage 05, left branch: "known attack rules")
# ==========================================================================
def run_signature_engine(flow: dict, signals: dict) -> list:
    """Evaluate every rule in signature_rules.json against this flow.
    Returns a list of matched-rule dicts."""
    hits = []
    src_ip = flow.get("src_ip")
    dst_port = flow.get("dst_port")
    now = flow.get("end_ts", time.time())

    for rule in SIGNATURE_RULES:
        rtype = rule["type"]
        params = rule["params"]

        if rtype == "port_scan":
            window = params["window_seconds"]
            dq = PORT_SCAN_TRACKER[src_ip]
            dq.append((now, dst_port))
            while dq and now - dq[0][0] > window:
                dq.popleft()
            if len({p for _, p in dq}) >= params["unique_ports_threshold"]:
                hits.append(rule)

        elif rtype == "dns_tunneling":
            if signals.get("app_layer_type") == "dns":
                dns = flow.get("app_layer", {}).get("dns", {})
                if (dns.get("qtype") in params["qtypes"]
                        and signals.get("dns_rdata_len", 0) >= params["rdata_len_threshold"]):
                    hits.append(rule)

        elif rtype == "syn_flood":
            if signals.get("syn_count", 0) > 0:
                window = params["window_seconds"]
                dq = SYN_TRACKER[src_ip]
                dq.append(now)
                while dq and now - dq[0] > window:
                    dq.popleft()
                if len(dq) >= params["syn_count_threshold"]:
                    hits.append(rule)

        elif rtype == "ioc_match":
            if src_ip in params["ioc_list"] or flow.get("dst_ip") in params["ioc_list"]:
                hits.append(rule)

        elif rtype == "high_entropy_payload":
            if (dst_port in params["plaintext_ports"]
                    and signals.get("avg_payload_entropy", 0) >= params["entropy_threshold"]):
                hits.append(rule)

        # ftp_bruteforce / smtp_burst need cross-flow app-layer counters;
        # left as extension points -- wire up the same sliding-window
        # pattern as port_scan/syn_flood above once ingestion_sensor
        # forwards per-command FTP/SMTP events.

    return hits


# ==========================================================================
# AI engine  (Stage 05, right branch: "unsupervised, no labels required")
# ==========================================================================
def run_ai_engine(vector: list):
    """Returns (is_anomaly: bool, anomaly_score: float) or (False, None) if
    no model is loaded."""
    if _model_bundle is None:
        return False, None
    model = _model_bundle["model"]
    scaler = _model_bundle["scaler"]
    X = scaler.transform([vector])
    score = float(model.decision_function(X)[0])  # lower = more anomalous
    is_anomaly = score < ANOMALY_SCORE_THRESHOLD
    return is_anomaly, score


# ==========================================================================
# Correlation  (Stage 05: "Correlate alerts, reduce false positives,
#               prioritize real threats" -> builds the attack timeline)
# ==========================================================================
def correlate_alert(alert: dict) -> str:
    key = f"{alert['src_ip']}->{alert['dst_ip']}"
    with _state_lock:
        INCIDENTS[key].append(alert["alert_id"])
        incident_size = len(INCIDENTS[key])
    alert["incident_key"] = key
    alert["incident_alert_count"] = incident_size
    return key


# ==========================================================================
# Core pipeline: one flow in -> zero or one alert out
# ==========================================================================
def process_flow(flow: dict):
    features = extractor.extract(flow)
    signals = features["signals"]

    sig_hits = run_signature_engine(flow, signals)
    is_anomaly, anomaly_score = run_ai_engine(features["vector"])

    if not sig_hits and not is_anomaly:
        return None  # clean traffic, nothing to report

    severity = "critical" if any(r["severity"] == "critical" for r in sig_hits) else (
        "high" if (sig_hits and any(r["severity"] == "high" for r in sig_hits)) or (
            is_anomaly and anomaly_score is not None and anomaly_score < -0.15
        ) else "medium"
    )

    alert = {
        "alert_id": f"ALT-{int(time.time() * 1000)}-{flow.get('flow_id', 'unknown')[:8]}",
        "flow_id": flow.get("flow_id"),
        "src_ip": flow.get("src_ip"),
        "dst_ip": flow.get("dst_ip"),
        "src_port": flow.get("src_port"),
        "dst_port": flow.get("dst_port"),
        "protocol": flow.get("protocol"),
        "timestamp": flow.get("end_ts", time.time()),
        "detection_method": (
            "signature+ai" if sig_hits and is_anomaly else
            "signature" if sig_hits else "ai"
        ),
        "matched_rules": [{"id": r["id"], "name": r["name"]} for r in sig_hits],
        "anomaly_score": anomaly_score,
        "severity": severity,
        "signals": signals,
    }

    correlate_alert(alert)

    # Stage 08: hash + chain-of-custody
    evidence_block = hasher.add_evidence(
        {"alert": alert, "flow_summary": {
            "flow_id": flow.get("flow_id"),
            "packet_count": len(flow.get("packets", [])),
        }},
        actor="processing_engine",
    )
    alert["evidence_id"] = evidence_block["evidence_id"]
    alert["evidence_hash"] = evidence_block["evidence_hash"]

    with _state_lock:
        ALERTS.appendleft(alert)

    socketio.emit("new_alert", alert)
    _forward_to_backend(alert)
    return alert


def _forward_to_backend(alert: dict):
    """Best-effort push to backend_api so it can persist the alert into a
    case. Non-fatal if backend_api isn't up yet (e.g. teammates still
    building it) -- the alert already lives in this service's own state
    and evidence vault."""
    try:
        requests.post(f"{BACKEND_API_URL}/api/alerts", json=alert, timeout=1.5)
    except requests.RequestException:
        pass


# ==========================================================================
# HTTP API
# ==========================================================================
@app.route("/health", methods=["GET"])
def health():
    uptime = int(time.time() - SERVICE_START_TIME)

    return jsonify({
        "status": "healthy",
        "service": "NetFalcon Processing Engine",
        "version": "1.0.0",

        "model_loaded": _model_bundle is not None,
        "rules_loaded": len(SIGNATURE_RULES),

        "alerts": len(ALERTS),
        "incidents": len(INCIDENTS),
        "evidence_records": len(hasher.all_evidence()),

        "uptime_seconds": uptime,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })


@app.route("/api/ingest/flow", methods=["POST"])
def ingest_flow():
    """Single-flow ingestion, called by ingestion_sensor for each completed
    session (or periodically for long-lived ones)."""
    flow = request.get_json(force=True)
    alert = process_flow(flow)
    return jsonify({"alert": alert}), 200


@app.route("/api/ingest/flows", methods=["POST"])
def ingest_flows():
    """Batch ingestion -- more efficient than one HTTP call per flow."""
    payload = request.get_json(force=True)
    flows = payload.get("flows", [])
    results = [a for a in (process_flow(f) for f in flows) if a]
    return jsonify({"alerts": results, "processed": len(flows), "flagged": len(results)}), 200


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    limit = int(request.args.get("limit", 100))
    with _state_lock:
        return jsonify(list(ALERTS)[:limit])


@app.route("/api/incidents", methods=["GET"])
def get_incidents():
    with _state_lock:
        return jsonify({k: v for k, v in INCIDENTS.items()})


@app.route("/api/evidence/verify", methods=["GET"])
def verify_evidence():
    is_valid, broken_index = hasher.verify_chain()
    return jsonify({"valid": is_valid, "broken_at_index": broken_index,
                     "chain_length": len(hasher.all_evidence())})


@app.route("/api/evidence/<evidence_id>", methods=["GET"])
def get_evidence(evidence_id):
    block = hasher.get_evidence(evidence_id)
    if not block:
        return jsonify({"error": "not found"}), 404
    return jsonify(block)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8001))

    print(
        f"[processing_engine] Starting on :{port} "
        f"(model={'loaded' if _model_bundle else 'MISSING'}, "
        f"rules={len(SIGNATURE_RULES)}, backend={BACKEND_API_URL})"
    )

    socketio.run(
        app,
        host="0.0.0.0",
        port=port,
        debug=False,
        use_reloader=False
    )