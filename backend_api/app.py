"""
app.py
------
Backend API (Service 3): Central Flask + WebSocket server.

Responsibilities:
    - Serve REST endpoints (routes/cases.py, routes/export_pdf.py)
    - Consume correlated alerts published to Kafka by processing_engine
    - Persist alerts to PostgreSQL
    - Broadcast real-time events over WebSockets to frontend_ui

Expected Kafka message (topic: KAFKA_ALERTS_TOPIC), published by
processing_engine after signature + AI detection + correlation:
    {
        "source_ip": "192.168.1.45",
        "destination_ip": "185.x.x.x",
        "destination_port": 53,
        "protocol": "DNS",
        "alert_type": "DNS Tunneling Detected",
        "severity": "CRITICAL",
        "detection_engine": "AI",
        "anomaly_score": 9.84,
        "baseline_deviation": 3.7,
        "description": "Unusually large TXT payload, consistent with tunneled data exfiltration."
    }
"""

import eventlet
eventlet.monkey_patch()

import os
import json
import logging
import threading

from flask import Flask, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

from database.db_connection import init_pool, get_db_cursor, close_pool
from routes.cases import cases_bp
from routes.export_pdf import export_bp

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("backend_api")

KAFKA_BROKER = os.environ.get("KAFKA_BROKER", "kafka:9092")
KAFKA_TOPIC = os.environ.get("KAFKA_ALERTS_TOPIC", "processed-alerts")
KAFKA_GROUP_ID = os.environ.get("KAFKA_GROUP_ID", "backend-api-group")
CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": CORS_ORIGINS}})
socketio = SocketIO(app, cors_allowed_origins=CORS_ORIGINS, async_mode="eventlet")

app.register_blueprint(cases_bp)
app.register_blueprint(export_bp)


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "backend_api"}), 200


@socketio.on("connect")
def handle_connect():
    logger.info("Frontend client connected")


@socketio.on("disconnect")
def handle_disconnect():
    logger.info("Frontend client disconnected")


def _persist_alert(alert_data: dict):
    """Inserts a Kafka-delivered alert into `alerts` and returns the stored row."""
    with get_db_cursor(commit=True) as cur:
        cur.execute(
            """
            INSERT INTO alerts (
                source_ip, destination_ip, destination_port, protocol,
                alert_type, severity, detection_engine, anomaly_score,
                baseline_deviation, description, raw_payload
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
            """,
            (
                alert_data.get("source_ip"),
                alert_data.get("destination_ip"),
                alert_data.get("destination_port"),
                alert_data.get("protocol"),
                alert_data.get("alert_type"),
                alert_data.get("severity", "MEDIUM"),
                alert_data.get("detection_engine", "SIGNATURE"),
                alert_data.get("anomaly_score"),
                alert_data.get("baseline_deviation"),
                alert_data.get("description"),
                json.dumps(alert_data),
            ),
        )
        return cur.fetchone()


def kafka_consumer_loop():
    """
    Background thread: consumes correlated alerts from processing_engine
    and broadcasts them to every connected dashboard in real time.
    """
    try:
        consumer = KafkaConsumer(
            KAFKA_TOPIC,
            bootstrap_servers=KAFKA_BROKER,
            group_id=KAFKA_GROUP_ID,
            auto_offset_reset="latest",
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            enable_auto_commit=True,
        )
    except NoBrokersAvailable:
        logger.error(f"Could not reach Kafka broker at {KAFKA_BROKER}. Consumer thread exiting.")
        return

    logger.info(f"Listening for alerts on Kafka topic '{KAFKA_TOPIC}' @ {KAFKA_BROKER}")

    for message in consumer:
        try:
            alert_data = message.value
            stored_alert = _persist_alert(alert_data)

            socketio.emit("new_alert", stored_alert)
            if stored_alert.get("severity") == "CRITICAL":
                socketio.emit("critical_alert", stored_alert)

            logger.info(
                f"Alert ingested: {stored_alert.get('alert_type')} "
                f"from {stored_alert.get('source_ip')} [{stored_alert.get('severity')}]"
            )
        except Exception as exc:
            logger.exception(f"Failed to process Kafka message: {exc}")


def start_background_consumer():
    thread = threading.Thread(target=kafka_consumer_loop, daemon=True)
    thread.start()


# Runs on both `python app.py` and `gunicorn app:app` (module-level import)
init_pool()
start_background_consumer()


if __name__ == "__main__":
    try:
        socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
    finally:
        close_pool()
