"""
Command-line entrypoint for detection.

Runs the full must-have pipeline in one pass: PCAP import -> DPI ->
signature matching -> beaconing analysis -> AI anomaly detection -> alerts.jsonl.

Example:
    python3 -m detection.cli --pcap sample.pcap --out-dir ./out
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ingestion.pcap_importer import PcapImporter
from dpi.dpi_engine import DPIEngine
from detection.signature_engine import SignatureEngine
from detection.beaconing import BeaconDetector
from detection.ai_anomaly import AIAnomalyDetector  # NEW: Import AI detector


def main():
    parser = argparse.ArgumentParser(description="Signature + beaconing + AI anomaly detection over a PCAP file")
    parser.add_argument("--pcap", required=True, help="Path to a PCAP/PCAPNG file")
    parser.add_argument("--out-dir", default="./out", help="Directory to write alerts.jsonl")
    parser.add_argument("--rules", default=None, help="Path to a custom rules.json (defaults to the bundled ruleset)")
    parser.add_argument("--ai-model", default="ai_model_enhanced.pkl", help="Path to trained AI model (default: ai_model_enhanced.pkl)")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    alerts_path = os.path.join(args.out_dir, "alerts.jsonl")

    importer = PcapImporter(args.pcap)
    dpi = DPIEngine()
    sig_engine = SignatureEngine(rules_path=args.rules)
    beacon_detector = BeaconDetector()
    
    # NEW: Initialize AI detector with enhanced model
    print("[+] Initializing Enhanced AI Anomaly Detector...")
    ai_detector = AIAnomalyDetector(model_path="ai_model_enhanced.pkl", scaler_path="scaler.pkl")
    if ai_detector.model is None:
        print("[!] WARNING: Enhanced AI model not found. Run detection.ai_train first to train the model.")
        print("[!] Continuing without AI detection...")

    all_records = []
    alerts = []

    for record, raw_pkt in importer.iter_packets_with_raw():
        all_records.append(record)
        decoded = dpi.process(raw_pkt, record.packet_id, record.app_protocol_guess)
        
        # Signature detection (existing)
        alerts += sig_engine.check(record, decoded=decoded, raw_pkt=raw_pkt)

    # Beaconing detection (existing)
    alerts += beacon_detector.analyze(all_records)
    
    # NEW: AI Anomaly detection on flows
    print("[+] Running Enhanced AI Anomaly Detection on flows...")
    
    # Build flows from records (similar to flow_tracker.py logic)
    flows = {}
    for record in all_records:
        # FIXED: Use transport_protocol instead of protocol
        flow_key = f"{record.src_ip}_{record.dst_ip}_{record.src_port}_{record.dst_port}_{record.transport_protocol}"
        
        if flow_key not in flows:
            flows[flow_key] = {
                'src_ip': record.src_ip,
                'dst_ip': record.dst_ip,
                'src_port': record.src_port,
                'dst_port': record.dst_port,
                'protocol': record.transport_protocol,  # FIXED: Use transport_protocol
                'fwd_packets': 0,
                'rev_packets': 0,
                'fwd_bytes': 0,
                'rev_bytes': 0,
                'start_time': record.timestamp,
                'end_time': record.timestamp,
                'duration': 0
            }
        
        flow = flows[flow_key]
        if record.src_ip == flow['src_ip'] and record.src_port == flow['src_port']:
            flow['fwd_packets'] += 1
            flow['fwd_bytes'] += record.payload_len
        else:
            flow['rev_packets'] += 1
            flow['rev_bytes'] += record.payload_len
        
        flow['end_time'] = record.timestamp
        flow['duration'] = flow['end_time'] - flow['start_time']
    
    # Run AI detection on each flow
    ai_alerts_count = 0
    for flow in flows.values():
        if ai_detector.model is not None:
            ai_alert = ai_detector.check_flow(flow)
            if ai_alert:
                alerts.append(ai_alert)
                ai_alerts_count += 1
                print(f"[AI] Anomaly detected: {flow.get('src_ip', 'unknown')} -> {flow.get('dst_ip', 'unknown')} "
                      f"(Packets: {flow.get('fwd_packets', 0)}/{flow.get('rev_packets', 0)})")
    
    if ai_alerts_count > 0:
        print(f"[+] AI detected {ai_alerts_count} anomalous flows")

    # FIXED: Sort alerts by timestamp - handle both objects and dictionaries
    def get_timestamp(alert):
        """Get timestamp from either an Alert object or a dict"""
        if hasattr(alert, 'timestamp'):
            return alert.timestamp
        elif isinstance(alert, dict):
            return alert.get('timestamp', 0)
        return 0
    
    alerts.sort(key=get_timestamp)

    # Write alerts to file
    with open(alerts_path, "w") as f:
        for alert in alerts:
            # If it's a dict, convert to JSON directly
            if isinstance(alert, dict):
                f.write(json.dumps(alert) + "\n")
            else:
                # If it's an Alert object, use its to_json method
                f.write(alert.to_json() + "\n")

    # Statistics
    by_category = {}
    by_severity = {}
    for a in alerts:
        if isinstance(a, dict):
            category = a.get('category', 'unknown')
            severity = a.get('severity', 'unknown')
        else:
            category = a.category
            severity = a.severity
        by_category[category] = by_category.get(category, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1

    print(f"[+] {len(alerts)} alerts generated", file=sys.stderr)
    print(f"[+] By category: {by_category}", file=sys.stderr)
    print(f"[+] By severity: {by_severity}", file=sys.stderr)
    print(f"[+] Output: {alerts_path}", file=sys.stderr)


if __name__ == "__main__":
    main()