"""
NetFalcon - Ingestion Sensor

Captures live packets, builds flow records, and forwards completed flows to
processing_engine using a JSON-safe, versioned flow schema.
"""

import base64
import logging
import os
import threading
import time
import uuid

import requests
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw


PROCESSING_ENGINE_URL = os.environ.get(
    "PROCESSING_ENGINE_URL",
    "http://127.0.0.1:8001/api/ingest/flow",
)
# Leave empty to let Scapy choose the default interface. Override with
# NETFALCON_INTERFACE=Ethernet / eth0 / wlan0 when a specific NIC is needed.
INTERFACE = os.environ.get("NETFALCON_INTERFACE", "")
FLOW_TIMEOUT = float(os.environ.get("FLOW_TIMEOUT", "30"))
MAX_PACKETS_PER_FLOW = int(os.environ.get("MAX_PACKETS_PER_FLOW", "20"))
HTTP_TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "10"))
MAX_PAYLOAD_BYTES = int(os.environ.get("MAX_PAYLOAD_BYTES", "4096"))
FLOW_SCHEMA_VERSION = 1

logging.basicConfig(
    filename="sensor.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

FLOW_CACHE = {}


def _packet_payload(packet) -> bytes:
    """Return application payload bytes, capped to keep flow JSON bounded."""
    if packet.haslayer(Raw):
        return bytes(packet[Raw].load)[:MAX_PAYLOAD_BYTES]
    return b""


def _dns_metadata(packet):
    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]
    metadata = {"qtype": None, "rdata_len": 0}

    if dns.qdcount and packet.haslayer(DNSQR):
        qtype = packet[DNSQR].qtype
        try:
            from scapy.layers.dns import dnsqtypes
            qtype_name = dnsqtypes.get(qtype, str(qtype))
        except Exception:
            qtype_name = str(qtype)
        metadata["qtype"] = qtype_name.upper()

    # DNS answers are represented as a linked list in Scapy. For the
    # tunneling signature we only need the total textual/bytes RDATA size.
    total = 0
    answer = dns.an
    seen = 0
    while answer is not None and seen < 100:
        try:
            rdata = getattr(answer, "rdata", b"")
            total += len(rdata if isinstance(rdata, (bytes, bytearray)) else str(rdata).encode())
        except Exception:
            pass
        answer = getattr(answer, "payload", None)
        if not getattr(answer, "name", None):
            break
        seen += 1
    metadata["rdata_len"] = total
    return metadata


def _new_flow(packet, protocol, src_port, dst_port, current_time):
    payload = _packet_payload(packet)
    flow = {
        "schema_version": FLOW_SCHEMA_VERSION,
        "flow_id": str(uuid.uuid4()),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "start_ts": current_time,
        "end_ts": current_time,
        "duration": 0.0,
        "packet_count": 1,
        "total_bytes": len(packet),
        "syn_count": 0,
        "ttl": int(getattr(packet[IP], "ttl", 64)),
        "packets": [
            {
                "length": len(packet),
                "timestamp": current_time,
                "payload_b64": base64.b64encode(payload).decode("ascii") if payload else "",
            }
        ],
    }

    if protocol == "TCP":
        flags = int(packet[TCP].flags)
        # SYN without ACK is a connection initiation and is the useful
        # primitive for the SYN-flood signature.
        flow["syn_count"] = int(bool(flags & 0x02) and not bool(flags & 0x10))

    dns = _dns_metadata(packet)
    if dns is not None:
        flow["app_layer_type"] = "dns"
        flow["app_layer"] = {"dns": dns}
        flow["dns_rdata_len"] = dns["rdata_len"]
    return flow


def update_flow(packet, protocol, src_port, dst_port):
    key = (
        packet[IP].src,
        packet[IP].dst,
        src_port,
        dst_port,
        protocol,
    )
    current_time = time.time()

    if key not in FLOW_CACHE:
        FLOW_CACHE[key] = _new_flow(packet, protocol, src_port, dst_port, current_time)
    else:
        flow = FLOW_CACHE[key]
        payload = _packet_payload(packet)
        flow["packet_count"] += 1
        flow["total_bytes"] += len(packet)
        flow["end_ts"] = current_time
        flow["duration"] = max(flow["end_ts"] - flow["start_ts"], 0.0)
        flow["ttl"] = int(getattr(packet[IP], "ttl", flow.get("ttl", 64)))
        flow["packets"].append(
            {
                "length": len(packet),
                "timestamp": current_time,
                "payload_b64": base64.b64encode(payload).decode("ascii") if payload else "",
            }
        )

        if protocol == "TCP":
            flags = int(packet[TCP].flags)
            if flags & 0x02 and not flags & 0x10:
                flow["syn_count"] = flow.get("syn_count", 0) + 1

        dns = _dns_metadata(packet)
        if dns is not None:
            flow["app_layer_type"] = "dns"
            flow["app_layer"] = {"dns": dns}
            flow["dns_rdata_len"] = max(flow.get("dns_rdata_len", 0), dns["rdata_len"])

    return FLOW_CACHE[key]


def _finalize_flow(flow):
    flow = dict(flow)
    flow["duration"] = max(float(flow.get("end_ts", time.time())) - float(flow.get("start_ts", time.time())), 0.0)
    return flow


def _send_flow(flow, reason):
    payload = _finalize_flow(flow)
    try:
        response = requests.post(
            PROCESSING_ENGINE_URL,
            json=payload,
            timeout=HTTP_TIMEOUT,
        )
        response.raise_for_status()
        print(f"✓ {reason}: flow sent ({response.status_code})")
        logging.info("Flow %s sent successfully (%s)", flow["flow_id"], reason)
        return True
    except requests.RequestException as exc:
        print("Processing Engine Offline:", exc)
        logging.error("Flow %s failed to send: %s", flow.get("flow_id"), exc)
        return False


def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    protocol = "OTHER"
    src_port = 0
    dst_port = 0

    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    flow = update_flow(packet, protocol, src_port, dst_port)

    print(
        f"[{protocol}] {flow['src_ip']}:{flow['src_port']} -> "
        f"{flow['dst_ip']}:{flow['dst_port']} Packets={flow['packet_count']}"
    )

    if flow["packet_count"] >= MAX_PACKETS_PER_FLOW:
        key = (
            flow["src_ip"], flow["dst_ip"], flow["src_port"],
            flow["dst_port"], flow["protocol"]
        )
        _send_flow(flow, "Flow")
        FLOW_CACHE.pop(key, None)


def flush_old_flows():
    while True:
        time.sleep(5)
        current_time = time.time()
        expired = []

        for key, flow in list(FLOW_CACHE.items()):
            idle_time = current_time - flow["end_ts"]
            if idle_time >= FLOW_TIMEOUT:
                _send_flow(flow, "Idle flow")
                expired.append(key)

        for key in expired:
            FLOW_CACHE.pop(key, None)


def main():
    print("=" * 60)
    print("NetFalcon Ingestion Sensor")
    print("=" * 60)
    print(f"Interface           : {INTERFACE or 'Scapy default'}")
    print(f"Processing Engine   : {PROCESSING_ENGINE_URL}")
    print(f"Flow Timeout        : {FLOW_TIMEOUT} sec")
    print(f"Packets Per Flow    : {MAX_PACKETS_PER_FLOW}")
    print(f"Schema Version      : {FLOW_SCHEMA_VERSION}")
    print("=" * 60)

    threading.Thread(target=flush_old_flows, daemon=True).start()
    logging.info("Sensor Started")

    sniff_kwargs = {"prn": packet_callback, "store": False}
    if INTERFACE:
        sniff_kwargs["iface"] = INTERFACE

    try:
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        print("\nStopping Sensor...")
        logging.info("Sensor Stopped")
    except Exception as exc:
        print("Fatal Error:", exc)
        logging.exception("Fatal sensor error")


if __name__ == "__main__":
    main()
