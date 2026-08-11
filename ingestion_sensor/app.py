"""
NetFalcon - Ingestion Sensor

Captures live packets and forwards completed
network flows to the Processing Engine.
"""

import logging
import threading
import time
import uuid

import requests

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP


# =====================================================
# Configuration
# =====================================================

PROCESSING_ENGINE_URL = "http://127.0.0.1:8001/api/ingest/flow"

INTERFACE = "Ethernet"

FLOW_TIMEOUT = 30        # seconds

MAX_PACKETS_PER_FLOW = 20

HTTP_TIMEOUT = 2


# =====================================================
# Logging
# =====================================================

logging.basicConfig(

    filename="sensor.log",

    level=logging.INFO,

    format="%(asctime)s | %(levelname)s | %(message)s"

)


# =====================================================
# Flow Cache
# =====================================================

FLOW_CACHE = {}

print("=" * 60)
print("NetFalcon Ingestion Sensor")
print("=" * 60)
print("Waiting for network packets...")
print()
# =====================================================
# Flow Builder
# =====================================================

def update_flow(packet, protocol, src_port, dst_port):

    key = (
        packet[IP].src,
        packet[IP].dst,
        src_port,
        dst_port,
        protocol
    )

    current_time = time.time()

    if key not in FLOW_CACHE:

        FLOW_CACHE[key] = {

            "flow_id": str(uuid.uuid4()),

            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,

            "src_port": src_port,
            "dst_port": dst_port,

            "protocol": protocol,

            "start_ts": current_time,
            "end_ts": current_time,

            "packet_count": 1,

            "total_bytes": len(packet),

            "packets": [
                {
                    "length": len(packet),
                    "timestamp": current_time
                }
            ]

        }

    else:

        flow = FLOW_CACHE[key]

        flow["packet_count"] += 1

        flow["total_bytes"] += len(packet)

        flow["end_ts"] = current_time

        flow["packets"].append(
            {
                "length": len(packet),
                "timestamp": current_time
            }
        )

    return FLOW_CACHE[key]

# =====================================================
# Packet Callback
# =====================================================

def packet_callback(packet):
    """
    Called every time Scapy captures a packet.
    """

    if not packet.haslayer(IP):
        return

    protocol = "OTHER"
    src_port = 0
    dst_port = 0

    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    # Build / Update Flow
    flow = update_flow(
        packet,
        protocol,
        src_port,
        dst_port
    )

    print(
        f"[{protocol}] "
        f"{flow['src_ip']}:{flow['src_port']} -> "
        f"{flow['dst_ip']}:{flow['dst_port']} "
        f"Packets={flow['packet_count']}"
    )

    # Send flow after enough packets
    if flow["packet_count"] >= MAX_PACKETS_PER_FLOW:

        try:

            response = requests.post(
                PROCESSING_ENGINE_URL,
                json=flow,
                timeout=HTTP_TIMEOUT
            )

            print(f"✓ Flow sent ({response.status_code})")

            logging.info(
                "Flow %s sent successfully",
                flow["flow_id"]
            )

        except Exception as e:

            print("Processing Engine Offline:", e)

            logging.error(str(e))

        # Remove completed flow
        key = (
            flow["src_ip"],
            flow["dst_ip"],
            flow["src_port"],
            flow["dst_port"],
            flow["protocol"]
        )

        FLOW_CACHE.pop(key, None)


        # =====================================================
# Flow Timeout Manager
# =====================================================

def flush_old_flows():
    """
    Background thread that periodically sends
    completed or idle flows.
    """

    while True:

        time.sleep(5)

        current_time = time.time()

        expired = []

        for key, flow in list(FLOW_CACHE.items()):

            idle_time = current_time - flow["end_ts"]

            if idle_time >= FLOW_TIMEOUT:

                try:

                    response = requests.post(
                        PROCESSING_ENGINE_URL,
                        json=flow,
                        timeout=HTTP_TIMEOUT
                    )

                    print(
                        f"✓ Idle Flow Sent ({response.status_code})"
                    )

                    logging.info(
                        "Idle Flow Sent : %s",
                        flow["flow_id"]
                    )

                except Exception as e:

                    print("Processing Engine Offline:", e)

                    logging.error(str(e))

                expired.append(key)

        for key in expired:

            FLOW_CACHE.pop(key, None)

            # =====================================================
# Main
# =====================================================

if __name__ == "__main__":

    print("=" * 60)
    print("NetFalcon Ingestion Sensor")
    print("=" * 60)
    print(f"Interface           : {INTERFACE}")
    print(f"Processing Engine   : {PROCESSING_ENGINE_URL}")
    print(f"Flow Timeout        : {FLOW_TIMEOUT} sec")
    print(f"Packets Per Flow    : {MAX_PACKETS_PER_FLOW}")
    print("=" * 60)
    print()

    # Start background thread
    threading.Thread(
        target=flush_old_flows,
        daemon=True
    ).start()

    logging.info("Sensor Started")

    print("Waiting for packets...\n")

    try:

        sniff(
            iface=INTERFACE,
            prn=packet_callback,
            store=False
        )

    except KeyboardInterrupt:

        print("\nStopping Sensor...")

        logging.info("Sensor Stopped")

    except Exception as e:

        print("Fatal Error:", e)

        logging.exception(e)