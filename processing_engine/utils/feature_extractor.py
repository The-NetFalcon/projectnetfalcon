"""
Feature Extraction Engine
-------------------------

Converts a network flow into:

1. ML feature vector (Isolation Forest input)
2. Signals for signature detection

Output format:

{
    "vector": [...],
    "signals": {...}
}
"""

import math


class FeatureExtractor:

    def __init__(self):
        pass

    def extract(self, flow: dict):

        packets = flow.get("packets", [])

        packet_count = len(packets)

        duration = max(
            float(flow.get("duration", 0.001)),
            0.001
        )

        total_bytes = float(flow.get("total_bytes", 0))

        src_port = int(flow.get("src_port", 0))

        dst_port = int(flow.get("dst_port", 0))

        protocol = flow.get("protocol", "").upper()

        ttl = float(flow.get("ttl", 64))

        # -----------------------------
        # Packet statistics
        # -----------------------------

        packets_per_second = packet_count / duration

        average_packet_size = (
            total_bytes / packet_count
            if packet_count > 0
            else 0
        )

        # -----------------------------
        # Protocol Encoding
        # -----------------------------

        protocol_map = {
            "TCP": 6,
            "UDP": 17,
            "ICMP": 1
        }

        protocol_number = protocol_map.get(protocol, 0)

        # -----------------------------
        # Payload Entropy
        # -----------------------------

        entropy = self.calculate_entropy(packets)

        # -----------------------------
        # ML Feature Vector
        # -----------------------------

        vector = [

            packet_count,

            total_bytes,

            duration,

            packets_per_second,

            average_packet_size,

            protocol_number,

            src_port,

            dst_port,

            ttl,

            entropy

        ]

        # -----------------------------
        # Signature Signals
        # -----------------------------

        signals = {

            "packet_count": packet_count,

            "packets_per_second": packets_per_second,

            "avg_packet_size": average_packet_size,

            "avg_payload_entropy": entropy,

            "syn_count": flow.get("syn_count", 0),

            "dns_rdata_len": flow.get("dns_rdata_len", 0),

            "app_layer_type": flow.get("app_layer_type")

        }

        return {

            "vector": vector,

            "signals": signals

        }

    # ---------------------------------
    # Shannon Entropy
    # ---------------------------------

    def calculate_entropy(self, packets):

        if not packets:
            return 0

        byte_frequency = {}

        total = 0

        for payload in packets:

            if isinstance(payload, bytes):

                for b in payload:

                    byte_frequency[b] = (
                        byte_frequency.get(b, 0) + 1
                    )

                    total += 1

        if total == 0:
            return 0

        entropy = 0

        for count in byte_frequency.values():

            probability = count / total

            entropy -= probability * math.log2(probability)

        return round(entropy, 4)