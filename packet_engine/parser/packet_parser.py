"""
parser/packet_parser.py
───────────────────────
Decodes raw Scapy packets into structured dictionaries.
Identifies protocols, extracts payload metadata, and forwards
decoded packets to the FlowGenerator.

Protocols handled: Ethernet, IP, TCP, UDP, DNS, HTTP (cleartext),
                   ICMP, TLS (metadata only).
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from scapy.all import Packet, IP, TCP, UDP, DNS, ICMP, Raw

logger = logging.getLogger(__name__)


class PacketParser:
    """
    Stateless packet decoder. Extracts fields needed for flow
    generation and feature extraction from a raw Scapy Packet.
    """

    PROTOCOL_MAP = {6: "TCP", 17: "UDP", 1: "ICMP"}

    def process(self, packet: Packet) -> Optional[dict]:
        """
        Decode a Scapy packet into a structured dict.
        Returns None if the packet is not IP-layer.
        """
        if not packet.haslayer(IP):
            return None

        ip = packet[IP]
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "protocol": self.PROTOCOL_MAP.get(ip.proto, str(ip.proto)),
            "ip_proto_num": ip.proto,
            "ttl": ip.ttl,
            "ip_flags": str(ip.flags),
            "packet_len": len(packet),
            "src_port": None,
            "dst_port": None,
            "tcp_flags": None,
            "payload_bytes": 0,
            "payload_entropy": 0.0,
            "is_dns": False,
            "dns_query": None,
        }

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            record["src_port"] = tcp.sport
            record["dst_port"] = tcp.dport
            record["tcp_flags"] = str(tcp.flags)

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            record["src_port"] = udp.sport
            record["dst_port"] = udp.dport

            if packet.haslayer(DNS):
                dns = packet[DNS]
                record["is_dns"] = True
                if dns.qd:
                    record["dns_query"] = dns.qd.qname.decode(errors="replace")

        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            record["icmp_type"] = icmp.type
            record["icmp_code"] = icmp.code

        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            record["payload_bytes"] = len(payload)
            record["payload_entropy"] = self._byte_entropy(payload)

        return record

    @staticmethod
    def _byte_entropy(data: bytes) -> float:
        """Shannon entropy of a byte sequence (0.0 – 8.0)."""
        if not data:
            return 0.0
        from math import log2
        freq = [data.count(b) / len(data) for b in set(data)]
        return -sum(p * log2(p) for p in freq if p > 0)
