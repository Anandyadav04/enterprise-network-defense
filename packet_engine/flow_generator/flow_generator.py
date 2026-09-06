"""
flow_generator/flow_generator.py
─────────────────────────────────
Assembles individual packets into network flows (sessions).
Maintains in-progress flow state in Redis and publishes
completed/timed-out flows to the Kafka `raw-alerts` topic.

A flow is keyed by: (src_ip, dst_ip, src_port, dst_port, protocol)
Flow features align with CIC-IDS2017 feature set for AI compatibility.
"""

import json
import logging
import time
from typing import Optional

from packet_engine.redis.flow_cache import FlowCache
from kafka import KafkaProducer

logger = logging.getLogger(__name__)

FLOW_TIMEOUT_SECONDS = 120      # Idle timeout before a flow is considered complete
TCP_FIN_RST_FLAGS = {"F", "R"}  # TCP flags indicating session end


class FlowGenerator:
    """
    Stateful flow aggregator. Tracks per-flow packet statistics
    and emits completed flows as Kafka messages.
    """

    def __init__(self, flow_cache: FlowCache, producer: KafkaProducer, topic: str = "raw-flows"):
        self.cache = flow_cache
        self.producer = producer
        self.topic = topic

    def process_packet(self, packet: dict) -> None:
        """Update flow state for an incoming decoded packet."""
        flow_key = self._flow_key(packet)
        if not flow_key:
            return

        flow = self.cache.get(flow_key) or self._init_flow(packet, flow_key)

        # Update flow statistics
        flow["packet_count"] += 1
        flow["byte_count"] += packet.get("packet_len", 0)
        flow["last_seen"] = time.time()

        fwd = packet["src_ip"] == flow["src_ip"]
        if fwd:
            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += packet.get("packet_len", 0)
        else:
            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += packet.get("packet_len", 0)

        # Track inter-arrival times
        if flow["last_pkt_time"]:
            iat = time.time() - flow["last_pkt_time"]
            flow["iat_list"].append(iat)
        flow["last_pkt_time"] = time.time()

        # Accumulate DNS queries
        if packet.get("is_dns") and packet.get("dns_query"):
            flow["dns_queries"].append(packet["dns_query"])

        # TCP flag tracking
        if packet.get("tcp_flags"):
            flow["tcp_flag_set"].update(set(packet["tcp_flags"]))

        self.cache.set(flow_key, flow)

        # Check for TCP session termination
        if packet.get("tcp_flags") and TCP_FIN_RST_FLAGS & set(packet["tcp_flags"]):
            self._emit_flow(flow_key, flow)

    def expire_flows(self) -> None:
        """Emit all flows that have exceeded FLOW_TIMEOUT_SECONDS."""
        now = time.time()
        for key in self.cache.list_keys():
            flow = self.cache.get(key)
            if flow and (now - flow.get("last_seen", now)) > FLOW_TIMEOUT_SECONDS:
                self._emit_flow(key, flow)

    def _emit_flow(self, key: str, flow: dict) -> None:
        """Publish a completed flow to Kafka and remove from cache."""
        flow["duration"] = flow["last_seen"] - flow["start_time"]
        flow["iat_mean"] = (
            sum(flow["iat_list"]) / len(flow["iat_list"]) if flow["iat_list"] else 0.0
        )
        flow["iat_std"] = self._std(flow["iat_list"])
        flow["dns_query_count"] = len(flow["dns_queries"])
        flow["tcp_flags_seen"] = list(flow["tcp_flag_set"])

        # Remove non-serializable runtime fields
        flow.pop("iat_list", None)
        flow.pop("tcp_flag_set", None)

        self.producer.send(self.topic, value=json.dumps(flow).encode())
        self.cache.delete(key)
        logger.debug("Flow emitted: %s", key)

    def _init_flow(self, packet: dict, key: str) -> dict:
        return {
            "flow_key": key,
            "src_ip": packet["src_ip"],
            "dst_ip": packet["dst_ip"],
            "src_port": packet.get("src_port"),
            "dst_port": packet.get("dst_port"),
            "protocol": packet["protocol"],
            "start_time": time.time(),
            "last_seen": time.time(),
            "last_pkt_time": None,
            "packet_count": 0,
            "byte_count": 0,
            "fwd_packets": 0,
            "fwd_bytes": 0,
            "bwd_packets": 0,
            "bwd_bytes": 0,
            "iat_list": [],
            "dns_queries": [],
            "tcp_flag_set": set(),
            "duration": 0.0,
        }

    @staticmethod
    def _flow_key(packet: dict) -> Optional[str]:
        try:
            parts = (
                packet["src_ip"],
                packet["dst_ip"],
                str(packet.get("src_port", 0)),
                str(packet.get("dst_port", 0)),
                packet["protocol"],
            )
            return "|".join(parts)
        except KeyError:
            return None

    @staticmethod
    def _std(values: list) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        return (sum((x - mean) ** 2 for x in values) / len(values)) ** 0.5
