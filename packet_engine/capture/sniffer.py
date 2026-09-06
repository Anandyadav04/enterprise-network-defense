"""
capture/sniffer.py
──────────────────
Live packet capture using Scapy from a network interface.
Publishes raw packet data to the internal packet queue for preprocessing.

Responsibilities:
- Open the capture interface in promiscuous mode
- Filter out noise (ARP, spanning-tree, etc.) via BPF filters
- Pass each captured packet to PacketParser for decoding
- Support both live capture (Scapy) and PCAP replay (for testing)
"""

import logging
from scapy.all import sniff, conf
from packet_engine.parser.packet_parser import PacketParser

logger = logging.getLogger(__name__)


class PacketSniffer:
    """
    Captures live packets from a network interface and forwards
    them to the PacketParser for decoding and feature extraction.
    """

    def __init__(self, interface: str, parser: PacketParser, bpf_filter: str = "ip"):
        self.interface = interface
        self.parser = parser
        self.bpf_filter = bpf_filter
        conf.sniff_promisc = True

    def _packet_callback(self, packet) -> None:
        """Called by Scapy for each captured packet."""
        try:
            self.parser.process(packet)
        except Exception as exc:
            logger.warning("Error processing packet: %s", exc)

    def start(self) -> None:
        """Start live packet capture (blocking)."""
        logger.info(
            "Starting capture on interface=%s filter='%s'",
            self.interface,
            self.bpf_filter,
        )
        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=self._packet_callback,
            store=False,
        )

    def replay_pcap(self, pcap_path: str) -> None:
        """Replay a PCAP file for offline testing."""
        logger.info("Replaying PCAP: %s", pcap_path)
        sniff(
            offline=pcap_path,
            filter=self.bpf_filter,
            prn=self._packet_callback,
            store=False,
        )
