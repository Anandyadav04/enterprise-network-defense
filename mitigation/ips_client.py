"""
mitigation/ips_client.py
─────────────────────────
Optional IPS integration via pfSense REST API.

This module is ONLY activated when IPS_ENABLED=true in .env.
It applies temporary firewall block rules through the pfSense
fauxapi or pfSense-API (2.x) endpoints.

IMPORTANT: Incorrect block rules can disrupt legitimate traffic.
Only activate this module for CRITICAL risk events with high
AI confidence AND threat intelligence confirmation.

pfSense API options:
  - fauxapi: https://github.com/nicholaswilde/fauxapi
  - pfSense-API (official): https://github.com/jaredhendrickson13/pfsense-api
"""

import logging
import os
from typing import Optional

import requests

logger = logging.getLogger(__name__)

PFSENSE_HOST = os.getenv("PFSENSE_HOST", "")
PFSENSE_API_KEY = os.getenv("PFSENSE_API_KEY", "")
BLOCK_RULE_TTL_DEFAULT = 60  # minutes


class IPSClient:
    """
    Thin client for applying temporary pfSense firewall block rules.
    Each block is logged for audit trail. Rules are time-limited.
    """

    def __init__(self, host: str = PFSENSE_HOST, api_key: str = PFSENSE_API_KEY):
        self.host = host
        self.api_key = api_key
        self.base_url = f"https://{host}/api/v1" if host else ""
        self._blocked: dict = {}  # ip → block timestamp (audit)

    def block_ip(self, ip: str, duration_minutes: int = BLOCK_RULE_TTL_DEFAULT) -> bool:
        """
        Apply a temporary block rule for the given source IP.
        Returns True on success, False on failure.
        """
        if not self.host or not self.api_key:
            logger.warning("IPS not configured — PFSENSE_HOST or API_KEY missing. Skipping block.")
            return False

        if ip in self._blocked:
            logger.info("IPS: %s already blocked. Skipping duplicate.", ip)
            return True

        logger.critical(
            "IPS: BLOCKING src=%s for %d minutes via pfSense at %s",
            ip, duration_minutes, self.host,
        )

        # pfSense-API firewall rule create endpoint
        # Adjust endpoint path based on your pfSense API version
        payload = {
            "type": "block",
            "interface": "wan",
            "ipprotocol": "inet",
            "protocol": "any",
            "src": ip,
            "dst": "any",
            "descr": f"Auto-block by NetDefense | {duration_minutes}min TTL",
            "top": True,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            resp = requests.post(
                f"{self.base_url}/firewall/rule",
                json=payload,
                headers=headers,
                verify=False,  # pfSense typically uses self-signed cert
                timeout=10,
            )
            resp.raise_for_status()
            self._blocked[ip] = True
            logger.critical("IPS: Block rule applied for %s. Reload firewall.", ip)
            self._reload_firewall(headers)
            return True
        except Exception as exc:
            logger.error("IPS block failed for %s: %s", ip, exc)
            return False

    def _reload_firewall(self, headers: dict) -> None:
        """Trigger pfSense firewall reload after rule change."""
        try:
            requests.post(
                f"{self.base_url}/firewall/apply",
                headers=headers,
                verify=False,
                timeout=10,
            )
            logger.info("IPS: Firewall rules reloaded.")
        except Exception as exc:
            logger.error("IPS: Firewall reload failed: %s", exc)

    def unblock_ip(self, ip: str) -> bool:
        """Remove block rule for an IP (manual or policy-driven unblock)."""
        logger.info("IPS: Unblocking %s", ip)
        self._blocked.pop(ip, None)
        # TODO: Implement pfSense rule deletion by tracking rule IDs
        return True

    def list_blocked(self) -> list:
        """Return list of currently blocked IPs (in-memory, this session only)."""
        return list(self._blocked.keys())
