"""
redis/flow_cache.py
────────────────────
Redis client wrapper for storing and retrieving in-progress
network flow state across packet processing iterations.

Uses JSON serialization with a configurable TTL (default: 180s).
"""

import json
import logging
from typing import Optional

import redis

logger = logging.getLogger(__name__)

DEFAULT_TTL = 180  # seconds — flow entries expire after this idle period


class FlowCache:
    """
    Thin Redis wrapper for network flow state management.
    All keys are prefixed with 'flow:' to namespace within Redis.
    """

    KEY_PREFIX = "flow:"

    def __init__(self, host: str = "localhost", port: int = 6379, db: int = 0, ttl: int = DEFAULT_TTL):
        self.ttl = ttl
        self._client = redis.Redis(host=host, port=port, db=db, decode_responses=True)
        logger.info("FlowCache connected to Redis at %s:%s", host, port)

    def get(self, flow_key: str) -> Optional[dict]:
        """Retrieve a flow record by key. Returns None if not found."""
        raw = self._client.get(self.KEY_PREFIX + flow_key)
        if raw is None:
            return None
        data = json.loads(raw)
        # Restore set type for tcp_flag_set (serialized as list)
        if "tcp_flags_seen" in data:
            data["tcp_flag_set"] = set(data.get("tcp_flags_seen", []))
        return data

    def set(self, flow_key: str, flow: dict) -> None:
        """Store or update a flow record with TTL refresh."""
        serializable = {k: list(v) if isinstance(v, set) else v for k, v in flow.items()}
        self._client.setex(
            name=self.KEY_PREFIX + flow_key,
            time=self.ttl,
            value=json.dumps(serializable),
        )

    def delete(self, flow_key: str) -> None:
        """Remove a flow record (after emission)."""
        self._client.delete(self.KEY_PREFIX + flow_key)

    def list_keys(self) -> list:
        """Return all active flow keys (without prefix)."""
        keys = self._client.keys(self.KEY_PREFIX + "*")
        return [k.removeprefix(self.KEY_PREFIX) for k in keys]

    def flush_all_flows(self) -> int:
        """Delete all flow keys. Use carefully — for testing only."""
        keys = self._client.keys(self.KEY_PREFIX + "*")
        if keys:
            return self._client.delete(*keys)
        return 0

    def ping(self) -> bool:
        """Check Redis connectivity."""
        try:
            return self._client.ping()
        except redis.ConnectionError:
            return False
