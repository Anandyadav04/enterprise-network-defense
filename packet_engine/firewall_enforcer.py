"""
packet_engine/firewall_enforcer.py
──────────────────────────────────
Host-Level Linux Netfilter (iptables) Enforcement Engine.

Provides zero-trust microsegmentation and active host-based packet dropping
inside the target DMZ container namespace (shared with enterprise-web-app).

Subscribes to Redis channel 'firewall:rules' and executes kernel-level
iptables DROP rules in real-time when the SOC Dashboard or AI IPS mitigates an IP.
"""

import os
import json
import time
import logging
import subprocess
import threading
import redis

logger = logging.getLogger("HostIPSEnforcer")

REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
CHANNEL_NAME = "firewall:rules"
ACTIVE_BLOCKS_KEY = "firewall:active_blocks"


def run_iptables_command(cmd_args: list) -> bool:
    """Executes an iptables command safely and logs results."""
    try:
        res = subprocess.run(
            ["iptables"] + cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        return res.returncode == 0
    except Exception as e:
        logger.error("iptables execution error (%s): %s", " ".join(cmd_args), e)
        return False


def apply_drop_rule(ip: str) -> bool:
    """Applies iptables DROP rule for the specified source IP."""
    if not ip or ip.lower() in ("unknown", "127.0.0.1", "localhost"):
        return False

    # Check if rule already exists in INPUT chain
    if run_iptables_command(["-C", "INPUT", "-s", ip, "-j", "DROP"]):
        logger.info("[HOST-IPS] Rule already present for %s. Skipping duplicate.", ip)
        return True

    # Prepend DROP rule at top of INPUT chain
    success = run_iptables_command(["-I", "INPUT", "-s", ip, "-j", "DROP"])
    if success:
        logger.critical("🔥 [HOST-IPS] Kernel DROP rule enforced: Blocked all packets from %s", ip)
    else:
        logger.error("Failed to inject iptables DROP rule for %s", ip)
    return success


def remove_drop_rule(ip: str) -> bool:
    """Removes iptables DROP rule for the specified source IP."""
    if not ip:
        return False

    success = run_iptables_command(["-D", "INPUT", "-s", ip, "-j", "DROP"])
    if success:
        logger.info("🟢 [HOST-IPS] Kernel DROP rule removed: Restored traffic from %s", ip)
    else:
        logger.warning("[HOST-IPS] Rule for %s not found in INPUT chain or already removed.", ip)
    return success


def sync_existing_blocks(r: redis.Redis) -> None:
    """Re-applies any previously active blocks stored in Redis on startup."""
    try:
        active_ips = r.smembers(ACTIVE_BLOCKS_KEY)
        if active_ips:
            logger.info("[HOST-IPS] Syncing %d active firewall block rules from Redis...", len(active_ips))
            for raw_ip in active_ips:
                ip = raw_ip.decode("utf-8") if isinstance(raw_ip, bytes) else str(raw_ip)
                apply_drop_rule(ip)
    except Exception as e:
        logger.warning("Could not sync active blocks from Redis: %s", e)


def firewall_listener_loop():
    """Background listener that processes real-time firewall pub/sub events."""
    logger.info("Initializing Host-Level IPS Netfilter Enforcer (Redis pub/sub: %s)...", CHANNEL_NAME)

    while True:
        try:
            r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
            r.ping()
            logger.info("Host-IPS connected to Redis at %s:%d", REDIS_HOST, REDIS_PORT)

            # Re-apply active rules from Redis state
            sync_existing_blocks(r)

            pubsub = r.pubsub()
            pubsub.subscribe(CHANNEL_NAME)
            logger.info("Listening for real-time firewall block/unblock events...")

            for message in pubsub.listen():
                if message["type"] != "message":
                    continue

                try:
                    data = json.loads(message["data"])
                    action = data.get("action", "").upper()
                    ip = data.get("ip", "").strip()

                    if action == "BLOCK" and ip:
                        apply_drop_rule(ip)
                    elif action == "UNBLOCK" and ip:
                        remove_drop_rule(ip)
                    else:
                        logger.warning("Unrecognized firewall event: %s", data)
                except Exception as parse_err:
                    logger.error("Failed to process firewall message: %s", parse_err)

        except Exception as conn_err:
            logger.warning("Host-IPS Redis connection lost (%s). Reconnecting in 5s...", conn_err)
            time.sleep(5)


def start_firewall_enforcer():
    """Launches the firewall enforcer listener in a daemon background thread."""
    t = threading.Thread(target=firewall_listener_loop, name="FirewallEnforcerThread", daemon=True)
    t.start()
    return t
