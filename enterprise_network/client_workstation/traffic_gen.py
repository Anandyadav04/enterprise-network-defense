"""
enterprise_network/client_workstation/traffic_gen.py
─────────────────────────────────────────────────────
Simulates a legitimate corporate employee workstation.

Generates realistic benign network traffic to the DMZ enterprise
web server, mimicking normal employee browsing and API usage patterns.

Traffic patterns:
  1. Home page browsing (GET /)
  2. Status checks (GET /api/status)
  3. Employee directory searches (GET /api/search?q=...)
  4. Document downloads (GET /docs/download?file=...)
  5. Robots.txt fetches (simulating browser/crawler behavior)

All traffic is HTTP over TCP from Corporate LAN (10.0.1.25)
to DMZ Web Server (10.0.2.80), which is exactly the kind
of benign baseline the AI classifier should learn to ignore.
"""

import os
import time
import random
import logging
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("client-workstation")

# ── Configuration ─────────────────────────────────────────────────
WEB_APP_URL = os.environ.get("WEB_APP_URL", "http://enterprise-web-app")

# Traffic timing (seconds between requests)
MIN_INTERVAL = int(os.environ.get("MIN_INTERVAL", "3"))
MAX_INTERVAL = int(os.environ.get("MAX_INTERVAL", "8"))

# Simulated user agents for realistic HTTP headers
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 Safari/17.2",
    "Enterprise-Internal-Monitor/1.0",
]

# Realistic search queries an employee might run
SEARCH_QUERIES = [
    "Engineering", "Finance", "Marketing", "HR",
    "Alice", "Bob", "David", "security",
    "DevOps", "analyst", "director",
]

# Available documents to request
DOCUMENTS = [
    "annual_report.pdf",
    "security_policy.pdf",
    "employee_handbook.pdf",
    "network_topology.png",
]


# ── Traffic Generators ────────────────────────────────────────────

def browse_home(session):
    """Simulate browsing the corporate home page."""
    try:
        r = session.get(f"{WEB_APP_URL}/", timeout=5)
        logger.info("📄 Home page — %d (%d bytes)", r.status_code, len(r.content))
    except Exception as e:
        logger.warning("Home page error: %s", e)


def check_status(session):
    """Simulate an IT health-check API call."""
    try:
        r = session.get(f"{WEB_APP_URL}/api/status", timeout=5)
        data = r.json()
        logger.info("💚 Status check — %s (uptime: %ss)", data.get("status"), data.get("uptime_seconds"))
    except Exception as e:
        logger.warning("Status check error: %s", e)


def search_directory(session):
    """Simulate an employee searching the corporate directory."""
    query = random.choice(SEARCH_QUERIES)
    try:
        r = session.get(f"{WEB_APP_URL}/api/search", params={"q": query}, timeout=5)
        data = r.json()
        logger.info("🔍 Search '%s' — %d results", query, data.get("count", 0))
    except Exception as e:
        logger.warning("Search error: %s", e)


def download_document(session):
    """Simulate downloading a corporate document."""
    doc = random.choice(DOCUMENTS)
    try:
        r = session.get(f"{WEB_APP_URL}/docs/download", params={"file": doc}, timeout=5)
        logger.info("📥 Download '%s' — %d", doc, r.status_code)
    except Exception as e:
        logger.warning("Download error: %s", e)


def fetch_robots(session):
    """Simulate a browser/crawler fetching robots.txt."""
    try:
        r = session.get(f"{WEB_APP_URL}/robots.txt", timeout=5)
        logger.info("🤖 Robots.txt — %d", r.status_code)
    except Exception as e:
        logger.warning("Robots.txt error: %s", e)


# ── Main Loop ─────────────────────────────────────────────────────

# Weighted action selection — browsing and status checks are most common
ACTIONS = [
    (browse_home,       30),
    (check_status,      25),
    (search_directory,  25),
    (download_document, 15),
    (fetch_robots,       5),
]


def weighted_choice(actions):
    """Select a random action based on weights."""
    total = sum(w for _, w in actions)
    r = random.uniform(0, total)
    running = 0
    for action, weight in actions:
        running += weight
        if r <= running:
            return action
    return actions[0][0]


def wait_for_server():
    """Wait until the web server is reachable before starting traffic."""
    logger.info("Waiting for enterprise web app at %s ...", WEB_APP_URL)
    while True:
        try:
            r = requests.get(f"{WEB_APP_URL}/api/status", timeout=3)
            if r.ok:
                logger.info("✅ Enterprise Web App is reachable! Starting traffic generation.")
                return
        except Exception:
            pass
        time.sleep(2)


def main():
    logger.info("═══════════════════════════════════════════════════════")
    logger.info("  CLIENT WORKSTATION — Corporate Traffic Generator")
    logger.info("  Target: %s", WEB_APP_URL)
    logger.info("  Interval: %d–%d seconds", MIN_INTERVAL, MAX_INTERVAL)
    logger.info("═══════════════════════════════════════════════════════")

    wait_for_server()

    session = requests.Session()
    session.headers.update({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/json",
        "X-Employee-ID": "EMP-10025",
        "X-Department": "Engineering",
    })

    request_count = 0
    while True:
        action = weighted_choice(ACTIONS)
        action(session)
        request_count += 1

        if request_count % 50 == 0:
            logger.info("📊 Total requests sent: %d", request_count)
            # Rotate user agent occasionally
            session.headers["User-Agent"] = random.choice(USER_AGENTS)

        delay = random.uniform(MIN_INTERVAL, MAX_INTERVAL)
        time.sleep(delay)


if __name__ == "__main__":
    main()
