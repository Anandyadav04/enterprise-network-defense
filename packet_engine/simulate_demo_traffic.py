"""
simulate_demo_traffic.py
─────────────────────────
Generates a realistic mix of BENIGN and MALICIOUS network events
for demonstration purposes. Injects directly into Kafka 'raw-alerts'.
"""

import json
import random
import time
from datetime import datetime, timedelta
from kafka import KafkaProducer

# ── Realistic IP pools ──
INTERNAL_IPS = [
    "10.0.1.15", "10.0.1.22", "10.0.1.48", "10.0.2.10", "10.0.2.33",
    "10.0.3.5", "10.0.3.17", "192.168.1.100", "192.168.1.105", "192.168.1.112",
]

EXTERNAL_BENIGN = [
    "8.8.8.8", "1.1.1.1", "142.250.195.68", "151.101.1.140",
    "13.107.42.14", "104.16.132.229", "172.217.14.110", "52.96.166.130",
]

EXTERNAL_MALICIOUS = [
    "185.15.59.224", "45.33.32.156", "91.219.237.229", "198.51.100.23",
    "203.0.113.42", "77.247.181.163", "185.220.101.34", "23.129.64.217",
]

# ── Attack scenarios ──
ATTACK_SCENARIOS = [
    {
        "signature": "ET MALWARE Win32/Trickbot Data Exfiltration",
        "category": "A Network Trojan was detected",
        "severity": 1,
        "src_port": 4444, "dst_port": 443,
    },
    {
        "signature": "ET SCAN Potential SSH Scan",
        "category": "Attempted Information Leak",
        "severity": 2,
        "src_port": random.randint(40000, 65000), "dst_port": 22,
    },
    {
        "signature": "ET EXPLOIT Possible SQL Injection Attempt",
        "category": "Web Application Attack",
        "severity": 1,
        "src_port": random.randint(40000, 65000), "dst_port": 80,
    },
    {
        "signature": "ET TROJAN CobaltStrike Beacon Activity",
        "category": "A Network Trojan was detected",
        "severity": 1,
        "src_port": random.randint(40000, 65000), "dst_port": 443,
    },
    {
        "signature": "ET DOS Possible NTP DDoS Amplification",
        "category": "Attempted Denial of Service",
        "severity": 2,
        "src_port": 123, "dst_port": random.randint(1024, 65000),
    },
    {
        "signature": "ET POLICY DNS Query to .onion Proxy Domain",
        "category": "Potentially Bad Traffic",
        "severity": 2,
        "src_port": random.randint(40000, 65000), "dst_port": 53,
    },
    {
        "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
        "category": "Attempted Information Leak",
        "severity": 2,
        "src_port": random.randint(40000, 65000), "dst_port": 80,
    },
]

BENIGN_SCENARIOS = [
    {
        "signature": None,
        "category": None,
        "severity": 3,
        "desc": "HTTPS Web Browsing",
        "src_port_range": (40000, 65000), "dst_port": 443,
        "proto": "TCP",
    },
    {
        "signature": None,
        "category": None,
        "severity": 3,
        "desc": "DNS Resolution",
        "src_port_range": (40000, 65000), "dst_port": 53,
        "proto": "UDP",
    },
    {
        "signature": None,
        "category": None,
        "severity": 3,
        "desc": "HTTP Web Traffic",
        "src_port_range": (40000, 65000), "dst_port": 80,
        "proto": "TCP",
    },
    {
        "signature": None,
        "category": None,
        "severity": 3,
        "desc": "SMTP Email",
        "src_port_range": (40000, 65000), "dst_port": 587,
        "proto": "TCP",
    },
]


def create_alert_event(scenario, src_ip, dst_ip, timestamp):
    """Create a Suricata-style alert event."""
    return {
        "status": "OPEN",
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": scenario.get("src_port", random.randint(40000, 65000)),
        "dest_ip": dst_ip,
        "dest_port": scenario["dst_port"],
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": random.randint(2000000, 2999999),
            "rev": random.randint(1, 5),
            "signature": scenario["signature"],
            "category": scenario["category"],
            "severity": scenario["severity"],
        },
        "source": "suricata",
    }


def create_benign_event(scenario, src_ip, dst_ip, timestamp):
    """Create a benign flow event disguised as a low-severity Suricata alert."""
    return {
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": random.randint(*scenario["src_port_range"]),
        "dest_ip": dst_ip,
        "dest_port": scenario["dst_port"],
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": random.randint(2000000, 2999999),
            "rev": 1,
            "signature": None,
            "category": None,
            "severity": 3,
        },
        "source": "suricata",
    }


def main():
    print("=" * 50)
    print("  Enterprise Security — Demo Traffic Generator")
    print("=" * 50)

    producer = KafkaProducer(
        bootstrap_servers='localhost:29092',
        value_serializer=lambda v: json.dumps(v).encode('utf-8'),
        key_serializer=lambda k: k.encode('utf-8'),
    )

    now = datetime.utcnow()
    events = []

    # ── Generate benign background traffic (last 60 seconds) ──
    print("[*] Generating benign background traffic...")
    for i in range(60):
        ts = now - timedelta(seconds=random.randint(0, 60))
        scenario = random.choice(BENIGN_SCENARIOS)
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = random.choice(EXTERNAL_BENIGN)
        events.append(create_benign_event(scenario, src_ip, dst_ip, ts))

    # ── Generate attack events (sprinkled in last 60 seconds) ──
    print("[*] Generating attack events...")
    for scenario in ATTACK_SCENARIOS:
        count = random.randint(1, 3)
        for _ in range(count):
            ts = now - timedelta(seconds=random.randint(0, 60))
            src_ip = random.choice(EXTERNAL_MALICIOUS)
            dst_ip = random.choice(INTERNAL_IPS)
            events.append(create_alert_event(scenario, src_ip, dst_ip, ts))

    # ── Inject one high-profile Trickbot attack (most recent) ──
    print("[*] Injecting high-profile Trickbot exfiltration...")
    trickbot = create_alert_event(ATTACK_SCENARIOS[0], "185.15.59.224", "10.0.1.15", now)
    events.append(trickbot)

    # ── Shuffle and send ──
    random.shuffle(events)
    total = len(events)
    print(f"[*] Sending {total} events to Kafka...")

    for i, event in enumerate(events):
        producer.send('raw-alerts', key=event["src_ip"], value=event)
        if (i + 1) % 10 == 0:
            print(f"    [{i+1}/{total}] events sent...")
            time.sleep(0.3)  # Small delay to let the pipeline process

    producer.flush()
    print(f"\n[✓] Successfully injected {total} events!")
    print("    - ~60 benign traffic events")
    print(f"    - ~{total - 61} attack events (7 different attack types)")
    print("    - 1 high-profile Trickbot exfiltration")
    print("\n    Check your Dashboard at http://localhost:5173/")
    print("=" * 50)


if __name__ == "__main__":
    main()
