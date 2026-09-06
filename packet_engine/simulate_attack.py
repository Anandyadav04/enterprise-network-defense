import json
import time
from kafka import KafkaProducer

def simulate_alert():
    print("[*] Generating high-severity Suricata alert...")
    producer = KafkaProducer(
        bootstrap_servers='localhost:29092',
        value_serializer=lambda v: json.dumps(v).encode('utf-8'),
        key_serializer=lambda k: k.encode('utf-8')
    )
    
    alert = {
        "timestamp": "2026-08-29T12:25:00.000000+0000",
        "event_type": "alert",
        "src_ip": "185.15.59.224", # Known bad IP
        "src_port": 4444,
        "dest_ip": "10.0.0.5",
        "dest_port": 443,
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2028751,
            "rev": 2,
            "signature": "ET MALWARE Win32/Trickbot Data Exfiltration",
            "category": "A Network Trojan was detected",
            "severity": 1
        },
        "source": "suricata"
    }
    
    producer.send('raw-alerts', key=alert["src_ip"], value=alert)
    producer.flush()
    print("[-] Alert injected into Kafka 'raw-alerts' topic.")

if __name__ == "__main__":
    print("========================================")
    print("   Initiating Threat Simulation...      ")
    print("========================================")
    simulate_alert()
    print("========================================")
    print(" Simulation Complete. Check Kibana!     ")
    print("========================================")

