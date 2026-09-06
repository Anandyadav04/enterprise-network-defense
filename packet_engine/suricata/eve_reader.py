"""
suricata/eve_reader.py
───────────────────────
Reads Suricata's EVE JSON output (eve.json) and publishes
alerts to the Kafka `raw-alerts` topic.

Suricata produces structured JSON alerts in EVE format.
This reader tails the file and forwards each alert event.

Suricata must be configured with:
  outputs:
    - eve-log:
        enabled: yes
        filetype: regular
        filename: /var/log/suricata/eve.json
        types:
          - alert
          - dns
          - flow
          - http
"""

import json
import logging
import time
from pathlib import Path
from typing import Iterator

from kafka import KafkaProducer

logger = logging.getLogger(__name__)

EVE_LOG_PATH = "/var/log/suricata/eve.json"
KAFKA_TOPIC_RAW_ALERTS = "raw-alerts"


class EveReader:
    """
    Tails Suricata's eve.json and forwards alert events to Kafka.
    Supports both event_type='alert' and 'dns'/'flow' for metadata.
    """

    TRACKED_EVENT_TYPES = {"alert", "dns", "flow", "http"}

    def __init__(self, producer: KafkaProducer, eve_path: str = EVE_LOG_PATH):
        self.producer = producer
        self.eve_path = Path(eve_path)

    def tail(self) -> Iterator[dict]:
        """Tail eve.json continuously, yielding new JSON lines."""
        with open(self.eve_path, "r", encoding="utf-8") as fh:
            fh.seek(0, 2)  # Seek to end — only new events
            while True:
                line = fh.readline()
                if not line:
                    time.sleep(0.05)
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("Invalid JSON line in eve.json: %s", line[:80])

    def run(self) -> None:
        """Continuously tail eve.json and publish tracked events to Kafka."""
        logger.info("EveReader started — watching %s", self.eve_path)
        for event in self.tail():
            if event.get("event_type") in self.TRACKED_EVENT_TYPES:
                self._publish(event)

    def _publish(self, event: dict) -> None:
        """Enrich event with source tag and publish to Kafka."""
        event["source"] = "suricata"
        self.producer.send(
            KAFKA_TOPIC_RAW_ALERTS,
            key=event.get("src_ip", "unknown").encode(),
            value=json.dumps(event).encode(),
        )
