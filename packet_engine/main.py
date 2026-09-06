import os
import time
import logging
from kafka import KafkaProducer

from suricata.eve_reader import EveReader

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("PacketEngine")

def wait_for_kafka(bootstrap_servers):
    """Wait for Kafka to become available before starting."""
    logger.info(f"Connecting to Kafka at {bootstrap_servers}...")
    while True:
        try:
            producer = KafkaProducer(
                bootstrap_servers=bootstrap_servers,
                value_serializer=lambda v: v, # eve_reader serializes to bytes internally
                key_serializer=lambda k: k # eve_reader serializes to bytes internally
            )
            logger.info("Successfully connected to Kafka!")
            return producer
        except Exception as e:
            logger.warning(f"Kafka not ready yet ({e}). Retrying in 5 seconds...")
            time.sleep(5)

def main():
    logger.info("Initializing Packet Engine Main Process")
    
    bootstrap_servers = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092")
    producer = wait_for_kafka(bootstrap_servers)

    # Initialize and run the EveReader
    # It will block and tail the eve.json forever
    reader = EveReader(producer)
    logger.info("Starting EveReader to tail Suricata logs...")
    reader.run()

if __name__ == "__main__":
    main()
