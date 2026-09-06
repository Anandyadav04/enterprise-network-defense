import logging
from processor import StreamProcessor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

if __name__ == "__main__":
    processor = StreamProcessor(bootstrap_servers="kafka:9092")
    processor.run()
