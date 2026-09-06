import logging
from inference.classifier import InferenceService

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

if __name__ == "__main__":
    service = InferenceService()
    service.run()
