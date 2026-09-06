FROM python:3.10-slim
WORKDIR /app

RUN pip install --no-cache-dir kafka-python redis requests

COPY . /app
ENV PYTHONPATH=/

# Placeholder entrypoint
CMD ["python", "-c", "import time, logging; logging.basicConfig(level=logging.INFO); logging.info('Threat Intel started'); time.sleep(86400)"]
