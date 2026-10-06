FROM python:3.10-slim
WORKDIR /app

RUN pip install --no-cache-dir kafka-python requests

COPY . /app
ENV PYTHONPATH=/

CMD ["python", "-u", "mitigation/response_engine.py"]
