FROM python:3.10-slim
WORKDIR /app

RUN pip install --no-cache-dir kafka-python redis

COPY . /app
ENV PYTHONPATH=/

# Run the stream processor
CMD ["python", "main.py"]
