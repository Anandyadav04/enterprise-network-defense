FROM python:3.10-slim
WORKDIR /app

RUN pip install --no-cache-dir kafka-python numpy onnxruntime scikit-learn pandas

COPY . /app
ENV PYTHONPATH=/

# Run the AI Inference Service
CMD ["python", "main.py"]
