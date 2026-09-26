FROM python:3.10-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY traffic_gen.py .

CMD ["python", "-u", "traffic_gen.py"]
