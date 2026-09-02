FROM python:3.11-slim

RUN apt-get update && apt-get install -y tshark && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN mkdir -p /app/evidence

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "-u", "capture.py"]