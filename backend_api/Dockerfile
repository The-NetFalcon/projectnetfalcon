# backend_api/Dockerfile
# SERVICE 3: Central API & DB Controller — Flask + WebSockets + Kafka consumer

FROM python:3.11-slim

WORKDIR /app

# libpq-dev + gcc needed to build psycopg2 if a wheel isn't available
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=app.py \
    PYTHONUNBUFFERED=1

EXPOSE 5000

# eventlet worker required for Flask-SocketIO's WebSocket support
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "app:app"]
