# ── Build context: repo root (required for /ml/ directory access) ─────────────
# Build with: docker compose (context: .) dockerfile: sensor/Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (better layer caching)
COPY sensor/requirements.txt ./sensor/requirements.txt
RUN pip install --no-cache-dir -r ./sensor/requirements.txt

# Copy sensor source and ML model files preserving relative path structure
COPY sensor/ ./sensor/
COPY ml/ ./ml/

# sensor.py resolves model path via: os.path.join(SENSOR_DIR, "..", "ml", "model")
# This requires WORKDIR to be /app/sensor so the relative path resolves correctly
WORKDIR /app/sensor

CMD ["python", "sensor.py", "--mode", "simulate"]
