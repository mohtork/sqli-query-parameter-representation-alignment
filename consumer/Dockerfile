FROM python:3.11-slim

WORKDIR /app

# System deps (slim image lacks build tools needed by some wheels)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (better Docker layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code (recursive copy picks up detectors/ subdirectory)
COPY . .

# Models are mounted at runtime via volume, not baked into image
ENV MODELS_DIR=/app/models

CMD ["python", "-u", "main.py"]