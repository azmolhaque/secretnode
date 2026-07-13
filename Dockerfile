# ── SecretNode — container image ────────────────────────────────────────────
# Multi-arch friendly (works on linux/amd64 and linux/arm64, incl. Raspberry Pi 5).
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# System deps for lxml on slim base
RUN apt-get update \
 && apt-get install -y --no-install-recommends libxml2 libxslt1.1 curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install python deps first (better layer caching)
COPY requirements.txt .
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libxml2-dev libxslt1-dev \
 && pip install --no-cache-dir -r requirements.txt \
 && apt-get purge -y build-essential libxml2-dev libxslt1-dev \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

# App code
COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Run as a non-root user
RUN useradd --create-home --uid 10001 secretnode \
 && mkdir -p /app/backend/data \
 && chown -R secretnode:secretnode /app
USER secretnode

EXPOSE 8000
WORKDIR /app/backend

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost:8000/api/health || exit 1

# SECRETNODE_API_KEY must be provided at runtime (the app refuses to boot without it):
#   docker run -e SECRETNODE_API_KEY=$(openssl rand -hex 24) -e GEMINI_API_KEY=... -p 8000:8000 secretnode
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--loop", "uvloop"]
