# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: build dependencies in a venv
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

# Install OS build dependencies (Pillow needs libjpeg/zlib)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libjpeg-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Create an isolated venv so the final stage stays clean
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: lean runtime image
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

WORKDIR /app

# Runtime OS libraries only
RUN apt-get update && apt-get install -y --no-install-recommends \
        libjpeg62-turbo \
        zlib1g \
    && rm -rf /var/lib/apt/lists/*

# Copy venv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy project source
COPY . .

# Create directories that Django will need at runtime
RUN mkdir -p /app/media /app/staticfiles /app/data

# Make entrypoint executable
RUN chmod +x /app/scripts/entrypoint.sh

# Default port for gunicorn
EXPOSE 8000

ENTRYPOINT ["/app/scripts/entrypoint.sh"]
