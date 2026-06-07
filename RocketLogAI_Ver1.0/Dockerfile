# RocketLogAI - AI-Powered Syslog Security Analyzer (v1.0-beta)
# Docker image for easy deployment

FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r rocketlogai && useradd -r -g rocketlogai rocketlogai

WORKDIR /app

# Copy dependency files first (better layer caching)
COPY pyproject.toml ./
COPY requirements.txt* ./

# Install the package with web extras (FastAPI, uvicorn, etc.)
# Note: bcrypt is included for secure local password storage (no more plaintext admin creds)
RUN pip install --no-cache-dir -U pip setuptools wheel && \
    pip install --no-cache-dir -e ".[web]"

# Copy the application code
COPY logsentinel/ ./logsentinel/
COPY templates/ ./templates/
COPY example-config.yaml ./

# Create data directory with proper permissions
RUN mkdir -p /app/data && chown -R rocketlogai:rocketlogai /app

# Switch to non-root user
USER rocketlogai

# Expose default ports
# 8787 - Web UI (configurable)
# 5140  - Syslog (UDP/TCP) - note: may require --privileged or port mapping for low ports
EXPOSE 8787 5140/udp 5140/tcp

# Default command: run with web UI
# Users can override: docker run ... logsentinel run
# Or for web only: logsentinel web
ENTRYPOINT ["logsentinel"]
CMD ["run", "--web"]