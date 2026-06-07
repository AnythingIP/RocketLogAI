# RocketLogAI - AI-Powered Syslog Security Analyzer (v1.3 - Daily Briefing edition)
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
# Note: bcrypt is included for secure local password storage.
# requests is included for optional online geo IP fallback (Maps page enrichment).
# cryptography for encrypted domain/Entra service secrets (Phase 4).
# open-interpreter for the powerful conversational AI Assistant / Operator (Phase 3).
RUN pip install --no-cache-dir -U pip setuptools wheel && \
    pip install --no-cache-dir -e ".[web]" && \
    pip install --no-cache-dir open-interpreter cryptography || true

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

# Healthcheck (simple)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:8787/ || exit 1

# Default command: run with web UI
# Users can override: docker run ... logsentinel run
# Or for web only: logsentinel web
ENTRYPOINT ["logsentinel"]
CMD ["run", "--web"]

# Recommended volumes:
#   - ./data:/app/data
#   - ./GeoLite2-City.mmdb:/app/GeoLite2-City.mmdb:ro   (for Maps)
#   - ./config.yaml:/app/config.yaml:ro                 (optional)