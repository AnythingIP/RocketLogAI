# RocketLogAI v2.0 — Production Docker image
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r rocketlogai && useradd -r -g rocketlogai rocketlogai

WORKDIR /app

# Full source before install (hatch needs package present)
COPY pyproject.toml ./
COPY requirements.txt* ./
COPY logsentinel/ ./logsentinel/
COPY templates/ ./templates/
COPY example-config.yaml ./

# Pin setuptools BEFORE open-interpreter: OI 0.4.x needs pkg_resources (gone in setuptools 82+)
# Install web + v2 + ai extras for full System Health / Operator support
RUN pip install --no-cache-dir -U pip wheel && \
    pip install --no-cache-dir "setuptools>=65,<81" && \
    pip install --no-cache-dir ".[web,v2,ai]" && \
    pip install --no-cache-dir cryptography

RUN mkdir -p /app/data && chown -R rocketlogai:rocketlogai /app

USER rocketlogai

EXPOSE 8787 5140/udp 5140/tcp

# Default is HTTPS-only on many lab installs; curl -k if TLS is on
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -fk https://localhost:8787/ || curl -f http://localhost:8787/ || exit 1

ENTRYPOINT ["logsentinel"]
CMD ["run", "--web"]
