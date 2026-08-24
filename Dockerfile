FROM python:3.11-slim AS base

# --- system deps: nmap for discovery, git+ca-certs to fetch nuclei templates ---
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap git ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

# --- nuclei binary (static Go binary from upstream release) ---
ARG NUCLEI_VERSION=3.3.7
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) nuclei_arch=amd64 ;; \
        arm64) nuclei_arch=arm64 ;; \
        *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -sSL -o /tmp/nuclei.zip \
        "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${nuclei_arch}.zip"; \
    cd /tmp && unzip -q nuclei.zip nuclei && mv nuclei /usr/local/bin/nuclei && chmod +x /usr/local/bin/nuclei; \
    rm -rf /tmp/nuclei.zip

# --- vulnerability template set, baked in at build time (see app/scanner/nuclei_scan.py) ---
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates /opt/nuclei-templates \
    && rm -rf /opt/nuclei-templates/.git/hooks

# --- app ---
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY app ./app

# Non-root by default: nmap falls back to an unprivileged TCP connect scan
# automatically, which is fine for office-LAN use and is the safer default
# for anything with a network-facing admin login. Grant NET_RAW/NET_ADMIN
# via docker-compose (commented out there) if you want SYN scans + OS
# fingerprinting instead.
RUN useradd --create-home --uid 10001 netguard \
    && mkdir -p /app/data \
    && chown -R netguard:netguard /app /opt/nuclei-templates
USER netguard

ENV DATA_DIR=/app/data \
    NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates \
    PYTHONUNBUFFERED=1

EXPOSE 8000
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
