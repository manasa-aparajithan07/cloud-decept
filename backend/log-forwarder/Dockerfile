# Log Forwarder - Reads cowrie.json and forwards to Event Collector
FROM python:3.11-slim-bookworm

WORKDIR /app

# Install runtime dependencies including geoip2
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Download MaxMind GeoLite2 Country database
RUN mkdir -p /usr/share/GeoIP && \
    wget -q "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb" -O /usr/share/GeoIP/GeoLite2-Country.mmdb && \
    chmod 644 /usr/share/GeoIP/GeoLite2-Country.mmdb

# Install Python dependencies
RUN pip install --no-cache-dir \
    httpx==0.27.0 \
    redis==5.0.1 \
    pyyaml==6.0.1 \
    geoip2==4.8.0

# Copy forwarder script
COPY --chown=root:root backend/log-forwarder/forwarder.py /app/forwarder.py

USER root

EXPOSE 8080

ENTRYPOINT ["python", "/app/forwarder.py"]