FROM python:3.12-slim

WORKDIR /app

# Install openssh-client so container can connect to NAS via SSH
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client curl \
    && rm -rf /var/lib/apt/lists/*

COPY nas-sentinel /app/nas-sentinel

EXPOSE 8088

# Default to loopback. Override only if you intentionally publish with API_TOKEN set.
ENV MONITOR_HOST=127.0.0.1
ENV MONITOR_PORT=8088

VOLUME ["/app/nas-sentinel/data"]

WORKDIR /app/nas-sentinel
CMD ["python", "server.py"]
