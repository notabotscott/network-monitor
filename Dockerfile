FROM python:3.12-slim

# Install nmap — python-nmap is a wrapper around the system binary
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY monitor/ ./monitor/

# Non-root user for defence-in-depth.
# NOTE: nmap -sS (SYN scan) requires CAP_NET_RAW.
#       Add --cap-add=NET_RAW to `docker run` and set MONITOR_NMAP_SUDO=true
#       if you need SYN scanning. TCP connect scan (-sT, the default when
#       not root) works fine without extra capabilities.
RUN useradd -m -u 1001 scanner && mkdir -p /data/state && chown scanner /data/state
USER scanner

# State directory for local backend — mount a volume here in production
VOLUME ["/data/state"]

ENV PYTHONUNBUFFERED=1 \
    MONITOR_RUN_MODE=job \
    MONITOR_STATE_BACKEND=local \
    MONITOR_STATE_LOCAL_DIR=/data/state \
    MONITOR_LOG_LEVEL=INFO

ENTRYPOINT ["python", "-m", "monitor.main"]
