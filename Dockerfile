FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY bifrost ./bifrost

RUN pip install --no-cache-dir . && \
    groupadd -g 1000 bifrost && \
    useradd -u 1000 -g 1000 -M -d /app bifrost

# Match itzg/minecraft-server's default UID/GID so files bifrost writes into
# /data are readable by the server without a chown pass.
USER 1000:1000

HEALTHCHECK --interval=60s --timeout=10s --start-period=60s --retries=3 \
    CMD ["python", "-m", "bifrost.healthcheck"]

ENTRYPOINT ["python", "-m", "bifrost"]
