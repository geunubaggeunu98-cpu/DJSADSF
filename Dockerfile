FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8000 \
    APP_ENV=production \
    COOKIE_SECURE=1 \
    DATA_DIR=/data/nexus
WORKDIR /app
RUN groupadd --system nexus && useradd --system --gid nexus nexus && mkdir -p /data/nexus
COPY --chown=nexus:nexus app.py nz_nexus_logo.png ./
COPY --chown=nexus:nexus templates ./templates
COPY entrypoint.py /usr/local/bin/nexus-entrypoint.py
EXPOSE 8000
# Railway mounts persistent volumes as root. The entrypoint fixes ownership
# of the private data directory, then drops privileges before starting Nexus.
ENTRYPOINT ["python", "/usr/local/bin/nexus-entrypoint.py"]
CMD ["python", "app.py"]
