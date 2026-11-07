# Real deployment image (website + detection engine). Not tested in this environment: try it on a staging server first.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && playwright install --with-deps chromium
COPY . .
ENV HOST=0.0.0.0 PORT=8000 DRP_DB=/data/drp.db UPLOAD_DIR=/data/uploads ARTIFACT_DIR=/data/artifacts PLAYWRIGHT_NO_SANDBOX=true
VOLUME /data
EXPOSE 8000
CMD ["bash", "scripts/start_real.sh"]
