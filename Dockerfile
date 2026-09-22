FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# 非 root 运行；/data 存 SQLite，/files 为演示下载目录
RUN useradd --system --uid 10001 --no-create-home appuser \
    && mkdir -p /data /files \
    && chown -R appuser:appuser /data /files
USER appuser

ENV TOKEN_DB_PATH=/data/tokens.db \
    FILES_DIR=/files \
    TOKEN_DEFAULT_TTL=300 \
    TOKEN_MAX_TTL=3600

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
