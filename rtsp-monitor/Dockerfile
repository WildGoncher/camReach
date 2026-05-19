FROM python:3.13-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ffmpeg \
        curl \
        && \
    rm -rf /var/lib/apt/lists/*

# Создаём пользователя ДО того как делаем что-либо с файлами
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Создаём папки и сразу отдаём их appuser
RUN mkdir -p /app/data /app/logs && \
    chown -R appuser:appuser /app/data /app/logs

#
# USER appuser  # временно, до решения проблемы с volumes на Windows
#
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--timeout-keep-alive", "75", "--log-level", "info"]
