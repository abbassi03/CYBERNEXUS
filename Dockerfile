FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CYBERNEXUS_DATABASE=/data/cybernexus.db
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --system cybernexus \
    && useradd --system --gid cybernexus --home-dir /app cybernexus \
    && mkdir -p /data /app/instance \
    && chown -R cybernexus:cybernexus /data /app
COPY --chown=cybernexus:cybernexus . .
USER cybernexus
EXPOSE 8000
CMD ["gunicorn", "--workers", "2", "--threads", "4", "--timeout", "60", "--bind", "0.0.0.0:8000", "wsgi:app"]
