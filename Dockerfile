FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    "openenv-core>=0.2.1" \
    "fastapi>=0.104.0" \
    "uvicorn>=0.24.0" \
    "pydantic>=2.0.0" \
    "openai>=1.0.0"

COPY . .

ENV PYTHONUNBUFFERED=1
ENV PORT=7860
ENV ENABLE_WEB_INTERFACE=true

EXPOSE 7860

CMD ["python", "-m", "uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "7860"]
