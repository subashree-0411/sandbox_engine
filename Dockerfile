FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pool_manager.py .
COPY behavioral_engine.py .
COPY sandbox_api.py .

EXPOSE 8001

CMD ["uvicorn", "sandbox_api:app", "--host", "0.0.0.0", "--port", "8001"]
