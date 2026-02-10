FROM docker:27-cli AS dockercli

FROM python:3.12-slim
WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Debian: docker-compose (v2 standalone) + openssl fuer meowftp hashing
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl openssl \
    docker-compose \
  && rm -rf /var/lib/apt/lists/*

# Docker CLI aus docker:cli image
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker

RUN pip install --no-cache-dir \
    fastapi==0.115.6 \
    uvicorn==0.32.1 \
    jinja2==3.1.4 \
    python-multipart==0.0.12 \
    docker==7.1.0

COPY app /app/app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
