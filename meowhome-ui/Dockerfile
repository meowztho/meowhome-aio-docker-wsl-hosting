FROM docker:27-cli AS dockercli

FROM python:3.12-slim
WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# openssl is used by the host-side meowftp helper invoked through the UI.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates openssl \
  && rm -rf /var/lib/apt/lists/*

# Ship Docker CLI + Compose v2 from the same upstream image. Keep a
# docker-compose alias for compatibility with older helper code.
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/bin/docker-compose

RUN pip install --no-cache-dir \
    fastapi==0.115.6 \
    uvicorn==0.32.1 \
    jinja2==3.1.4 \
    python-multipart==0.0.12 \
    docker==7.1.0

COPY app /app/app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
