FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir requests python-dotenv urllib3
COPY DNSUpdatecloudflare.py /app/DNSUpdatecloudflare.py
COPY run.sh /run.sh
RUN chmod +x /run.sh
ENTRYPOINT ["/run.sh"]
