FROM certbot/certbot:latest
RUN pip install --no-cache-dir certbot-dns-cloudflare
COPY run.sh /run.sh
RUN chmod +x /run.sh
ENTRYPOINT ["/run.sh"]
