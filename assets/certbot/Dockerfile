FROM docker:27-cli AS dockercli

FROM certbot/certbot:latest
RUN pip install --no-cache-dir certbot-dns-cloudflare
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY run.sh /run.sh
RUN chmod +x /run.sh
ENTRYPOINT ["/run.sh"]
