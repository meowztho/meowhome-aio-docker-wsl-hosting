FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    vsftpd db5.3-util openssl python3 \
    libpam-modules libpam-runtime \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 21
ENTRYPOINT ["/entrypoint.sh"]
