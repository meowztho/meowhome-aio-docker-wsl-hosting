FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 apache2-utils ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN a2enmod rewrite headers ssl http2 proxy proxy_http proxy_wstunnel proxy_fcgi setenvif
RUN mkdir -p /etc/apache2/snippets

RUN { \
  echo "ServerName localhost"; \
  echo ""; \
  echo "<Directory /var/www>"; \
  echo "  AllowOverride All"; \
  echo "  Require all granted"; \
  echo "</Directory>"; \
  echo ""; \
  echo "Protocols h2 http/1.1"; \
} > /etc/apache2/conf-enabled/00-global.conf

EXPOSE 80 443
CMD ["apachectl","-D","FOREGROUND"]
