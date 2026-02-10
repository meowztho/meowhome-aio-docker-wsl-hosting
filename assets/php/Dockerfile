FROM php:8.3-fpm-alpine

RUN apk add --no-cache \
    icu-dev libzip-dev oniguruma-dev zlib-dev \
    libpng-dev libjpeg-turbo-dev freetype-dev \
    bash curl git unzip

RUN docker-php-ext-configure gd --with-freetype --with-jpeg \
 && docker-php-ext-install -j$(nproc) intl pdo pdo_mysql zip opcache mbstring gd

WORKDIR /var/www
