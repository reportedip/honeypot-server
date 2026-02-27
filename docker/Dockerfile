FROM php:8.2-fpm-alpine

RUN apk add --no-cache nginx sqlite-dev \
    && docker-php-ext-install pdo_sqlite

COPY docker/nginx.conf /etc/nginx/http.d/default.conf
COPY docker/php-fpm.conf /usr/local/etc/php-fpm.d/zz-custom.conf

COPY . /var/www/honeypot
WORKDIR /var/www/honeypot

RUN mkdir -p data/cache \
    && chown -R www-data:www-data data/ \
    && chmod -R 775 data/

EXPOSE 80
CMD ["sh", "-c", "php-fpm -D && nginx -g 'daemon off;'"]
