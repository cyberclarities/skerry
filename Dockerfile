FROM python:3.12-alpine

WORKDIR /app

COPY requirements.txt .

# libffi is needed at runtime by cffi/cryptography (used via Authlib for
# OIDC). curl backs the docker-compose healthcheck. su-exec lets the
# entrypoint drop from root to the app user. Build-time deps (gcc, musl-dev,
# libffi-dev) are grouped under a virtual package and removed after pip
# install to keep the image lean.
RUN apk add --no-cache \
        libffi \
        curl \
        su-exec \
    && apk add --no-cache --virtual .build-deps \
        gcc \
        musl-dev \
        libffi-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

COPY . .

# The unprivileged user the app runs as. See docker-entrypoint.sh for why the
# container starts as root and how it stops being root before the app runs.
RUN addgroup -S -g 10001 skerry \
    && adduser -S -D -H -u 10001 -G skerry skerry \
    && mkdir -p /app/data \
    && chown -R skerry:skerry /app/data

EXPOSE 5000

ENTRYPOINT ["sh", "/app/docker-entrypoint.sh"]
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 1 --timeout 120 'run:app'"]
