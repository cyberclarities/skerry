FROM python:3.12-alpine

WORKDIR /app

COPY requirements.txt .

# libffi is needed at runtime by cffi/cryptography (used via Authlib for
# OIDC). curl backs the docker-compose healthcheck. Build-time deps (gcc,
# musl-dev, libffi-dev) are grouped under a virtual package and removed
# after pip install to keep the image lean.
RUN apk add --no-cache \
        libffi \
        curl \
    && apk add --no-cache --virtual .build-deps \
        gcc \
        musl-dev \
        libffi-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

COPY . .

RUN mkdir -p /app/data

EXPOSE 5000

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 1 --timeout 120 'run:app'"]
