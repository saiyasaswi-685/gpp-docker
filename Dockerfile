# Stage 1: Builder
FROM python:3.11-slim AS builder
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /build
COPY requirements.txt .
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential ca-certificates curl && \
    python -m pip install --upgrade pip setuptools wheel && \
    python -m pip install --prefix=/install -r requirements.txt && \
    rm -rf /var/lib/apt/lists/*

# Stage 2: Runtime
FROM python:3.11-slim
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends cron tzdata ca-certificates && \
    ln -fs /usr/share/zoneinfo/UTC /etc/localtime && \
    echo "UTC" > /etc/timezone && \
    dpkg-reconfigure -f noninteractive tzdata || true && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local
COPY . /app

COPY cron/mycron /etc/cron.d/mycron
RUN chmod 0644 /etc/cron.d/mycron
RUN touch /var/log/cron.log && chmod 0666 /var/log/cron.log

COPY start.sh /start.sh
RUN chmod +x /start.sh

RUN mkdir -p /data /cron && chmod 0755 /data /cron

EXPOSE 8080

CMD ["/start.sh"]
