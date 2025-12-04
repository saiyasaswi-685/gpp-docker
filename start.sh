#!/bin/sh
set -e

# Install the cron file (silently if already installed)
crontab /etc/cron.d/mycron || true
chmod 0644 /etc/cron.d/mycron

# Start cron daemon
cron

echo "Cron started. Logs: /var/log/cron.log"
echo "Starting uvicorn on 0.0.0.0:8080"

# Run uvicorn (foreground)
exec uvicorn app.api:app --host 0.0.0.0 --port 8080
