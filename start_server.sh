#!/bin/bash

LOG_DIR="logs"
LOG_FILE="$LOG_DIR/gunicorn.log"
ERROR_FILE="$LOG_DIR/gunicorn.err"

mkdir -p "$LOG_DIR"

echo "Starting Gunicorn..."
nohup gunicorn \
  --timeout 120 \
  --env DJANGO_SETTINGS_MODULE=ormproject.settings \
  --bind 0.0.0.0:8000 ormproject.wsgi:application \
  >> "$LOG_FILE" 2>> "$ERROR_FILE" &

echo "Gunicorn started. Logs: $LOG_FILE"
