#!/bin/bash

# Gunicorn startup script for Azure App Service
# This script will be used when deploying to Azure App Service with Linux

echo "Starting Gunicorn server..."

# Get the port from environment variable or default to 8000
PORT=${PORT:-8000}

# Start Gunicorn with proper configuration for Azure
exec gunicorn --bind 0.0.0.0:$PORT \
              --workers 1 \
              --timeout 120 \
              --keep-alive 2 \
              --max-requests 1000 \
              --max-requests-jitter 100 \
              --access-logfile - \
              --error-logfile - \
              --log-level info \
              app:app
