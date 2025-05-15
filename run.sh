#!/bin/bash

# Exit immediately if a command fails
set -e

# Start Celery Beat (for periodic tasks)
celery -A core beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler &

# Start Celery Flower (monitoring tool)
celery -A core.celery_app flower --basic_auth=admin:admin --port=5555 &

# Start Gunicorn (WSGI server for Django)
gunicorn core.wsgi:application --bind 0.0.0.0:8080 --workers 3
