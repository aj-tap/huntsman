"""Celery configuration for the Huntsman project."""
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'huntsman.settings')

app = Celery('huntsman')

app.config_from_object('django.conf:settings', namespace='CELERY')

app.autodiscover_tasks()
