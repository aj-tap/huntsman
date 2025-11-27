"""Django models for the Huntsman API."""
import uuid
import os
import yaml
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from typing import Dict, Any
from django.conf import settings
from api.config import refresh_configuration

class AnalysisTask(models.Model):
    """Represents a single analysis task and its state."""

    class Status(models.TextChoices):
        """Status choices for an AnalysisTask."""

        PENDING = 'PENDING', 'Pending'
        IN_PROGRESS = 'IN_PROGRESS', 'In Progress'
        SUCCESS = 'SUCCESS', 'Success'
        FAILURE = 'FAILURE', 'Failure'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    celery_task_id = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    service_name = models.CharField(max_length=100)
    identifier = models.CharField(max_length=255)
    identifier_type = models.CharField(max_length=50)
    result = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)

    def __str__(self) -> str:
        """
        Return a string representation of the task.

        Returns
        -------
        str
            A string representation of the task.
        """
        return f"Task {self.id} ({self.service_name} - {self.identifier})"

class ConfigFile(models.Model):
    """Represents a generic configuration file (Recipes, Patterns)."""

    name = models.CharField(max_length=100, unique=True, help_text="Friendly name")
    path = models.CharField(max_length=500, unique=True, help_text="Absolute path to the file on disk")
    content = models.TextField(help_text="YAML content")
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Save the model instance and write the content to disk."""
        try:
            yaml.safe_load(self.content)
        except Exception:
            pass 

        try:
            directory = os.path.dirname(self.path)
            if not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
            with open(self.path, 'w') as f:
                f.write(self.content)
        except Exception as e:
            print(f"CRITICAL ERROR: Failed to write config file to disk: {e}")
            raise e
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        """
        Return a string representation of the config file.

        Returns
        -------
        str
            A string representation of the config file.
        """
        return self.name

@receiver(post_save, sender=ConfigFile)
def clear_config_cache(sender: Any, instance: Any, **kwargs: Any) -> None:
    """Clear the configuration cache when a ConfigFile is saved."""
    refresh_configuration()

class Rule(models.Model):
    """
    Represents a detection Rule.

    Uses 'rule_id' (from YAML) as the unique identifier for synchronization.
    """

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    rule_id = models.CharField(max_length=255, unique=True, help_text="Unique ID from the YAML content", null=True, blank=True)
    name = models.CharField(max_length=255, help_text="Filename (e.g., detect-dns.yaml)")
    title = models.CharField(max_length=255, blank=True, null=True)
    author = models.CharField(max_length=100, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    content = models.TextField(help_text="Rule YAML content")
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Save the model instance and write the content to disk."""
        try:
            data = yaml.safe_load(self.content)
            if isinstance(data, dict):
                self.title = data.get('title', self.title)
                self.author = data.get('author', self.author)
                self.description = data.get('description', self.description)            
                extracted_id = data.get('id')
                if extracted_id:
                    self.rule_id = str(extracted_id)
        except Exception:
            pass

        rules_dir = settings.CORRELATION_RULES_PATH
        if rules_dir:
            try:
                if not os.path.exists(rules_dir):
                    os.makedirs(rules_dir, exist_ok=True)
                
                file_path = os.path.join(rules_dir, self.name)
                with open(file_path, 'w') as f:
                    f.write(self.content)
            except Exception as e:
                print(f"CRITICAL ERROR: Failed to write rule to disk: {e}")
                raise e

        super().save(*args, **kwargs)

    def __str__(self) -> str:
        """
        Return a string representation of the rule.

        Returns
        -------
        str
            A string representation of the rule.
        """
        return self.title or self.name
