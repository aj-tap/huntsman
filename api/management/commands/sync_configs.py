"""A Django management command to synchronize configuration files."""
import os
import yaml
from django.core.management.base import BaseCommand
from typing import Dict, Any
from django.conf import settings
from api.models import ConfigFile, Rule

class Command(BaseCommand):
    """
    Synchronize configuration files and rules with the database.

    This command scans for local configuration files (recipes, patterns) and
    correlation rules, and updates the database to reflect the contents of
    these files.
    """

    help = "Synchronizes configuration files and rules with the database."

    def handle(self, *args: Any, **options: Any) -> None:
        """Run the command."""
        self.sync_general_configs()
        self.stdout.write(self.style.SUCCESS("\nAll configurations synced successfully."))

    def sync_general_configs(self) -> None:
        """Synchronize generic ConfigFiles such as Recipes and IOC Patterns."""
        configs = {
            'API Recipes': getattr(settings, 'API_RECIPES_PATH', None),
            'Scraping Recipes': getattr(settings, 'SCRAPING_RECIPES_PATH', None),
            'Internal Services Recipes': getattr(settings, 'INTERNAL_SERVICES_RECIPES_PATH', None),
            'RSS Recipes': getattr(settings, 'RSS_RECIPES_PATH', None),
            'IOC Patterns': getattr(settings, 'IOC_PATTERNS_PATH', None),
            'Predefined Queries': getattr(settings, 'PREDEFINED_QUERIES_PATH', None),
        }

        for name, path in configs.items():
            if not path or not os.path.exists(path):
                continue
            
            try:
                with open(path, 'r') as f:
                    content = f.read()
                ConfigFile.objects.update_or_create(
                    path=path,
                    defaults={'name': name, 'content': content}
                )
                self.stdout.write(self.style.SUCCESS(f"Synced config: {name}"))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Failed to sync {name}: {e}"))
