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
        self.sync_correlation_rules()
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

    def sync_correlation_rules(self) -> None:
        """
        Scan the local rules directory and populate the Rule model.

        This method uses the 'id' field in the YAML file to prevent
        duplication.
        """
        rules_dir = getattr(settings, 'CORRELATION_RULES_PATH', None)
        if not rules_dir or not os.path.isdir(rules_dir):
            self.stdout.write(self.style.WARNING("Rules directory not found. Skipping rule sync."))
            return

        self.stdout.write(f"Scanning rules in {rules_dir}...")
        
        count = 0
        for filename in os.listdir(rules_dir):
            if not filename.endswith(('.yml', '.yaml')):
                continue

            file_path = os.path.join(rules_dir, filename)
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                try:
                    data = yaml.safe_load(content)
                    rule_id = data.get('id')
                except yaml.YAMLError:
                    self.stdout.write(self.style.ERROR(f"Invalid YAML in {filename}, skipping."))
                    continue

                if not rule_id:
                    self.stdout.write(self.style.WARNING(f"Rule {filename} missing 'id', skipping import."))
                    continue

                Rule.objects.update_or_create(
                    rule_id=str(rule_id),
                    defaults={
                        'name': filename,
                        'content': content,
                    }
                )
                count += 1
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Failed to process rule {filename}: {e}"))
        
        self.stdout.write(self.style.SUCCESS(f"Synced {count} rules from disk."))
