"""A Django management command to update correlation rules from the local directory."""
from django.core.management.base import BaseCommand
from typing import Dict, Any
from api.utils.rule_management import sync_rules_from_local_dir

class Command(BaseCommand):
    """
    Synchronize correlation rules from the local directory to the database.

    This command reads all YAML rule files from the directory specified by the
    `CORRELATION_RULES_PATH` setting and syncs them to the database.
    """

    help = "Syncs correlation rules from the local directory to the database."

    def handle(self, *args: Any, **options: Any) -> None:
        """Run the command."""
        self.stdout.write("Starting rule synchronization...")
        try:
            stats = sync_rules_from_local_dir()
            
            self.stdout.write(self.style.SUCCESS("--- Rule Sync Complete ---"))
            self.stdout.write(f"Created: {stats['created']}")
            self.stdout.write(f"Updated: {stats['updated']}")
            
            if stats['errors']:
                self.stdout.write(self.style.WARNING("Errors encountered:"))
                for err in stats['errors']:
                    self.stdout.write(self.style.ERROR(f"  - {err}"))
                    
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"Update failed: {e}"))
