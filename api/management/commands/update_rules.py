"""A Django management command to update correlation rules from GitHub."""
from django.core.management.base import BaseCommand
from typing import Dict, Any
from api.utils.rule_management import fetch_rules_from_github

class Command(BaseCommand):
    """
    Download the latest correlation rules from GitHub and sync to the database.

    This command fetches the latest correlation rules from the GitHub repository
    and updates the local database to match.
    """

    help = "Downloads the latest correlation rules from the GitHub repo and syncs to DB."

    def handle(self, *args: Any, **options: Any) -> None:
        """Run the command."""
        self.stdout.write("Starting rule update...")
        try:
            stats = fetch_rules_from_github()
            
            self.stdout.write(self.style.SUCCESS("--- Rule Update Complete ---"))
            self.stdout.write(f"Downloaded: {stats['downloaded']}")
            self.stdout.write(f"Skipped: {stats['skipped']}")
            
            if stats['errors']:
                self.stdout.write(self.style.WARNING("Errors encountered:"))
                for err in stats['errors']:
                    self.stdout.write(self.style.ERROR(f"  - {err}"))
                    
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"Update failed: {e}"))
