"""A Django management command to set up SuperDB pools."""
import requests
from django.core.management.base import BaseCommand
from typing import Dict, Any
from api.config import load_all_recipes
from api.db.superdb_client import SuperDBClient

class Command(BaseCommand):
    """
    Scan all YAML recipes and create the defined SuperDB pools via the API.

    This command loads all the recipe files, extracts the `db_pool` names,
    and then attempts to create each one using the SuperDB client.
    """

    help = "Scans all YAML recipes and creates the defined SuperDB pools via API."

    def handle(self, *args: Any, **options: Any) -> None:
        """Run the command."""
        self.stdout.write("Starting pool setup...")
        
        all_recipes = load_all_recipes()
        if not all_recipes:
            self.stderr.write(self.style.ERROR("Could not load any recipes. Aborting."))
            return

        pool_names = set()
        for recipe_name, recipe_data in all_recipes.items():
            if "db_pool" in recipe_data:
                pool_names.add(recipe_data["db_pool"])

            if "endpoints" in recipe_data and isinstance(recipe_data["endpoints"], dict):
                for endpoint_name, endpoint_data in recipe_data["endpoints"].items():
                    if isinstance(endpoint_data, dict) and "db_pool" in endpoint_data:
                        pool_names.add(endpoint_data["db_pool"])
        
        if not pool_names:
            self.stdout.write("No 'db_pool' definitions found in any recipes.")
            return

        self.stdout.write(f"Found {len(pool_names)} unique pools to create: {pool_names}")

        client = SuperDBClient()
        success_count = 0
        fail_count = 0

        for pool_name in pool_names:
            self.stdout.write(f"  Attempting to create pool: '{pool_name}'...")
            try:
                result = client.create_pool(
                    name=pool_name,
                    layout_order='asc',
                    layout_keys=[['task_id']]
                )
                
                if result:
                    self.stdout.write(self.style.SUCCESS(f"Successfully created pool '{pool_name}' (ID: {result.get('id')})"))
                    success_count += 1
                else:
                    self.stderr.write(self.style.ERROR(f"Failed to create pool '{pool_name}'. Client returned None."))
                    fail_count += 1

            except requests.exceptions.RequestException as e:
                if e.response is not None and e.response.status_code == 409:
                    self.stdout.write(self.style.WARNING(f"Pool '{pool_name}' already exists. Skipping."))
                else:
                    self.stderr.write(self.style.ERROR(f"Failed to create pool '{pool_name}': {e}"))
                    fail_count += 1
            except Exception as e:
                self.stderr.write(self.style.ERROR(f"An unexpected error occurred for pool '{pool_name}': {e}"))
                fail_count += 1

        client.create_pool(
                    name='stixdata',
                    layout_order='asc',
                    layout_keys=[['task_id']]
                )        

        self.stdout.write("\n" + self.style.SUCCESS("--- Setup Complete ---"))
        self.stdout.write(f"Successful creations: {success_count}")
        self.stdout.write(f"Failed/Skipped: {fail_count}")
