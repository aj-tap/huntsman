"""A utility for managing correlation rules."""
import os
import requests
import yaml
from typing import Dict, Any
from django.conf import settings
from api.models import Rule

GITHUB_API_URL = "https://api.github.com/repos/aj-tap/supersqlhunt/contents/_rules?ref=main"

def fetch_rules_from_github() -> Dict[str, Any]:
    """
    Fetch correlation rules from a GitHub repository and update the local database.

    This function fetches all YAML rule files from the specified GitHub repository,
    parses them, and then creates or updates the corresponding Rule objects in
    the local database.

    Returns
    -------
    dict
        A dictionary containing statistics about the fetch operation, including
        the number of rules downloaded, updated, created, skipped, and any errors
        that occurred.

    Raises
    ------
    Exception
        If the initial request to the GitHub API fails.
    """
    try:
        response = requests.get(GITHUB_API_URL, timeout=15)
        response.raise_for_status()
        files_data = response.json()
    except Exception as e:
        raise Exception(f"Failed to fetch file list from GitHub: {e}")

    stats: Dict[str, Any] = {
        "downloaded": 0,
        "updated": 0,
        "created": 0,
        "skipped": 0,
        "errors": []
    }

    for file_info in files_data:
        file_name = file_info.get('name')
        download_url = file_info.get('download_url')

        if not file_name or not download_url:
            continue
            
        if file_name.endswith(('.yml', '.yaml')):
            try:
                rule_res = requests.get(download_url, timeout=10)
                rule_res.raise_for_status()
                content = rule_res.text

                data = yaml.safe_load(content)
                if not isinstance(data, dict) or 'id' not in data:
                    stats['errors'].append(f"Skipped {file_name}: Missing 'id' field.")
                    continue
                
                rule_id = str(data['id'])

                _, created = Rule.objects.update_or_create(
                    rule_id=rule_id,
                    defaults={
                        'name': file_name,
                        'content': content
                    }
                )
                
                if created:
                    stats['created'] += 1
                else:
                    stats['updated'] += 1
                
                stats['downloaded'] += 1
                
            except Exception as e:
                stats['errors'].append(f"Error processing {file_name}: {str(e)}")
        else:
            stats['skipped'] += 1

    return stats
