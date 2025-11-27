"""Configuration loading for the Huntsman API."""
import yaml
from functools import lru_cache
from django.conf import settings
from typing import Dict

def refresh_configuration() -> None:
    """
    Clear the cache for the YAML configuration loader.

    This function clears the lru_cache for the _load_yaml_config function,
    forcing it to re-read the configuration files from disk the next time
    they are accessed.

    """
    _load_yaml_config.cache_clear()
    print("Configuration cache cleared. Recipes reloaded.")

@lru_cache(maxsize=4)
def _load_yaml_config(file_path: str) -> Dict:
    """
    Load a YAML configuration file.

    Parameters
    ----------
    file_path : str
        The path to the YAML configuration file.

    Returns
    -------
    dict
        The configuration loaded from the YAML file. Returns an empty dictionary
        if the file is not found or if there is an error parsing the file.

    """
    try:
        with open(file_path, 'r') as f:
            config = yaml.safe_load(f)
            print(f"Successfully loaded config from {file_path}")
            return config or {}
    except FileNotFoundError:
        print(f"ERROR: Config file not found at {file_path}")
        return {}
    except yaml.YAMLError as e:
        print(f"ERROR: Failed to parse YAML file {file_path}: {e}")
        return {}

def load_api_recipes() -> Dict:
    """
    Load the API recipes from the YAML configuration file.

    Returns
    -------
    dict
        The API recipes.

    """
    return _load_yaml_config(settings.API_RECIPES_PATH)

def load_scraping_recipes() -> Dict:
    """
    Load the scraping recipes from the YAML configuration file.

    Returns
    -------
    dict
        The scraping recipes.

    """
    return _load_yaml_config(settings.SCRAPING_RECIPES_PATH)

def load_internal_services_recipes() -> Dict:
    """
    Load the internal services recipes from the YAML configuration file.

    Returns
    -------
    dict
        The internal services recipes.

    """
    return _load_yaml_config(settings.INTERNAL_SERVICES_RECIPES_PATH)

def load_rss_recipes() -> Dict:
    """
    Load the RSS recipes from the YAML configuration file.

    Returns
    -------
    dict
        The RSS recipes.

    """
    return _load_yaml_config(settings.RSS_RECIPES_PATH)

def load_ioc_patterns() -> Dict:
    """
    Load the IOC patterns from the YAML configuration file.

    Returns
    -------
    dict
        The IOC patterns.

    """
    return _load_yaml_config(settings.IOC_PATTERNS_PATH)

def load_predefined_queries() -> Dict:
    """
    Load the predefined queries from the YAML configuration file.

    Returns
    -------
    dict
        The predefined queries.

    """
    path = getattr(settings, 'PREDEFINED_QUERIES_PATH', 'queries.yaml')
    return _load_yaml_config(path)

def load_all_recipes() -> Dict:
    """
    Load all recipes from the YAML configuration files.

    Returns
    -------
    dict
        A dictionary containing all the recipes.

    """
    api_recipes = load_api_recipes()
    scraping_recipes = load_scraping_recipes()
    internal_recipes = load_internal_services_recipes()
    rss_recipes = load_rss_recipes()

    combined_recipes = {**api_recipes, **scraping_recipes, **internal_recipes, **rss_recipes}

    return combined_recipes
