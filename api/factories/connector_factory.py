"""A factory for creating connector instances."""
import os
from typing import Union
from api.connectors.base import ExternalServiceConnector
from api.connectors.configurable_connector import ConfigurableConnector
from api.connectors.scraping_connector import ScrapingConnector
from api.connectors.internal_query_connector import InternalQueryConnector
from api.connectors.rss_connector import RSSConnector
from api.config import (
    load_api_recipes, 
    load_scraping_recipes, 
    load_internal_services_recipes,
    load_rss_recipes  
)

def get_connector(service_name: str) -> ExternalServiceConnector:
    """
    Create a connector instance based on the service name.

    This factory function determines the type of connector to create by
    checking the service name against the available API, scraping, internal
    query, and RSS recipes.

    Parameters
    ----------
    service_name : str
        The name of the service for which to create a connector.

    Returns
    -------
    ExternalServiceConnector
        An instance of the appropriate connector.

    Raises
    ------
    ValueError
        If the service name is not found in any of the recipe configurations,
        or if an API key is required but not found in the environment variables.
    """
    api_recipes = load_api_recipes()
    scraping_recipes = load_scraping_recipes()
    internal_services_recipes = load_internal_services_recipes() 
    rss_recipes = load_rss_recipes()
    service_name = service_name.lower()

    if service_name in api_recipes:
        service_recipe = api_recipes[service_name]
        api_key = None
        if "auth" in service_recipe:
            api_key_env_var = f"{service_name.upper()}_API_KEY"
            api_key = os.environ.get(api_key_env_var)
            if not api_key:
                raise ValueError(f"API key env var '{api_key_env_var}' not found.")
        return ConfigurableConnector(api_key=api_key, service_recipe=service_recipe)

    if service_name in scraping_recipes:
        service_recipe = scraping_recipes[service_name]
        return ScrapingConnector(service_recipe=service_recipe)

    if service_name in internal_services_recipes:
        service_recipe = internal_services_recipes[service_name]
        return InternalQueryConnector(service_recipe=service_recipe)

    if service_name in rss_recipes:
        service_recipe = rss_recipes[service_name]
        return RSSConnector(service_recipe=service_recipe)
        
    raise ValueError(f"Unknown service: '{service_name}'. Not found in any recipe configuration.")
