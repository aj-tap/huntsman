"""A connector for scraping web pages."""
import requests
import json
import logging
from lxml import html
from typing import Dict, Any
from .base import ExternalServiceConnector

logger = logging.getLogger(__name__)

class ScrapingConnector(ExternalServiceConnector):
    """
    A generic connector for web scraping, driven by a configuration.

    This connector uses lxml for robust XPath support to extract data from
    web pages based on a service recipe.

    Parameters
    ----------
    service_recipe : dict
        A dictionary containing the configuration for the scraping service.
    """

    def __init__(self, service_recipe: Dict[str, Any]) -> None:
        super().__init__()
        self.recipe: Dict[str, Any] = service_recipe

    def _extract_data(self, html_content: str, xpaths: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract data from HTML content based on a dictionary of XPaths.

        Parameters
        ----------
        html_content : str
            The HTML content to extract data from.
        xpaths : dict
            A dictionary where keys are the names of the data fields and
            values are the XPath expressions or configuration dictionaries.

        Returns
        -------
        dict
            A dictionary containing the extracted data.
        """
        if not html_content:
            return {key: None for key in xpaths}

        tree = html.fromstring(html_content)
        extracted_data = {}
        for key, xpath_config in xpaths.items():
            if isinstance(xpath_config, str):
                xpath = xpath_config
                attribute = None
            else:
                xpath = xpath_config.get('xpath')
                attribute = xpath_config.get('attribute')

            if not xpath:
                extracted_data[key] = None
                continue

            try:
                elements = tree.xpath(xpath)
                if elements:
                    if attribute:
                        extracted_data[key] = elements[0] if isinstance(elements[0], str) else elements[0].get(attribute)
                    else:
                        extracted_data[key] = ' '.join(
                            str(e).strip() if isinstance(e, str) else e.text_content().strip()
                            for e in elements
                        ).strip()
                else:
                    extracted_data[key] = None
            except Exception as e:
                logger.error(f"Error processing XPath for key '{key}': {e}")
                extracted_data[key] = None

        return extracted_data

    def fetch_and_store(self, identifier: str, identifier_type: str, task_db_id: str) -> Dict[str, Any]:
        """
        Fetch a web page, scrape it, and store the extracted data.

        Parameters
        ----------
        identifier : str
            The identifier to be used in the URL path.
        identifier_type : str
            The type of the identifier, used to select the correct endpoint recipe.
        task_db_id : str
            The database ID of the task associated with this operation.

        Returns
        -------
        dict
            A dictionary containing a reference to the stored data.

        Raises
        ------
        ValueError
            If the identifier type is not supported by the service.
        requests.exceptions.RequestException
            If the web scraping request fails.
        """
        endpoint_recipe = self.recipe["endpoints"].get(identifier_type)
        if not endpoint_recipe:
            raise ValueError(f"Identifier type '{identifier_type}' is not supported by this scraping service.")

        url = self.recipe["base_url"] + endpoint_recipe["path_template"].format(identifier=identifier)
        db_pool = endpoint_recipe["db_pool"]

        try:
            logger.info(f"Scraping URL: {url}")
            headers = {'User-Agent': 'HuntsmanBot/1.0'}
            response = self.session.get(url, timeout=20, headers=headers)
            response.raise_for_status()
            html_content = response.text
        except requests.exceptions.RequestException as e:
            logger.error(f"Scraping request failed: {e}")
            raise

        scraped_data = self._extract_data(html_content, endpoint_recipe["data_to_extract"])
        scraped_data['source_url'] = url
        scraped_data['task_id'] = task_db_id

        logger.debug(f"Extracted data: {scraped_data}")

        json_data_to_store = json.dumps(scraped_data, indent=2)
        self.db_client.load_data_to_branch(
            pool_id_or_name=db_pool,
            branch_name='main',
            data=json_data_to_store
        )
        return {"pool": db_pool}
