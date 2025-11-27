"""A connector for fetching and processing RSS feeds."""
import logging
import json
import time
import random
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional
import feedparser
import httpx
from bs4 import BeautifulSoup
from .base import ExternalServiceConnector
from ..db.superdb_client import SuperDBClient

logger = logging.getLogger(__name__)

class RSSConnector(ExternalServiceConnector):
    """
    A connector for fetching and processing data from RSS feeds.

    This connector fetches entries from an RSS feed, scrapes the full text of
    new articles, and stores the enriched data in a SuperDB pool.

    Parameters
    ----------
    service_recipe : dict
        A dictionary containing the configuration for the RSS feed.
    """

    _USER_AGENT: str = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    _TIMEOUT: float = 15.0
    _MAX_WORKERS: int = 5
    _TEXT_LIMIT: int = 100000
    _DELAY_MIN: float = 1.0
    _DELAY_MAX: float = 3.0

    def __init__(self, service_recipe: Dict[str, Any]) -> None:
        super().__init__()
        self.recipe: Dict[str, Any] = service_recipe
        self.db_client: SuperDBClient = SuperDBClient()

    def fetch_and_store(self, identifier: str, identifier_type: str, task_db_id: str) -> Dict[str, Any]:
        """
        Fetch new entries from an RSS feed, enrich them, and store them.

        Parameters
        ----------
        identifier : str
            The identifier for the fetch operation (not used for RSS feeds).
        identifier_type : str
            The type of the identifier (not used for RSS feeds).
        task_db_id : str
            The database ID of the task associated with this operation.

        Returns
        -------
        dict
            A dictionary with the result of the operation.

        Raises
        ------
        ValueError
            If the 'url' or 'db_pool' is not defined in the recipe.
        """
        feed_url = self.recipe.get("url")
        db_pool = self.recipe.get("db_pool")

        if not feed_url or not db_pool:
            raise ValueError("RSS feed 'url' and 'db_pool' must be defined in the recipe.")

        logger.info(f"Fetching RSS feed from: {feed_url}")
        
        entries = self._fetch_feed_data(feed_url)
        if not entries:
            return {"pool": db_pool, "message": "Feed is empty or could not be parsed.", "entries_processed": 0}

        new_entries = self._filter_new_entries(entries, db_pool)
        if not new_entries:
            logger.info("No new articles to process.")
            return {"pool": db_pool, "message": "No new articles found.", "entries_processed": 0}

        logger.info(f"Processing {len(new_entries)} new articles...")
        enriched_entries = self._process_entries_concurrently(new_entries, task_db_id, feed_url)

        if not enriched_entries:
            logger.info("No new entries could be processed successfully.")
            return {"pool": db_pool, "entries_processed": 0}

        self._bulk_save(enriched_entries, db_pool)

        return {"pool": db_pool, "entries_processed": len(enriched_entries)}

    def _fetch_feed_data(self, feed_url: str) -> List[Dict[str, Any]]:
        """
        Fetch and parse the data from an RSS feed.

        Parameters
        ----------
        feed_url : str
            The URL of the RSS feed.

        Returns
        -------
        list of dict
            A list of entries from the feed.

        Raises
        ------
        Exception
            If the feed cannot be parsed.
        """
        feed = feedparser.parse(feed_url)
        if feed.bozo:
            if not feed.entries:
                logger.error(f"Failed to parse RSS feed. Error: {feed.get('bozo_exception', 'Unknown error')}")
                raise Exception(f"Failed to parse RSS feed.")
        return feed.entries

    def _filter_new_entries(self, entries: List[Dict[str, Any]], db_pool: str) -> List[Dict[str, Any]]:
        """
        Filter out entries that already exist in the database.

        Parameters
        ----------
        entries : list of dict
            A list of entries from the RSS feed.
        db_pool : str
            The SuperDB pool where the entries are stored.

        Returns
        -------
        list of dict
            A list of new entries that are not yet in the database.
        """
        entry_ids = {entry.get("id", entry.get("link")) for entry in entries}
        entry_ids.discard(None)

        if not entry_ids:
            return []

        id_conditions = " or ".join([f"id == '{eid}'" for eid in entry_ids])
        existence_query = f"from '{db_pool}' | {id_conditions} | select id"
        
        logger.debug(f"Checking for existing entries with query: {existence_query}")
        existing_results = self.db_client.execute_query(query=existence_query, pool=db_pool)

        existing_ids = set()
        if existing_results:
            existing_ids = {result['id'] for result in existing_results if 'id' in result}

        return [
            entry for entry in entries
            if entry.get("id", entry.get("link")) not in existing_ids
        ]

    def _process_entries_concurrently(self, entries: List[Dict[str, Any]], task_db_id: str, feed_source_name: str) -> List[Dict[str, Any]]:
        """
        Process and enrich a list of entries concurrently.

        Parameters
        ----------
        entries : list of dict
            A list of entries to process.
        task_db_id : str
            The database ID of the task.
        feed_source_name : str
            The name of the feed source.

        Returns
        -------
        list of dict
            A list of enriched entries.
        """
        enriched_entries = []
        feed_name = self.recipe.get("name", feed_source_name)
        
        with ThreadPoolExecutor(max_workers=self._MAX_WORKERS) as executor:
            future_to_entry = {
                executor.submit(self._enrich_entry, entry, task_db_id, feed_name): entry 
                for entry in entries
            }
            
            for future in as_completed(future_to_entry):
                try:
                    result = future.result()
                    if result:
                        enriched_entries.append(result)
                except Exception as e:
                    logger.error(f"Error processing entry in thread: {e}")
        
        return enriched_entries

    def _enrich_entry(self, entry: Dict[str, Any], task_db_id: str, feed_name: str) -> Optional[Dict[str, Any]]:
        """
        Enrich a single entry by scraping its full text.

        Parameters
        ----------
        entry : dict
            The entry to enrich.
        task_db_id : str
            The database ID of the task.
        feed_name : str
            The name of the feed.

        Returns
        -------
        dict, optional
            The enriched entry, or None if an error occurred.
        """
        article_url = entry.get("link")
        entry_id = entry.get("id", article_url)
        
        if not article_url:
            return None

        try:
            time.sleep(random.uniform(self._DELAY_MIN, self._DELAY_MAX))
            
            logger.debug(f"Scraping new article: {article_url}")
            with httpx.Client(headers={'User-Agent': self._USER_AGENT}, follow_redirects=True, timeout=self._TIMEOUT) as client:
                response = client.get(article_url)
                response.raise_for_status()

            soup = BeautifulSoup(response.content, 'html.parser')
            
            for tag in soup(['script', 'style', 'noscript']):
                tag.decompose()

            raw_text = soup.get_text(separator=' ', strip=True)
            
            clean_text = re.sub(r'\s+', ' ', raw_text).strip()

            if not clean_text:
                clean_text = entry.get("summary", "") or entry.get("title", "")
                clean_text = re.sub(r'\s+', ' ', clean_text).strip()

            return {
                "task_id": task_db_id,
                "feed_source": feed_name,
                "title": entry.get("title"),
                "link": article_url,
                "summary": entry.get("summary"),
                "published": entry.get("published"),
                "id": entry_id,
                "full_text": clean_text[:self._TEXT_LIMIT],
            }
        except Exception as e:
            logger.warning(f"Skipping article {article_url} due to error: {e}")
            return None

    def _bulk_save(self, data: List[Dict[str, Any]], db_pool: str) -> None:
        """
        Save a list of enriched entries to SuperDB in bulk.

        Parameters
        ----------
        data : list of dict
            The data to be saved.
        db_pool : str
            The SuperDB pool to save the data to.
        """
        ndjson_payload = "\n".join([json.dumps(doc) for doc in data])
        self.db_client.load_data_to_branch(
            pool_id_or_name=db_pool,
            branch_name='main',
            data=ndjson_payload
        )
