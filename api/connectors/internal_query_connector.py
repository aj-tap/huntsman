"""A connector for internal queries."""
import json
from typing import Dict, Any
from .base import ExternalServiceConnector
from ..db.superdb_client import SuperDBClient

class InternalQueryConnector(ExternalServiceConnector):
    """
    A connector for executing internal queries against SuperDB.

    This connector is used for services that are defined by a query to be
    run against the local SuperDB instance, rather than an external API.

    Parameters
    ----------
    service_recipe : dict
        A dictionary containing the configuration for the internal query service.
    """

    def __init__(self, service_recipe: Dict[str, Any]) -> None:
        super().__init__()
        self.recipe: Dict[str, Any] = service_recipe

    def fetch_and_store(self, identifier: str, identifier_type: str, task_db_id: str) -> Dict[str, Any]:
        """
        Execute an internal query and return the results.

        This method constructs a query from a recipe, executes it against
        SuperDB, and returns the results directly, without storing them in a
        separate pool.

        Parameters
        ----------
        identifier : str
            The identifier to be used in the query.
        identifier_type : str
            The type of the identifier, used to select the correct query pattern.
        task_db_id : str
            The database ID of the task associated with this operation.

        Returns
        -------
        dict
            A dictionary containing the results of the query.

        Raises
        ------
        ValueError
            If the identifier type is not supported or if the query pattern
            is missing from the recipe.
        ConnectionError
            If the internal query execution fails.
        """
        endpoint_config = self.recipe.get("endpoints", {}).get(identifier_type)
        if not endpoint_config:
            raise ValueError(f"'{identifier_type}' is not a supported IOC type for the '{self.recipe.get('label')}' service.")

        query_pattern = endpoint_config.get("query_pattern")
        
        if not query_pattern:
            raise ValueError("Recipe for internal query is missing 'query_pattern'.")

        final_query = query_pattern.format(identifier=identifier)
        
        print(f"Executing internal query: {final_query}")
        
        query_client = SuperDBClient()
        query_results = query_client.execute_query(query=final_query)

        if query_results is None:
            raise ConnectionError("Internal query execution failed. Check SuperDB logs.")
            
        hits = len(query_results) if query_results else 0
        print(f"Internal query found {hits} hits for task {task_db_id}")

        return {
            "search_hits": hits, 
            "task_id": task_db_id,
            "data": query_results 
        }
