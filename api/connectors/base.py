"""Base classes for connectors."""
from abc import ABC, abstractmethod
import requests
from typing import Dict, Optional
from api.db.superdb_client import SuperDBClient

class ExternalServiceConnector(ABC):
    """
    Abstract Base Class for connectors to external services.

    This class provides a common interface for all connectors, including
    session management and a SuperDB client for data storage.

    Parameters
    ----------
    api_key : str, optional
        The API key for the external service, if required.
    """

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key: Optional[str] = api_key
        self.session: requests.Session = requests.Session()
        self.db_client: SuperDBClient = SuperDBClient()

    @abstractmethod
    def fetch_and_store(self, identifier: str, identifier_type: str, task_db_id: str) -> Dict:
        """
        Fetch data from the external service and store it.

        This is the main method for a connector and must be implemented by
        all subclasses.

        Parameters
        ----------
        identifier : str
            The identifier to be queried (e.g., a domain, IP address, or URL).
        identifier_type : str
            The type of the identifier.
        task_db_id : str
            The database ID of the task associated with this operation.

        Returns
        -------
        dict
            A dictionary containing a reference to the stored data, typically
            including the SuperDB pool and a task ID.
        """
        pass
