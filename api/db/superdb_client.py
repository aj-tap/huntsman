"""A client for interacting with the SuperDB API."""
import requests
import json
import logging
from typing import Dict, Any, Optional, List
from django.conf import settings

logger = logging.getLogger(__name__)

class SuperDBClient:
    """
    A client for interacting with the SuperDB API.

    This client provides methods for creating and managing pools, branches,
    and data within SuperDB.
    """

    def __init__(self) -> None:
        self.base_url: str = settings.SUPERDB_BASE_URL
        self.headers: Dict[str, str] = {'Accept': 'application/json','Content-Type': 'application/json'}

    def load_data_to_branch(self, pool_id_or_name: str, branch_name: str, data: Any, csv_delim: str = ',') -> Optional[Dict[str, Any]]:
        """
        Load data into a specific branch of a SuperDB pool.

        Parameters
        ----------
        pool_id_or_name : str
            The ID or name of the pool.
        branch_name : str
            The name of the branch.
        data : Any
            The data to load.
        csv_delim : str, optional
            The CSV delimiter, by default ','.

        Returns
        -------
        dict, optional
            The JSON response from the API, or None if an error occurred.
        """
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{branch_name}"
        params = {'csv.delim': csv_delim}
        try:
            response = requests.post(url, headers=self.headers, data=data, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error loading data to branch '{branch_name}' in pool '{pool_id_or_name}': {e}")
            return None

    def get_branch_info(self, pool_id_or_name: str, branch_name: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific branch.

        Parameters
        ----------
        pool_id_or_name : str
            The ID or name of the pool.
        branch_name : str
            The name of the branch.

        Returns
        -------
        dict, optional
            The JSON response from the API, or None if an error occurred.
        """
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{branch_name}"
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error getting branch info for '{branch_name}': {e}")
            return None

    def delete_branch(self, pool_id_or_name: str, branch_name: str) -> None:
        """
        Delete a branch from a pool.

        Parameters
        ----------
        pool_id_or_name : str
            The ID or name of the pool.
        branch_name : str
            The name of the branch to delete.
        """
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{branch_name}"
        try:
            response = requests.delete(url)
            response.raise_for_status()
            if response.status_code == 204:
                logger.info(f"Branch '{branch_name}' deleted successfully.")
            else:
                logger.warning(f"Unexpected response deleting branch '{branch_name}': {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error deleting branch '{branch_name}': {e}")

    def delete_data_from_branch(self, pool_id_or_name: str, branch_name: str, object_ids: Optional[List[str]] = None, where: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Delete data from a branch based on object IDs or a where clause.

        Parameters
        ----------
        pool_id_or_name : str
            The ID or name of the pool.
        branch_name : str
            The name of the branch.
        object_ids : list of str, optional
            A list of object IDs to delete.
        where : str, optional
            A where clause to filter the data to be deleted.

        Returns
        -------
        dict, optional
            The JSON response from the API, or None if an error occurred.
        """
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{branch_name}/delete"
        payload = {}
        if object_ids:
            payload['object_ids'] = object_ids
        if where:
            payload['where'] = where

        try:
            response = requests.post(url, headers=self.headers, data=json.dumps(payload))
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error deleting data from branch '{branch_name}': {e}")
            return None

    def merge_branches(self, pool_id_or_name: str, destination_branch: str, source_branch: str) -> Optional[Dict[str, Any]]:
        """
        Merge one branch into another.

        Parameters
        ----------
        pool_id_or_name : str
            The ID or name of the pool.
        destination_branch : str
            The name of the destination branch.
        source_branch : str
            The name of the source branch.

        Returns
        -------
        dict, optional
            The JSON response from the API, or None if an error occurred.
        """
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{destination_branch}/merge/{source_branch}"
        try:
            response = requests.post(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error merging branch '{source_branch}' into '{destination_branch}': {e}")
            return None

    def revert_commit(self, pool_id_or_name: str, branch_name: str, commit_id: str) -> Optional[Dict[str, Any]]:
        """
        Revert a specific commit on a branch.

        Parameters
        ----------
        pool_id_or_name : str
            The ID or name of the pool.
        branch_name : str
            The name of the branch.
        commit_id : str
            The ID of the commit to revert.

        Returns
        -------
        dict, optional
            The JSON response from the API, or None if an error occurred.
        """
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{branch_name}/revert/{commit_id}"
        try:
            response = requests.post(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error reverting commit '{commit_id}': {e}")
            return None

    def create_pool(self, name: str, layout_order: str = 'asc', layout_keys: List[List[str]] = [['ts']], thresh: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Create a new pool in SuperDB.

        Parameters
        ----------
        name : str
            The name of the new pool.
        layout_order : str, optional
            The layout order, by default 'asc'.
        layout_keys : list of list of str, optional
            The layout keys, by default [['ts']].
        thresh : int, optional
            The pool threshold, by default None.

        Returns
        -------
        dict, optional
            The JSON response from the API, or None if an error occurred.
        """
        url = f"{self.base_url}/pool"
        payload: Dict[str, Any] = {
            'name': name,
            'layout': {
                'order': layout_order,
                'keys': layout_keys
            }
        }
        if thresh is not None:
            payload['thresh'] = thresh

        try:
            response = requests.post(url, headers=self.headers, data=json.dumps(payload))
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error creating pool '{name}': {e}")
            return None

    def vacuum_pool(self, pool_id_or_name: str, revision: str, dryrun: bool = False) -> None:
        """
        Vacuum a pool to reclaim space.

        Parameters
        ----------
        pool_id_or_name : str
            The ID or name of the pool.
        revision : str
            The revision to vacuum up to.
        dryrun : bool, optional
            If True, perform a dry run without actually deleting data.
        """
        url = f"{self.base_url}/pool/{pool_id_or_name}/revision/{revision}/vacuum"
        params = {'dryrun': 'T' if dryrun else 'F'}

        try:
            response = requests.post(url, headers=self.headers, params=params)
            response.raise_for_status()

            if response.status_code == 200:
                data = response.json()
                if dryrun:
                    logger.info(f"Vacuum dryrun objects: {data.get('objects', [])}")
                else:
                    logger.info("Pool vacuumed successfully.")
            else:
                logger.warning(f"Unexpected response vacuuming pool: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error vacuuming pool: {e}")

    def execute_query(self, query: str, pool: Optional[str] = None, branch: str = 'main', ctrl: str = 'F') -> Optional[Dict[str, Any]]:
        """
        Execute a query against SuperDB.

        Parameters
        ----------
        query : str
            The query string to execute.
        pool : str, optional
            The pool to query against, by default None.
        branch : str, optional
            The branch to query against, by default 'main'.
        ctrl : str, optional
            Control flag, by default 'F'.

        Returns
        -------
        dict, optional
            The JSON response from the API, or None if an error occurred.
        """
        url = f"{self.base_url}/query"
        params = {'ctrl': ctrl}
        payload: Dict[str, Any] = {'query': query}
        
        if pool:
            payload['head.pool'] = pool
        payload['head.branch'] = branch
    
        try:
            logger.debug(f"Executing Query at {url} | Params: {params} | Payload: {payload}")
            
            response = requests.post(
                url, 
                headers=self.headers, 
                params=params, 
                data=json.dumps(payload)
            )
            logger.debug(f"Query Response Status: {response.status_code}")
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error executing query: {e}")
            if e.response is not None:
                 logger.error(f"DB Response: {e.response.text}")
            return None
