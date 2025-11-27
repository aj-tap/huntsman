"""A configurable connector for the Huntsman API."""
import requests
import json
import time
import base64
from datetime import datetime, timedelta
from typing import Dict, Any
from .base import ExternalServiceConnector

class ConfigurableConnector(ExternalServiceConnector):
    """
    A generic connector driven by an external API recipe configuration.

    This connector is designed to be highly flexible, with its behavior
    defined by a service recipe dictionary. It supports various authentication
    methods, request parameters, data storage configurations, and dynamic transformations.

    Parameters
    ----------
    api_key : str
        The API key for the service.
    service_recipe : dict
        A dictionary containing the configuration for the service.
    """

    def __init__(self, api_key: str, service_recipe: Dict[str, Any]) -> None:
        super().__init__(api_key)
        self.recipe: Dict[str, Any] = service_recipe

    def _prepare_request(self, identifier: str, identifier_type: str) -> Dict[str, Any]:
        """
        Prepare the details for an API request based on the service recipe.

        Parameters
        ----------
        identifier : str
            The identifier to be queried.
        identifier_type : str
            The type of the identifier.

        Returns
        -------
        dict
            A dictionary containing the prepared request details.

        Raises
        ------
        ValueError
            If the identifier type is not supported by the recipe.
        """
        endpoint_recipe = self.recipe["endpoints"].get(identifier_type)
        if not endpoint_recipe: 
            raise ValueError(f"Identifier type '{identifier_type}' is not supported.")
        
        url = self.recipe["base_url"] + endpoint_recipe["path_template"].format(identifier=identifier)
        headers = self.recipe.get("static_headers", {}).copy()
        
        if "headers" in endpoint_recipe:
            headers.update(endpoint_recipe["headers"])

        params = {}
        
        if "auth" in self.recipe and self.api_key:
            auth_recipe = self.recipe["auth"]
            prefix = auth_recipe.get("config", {}).get("prefix", "")
            final_key = f"{prefix}{self.api_key}" if prefix else self.api_key

            if auth_recipe["type"] == "header": 
                headers[auth_recipe["config"]["header_name"]] = final_key
            if auth_recipe["type"] == "param": 
                params[auth_recipe["config"]["param_name"]] = final_key
        
        now = datetime.now()
        context = {
            "identifier": identifier,
            "today": now.strftime("%Y-%m-%d"),
            "start_date": (now - timedelta(days=30)).strftime("%Y-%m-%d")
        }

        if "params_template" in endpoint_recipe:
            for k, v in endpoint_recipe["params_template"].items(): 
                if isinstance(v, dict) and v.get("transform") == "base64":
                    template_str = v.get("template", "")
                    formatted_str = template_str.format(**context)
                    encoded_bytes = base64.urlsafe_b64encode(formatted_str.encode("utf-8"))
                    params[k] = encoded_bytes.decode("utf-8")
                elif isinstance(v, str):
                    params[k] = v.format(**context)
                else:
                    params[k] = v
                    
        body_data = None
        if "body_template" in endpoint_recipe: 
            # We process the template into a dictionary. 
            # Whether this is sent as JSON or Form data depends on the 'encoding' field.
            body_data = json.loads(json.dumps(endpoint_recipe["body_template"]).format(identifier=identifier))
            
        return {
            "method": endpoint_recipe["method"], 
            "url": url, 
            "headers": headers, 
            "params": params, 
            "body_data": body_data, 
            "encoding": endpoint_recipe.get("encoding", "json"), # Default to JSON
            "db_pool": endpoint_recipe["db_pool"], 
            "ratelimit": endpoint_recipe.get("ratelimit")
        }

    def fetch_and_store(self, identifier: str, identifier_type: str, task_db_id: str) -> Dict[str, Any]:
        """
        Fetch data from the external service and store it in SuperDB.

        This method prepares and executes an API request, then stores the
        JSON response in the appropriate SuperDB pool.

        Parameters
        ----------
        identifier : str
            The identifier to be queried.
        identifier_type : str
            The type of the identifier.
        task_db_id : str
            The database ID of the task associated with this operation.

        Returns
        -------
        dict
            A dictionary containing a reference to the stored data.

        Raises
        ------
        requests.exceptions.RequestException
            If the API request fails.
        """
        request_details = self._prepare_request(identifier, identifier_type)
        db_pool = request_details["db_pool"]
        ratelimit = request_details["ratelimit"]

        try:
            if ratelimit:
                rate, period = ratelimit.split('/')
                # Simple rate limit parsing: 1/5s -> sleep 5
                unit_map = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
                duration = int(period[:-1]) * unit_map.get(period[-1], 1)
                count = int(rate)
                delay = duration / count
                time.sleep(delay)

            json_payload = None
            data_payload = None
            
            if request_details['encoding'] == 'form':
                data_payload = request_details['body_data']
            else:
                json_payload = request_details['body_data']

            response = self.session.request(
                method=request_details['method'], 
                url=request_details['url'], 
                headers=request_details['headers'], 
                params=request_details['params'], 
                json=json_payload, 
                data=data_payload,
                timeout=20
            )
            response.raise_for_status()
            
            try:
                raw_data = response.json()
            except json.JSONDecodeError:
                print(f"Warning: Response was not JSON. Content: {response.text[:100]}...")
                raw_data = {"error": "Invalid JSON response", "raw_content": response.text}

        except requests.exceptions.RequestException as e:
            print(f"API request failed: {e}")
            raise
            
        raw_data['task_id'] = task_db_id
        json_data_to_store = json.dumps(raw_data)
        self.db_client.load_data_to_branch(pool_id_or_name=db_pool, branch_name='main', data=json_data_to_store)
        return {"pool": db_pool}