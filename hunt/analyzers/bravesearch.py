from hunt.models import AbstractAnalyzer
import logging
import json
import requests
from datetime import datetime

class Bravesearch(AbstractAnalyzer): #Correct class name
    """
    A child class that extends the functionality of AbstractAnalyzer to interact with the Brave Search API.
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="bravesearch")
        self.ioctype = ioctype
        self.observable = observable
        self.task_id = task_id

    def _fetch_search(self, search_term: str):
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "X-Subscription-Token": self.api_key
        }
        params = {
            "q": search_term,#str(self.observable),
            "count": 5,
            "country": "us",
            "search_lang": "en",
            "spellcheck": 0
        }

        try:
            response = requests.get(self.base_url, headers=headers, params=params)
            response.raise_for_status()  # Raise HTTPError for bad responses
            return response.json()  # Return JSON response
        except requests.exceptions.RequestException as e:
            # Handle errors (network issues, API errors, etc.)
            print(f"An error occurred: {e}")
            return None

    def _get_ip_dorking(self):        
        search_term = f'inbody:{self.observable} OR intitle:{self.observable} OR inpage:{self.observable} IP'
        now = datetime.utcnow()
        timestamp_iso = now.strftime('%Y-%m-%dT%H:%M:%S') + 'Z'        
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "X-Subscription-Token": self.api_key
        }
        params = {
            "q": search_term,
            "count": 5,
            "country": "us",
            "search_lang": "en",
            "spellcheck": 0,
            "safesearch": "off",
        }
        try:
            response = requests.get(self.base_url, headers=headers, params=params)
            response.raise_for_status()  # Raise HTTPError for bad responses
            result_data = response.json()                        
            search_results = result_data.get('web', {}).get('results', []) # filter to get results only
            data = { "observable": self.observable, "rawData": search_results,
            "meta": {
                "ts": timestamp_iso,
                "taskId": self.task_id,
                "analyzerName": self.analyzer_name,},}
            
            return self.superDB_client.load_data_to_branch(self.poolname,"main", json.dumps(data, indent=4)
        )
        except requests.exceptions.RequestException as e:
            # Handle errors (network issues, API errors, etc.)
            print(f"An error occurred: {e}")
            return None

    def _get_ip_dorking(self):        
        search_term = f'inbody:{self.observable} OR intitle:{self.observable} OR inpage:{self.observable} IP'
        now = datetime.utcnow()
        timestamp_iso = now.strftime('%Y-%m-%dT%H:%M:%S') + 'Z'        
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "X-Subscription-Token": self.api_key
        }
        params = {
            "q": search_term,
            "count": 5,
            "country": "us",
            "search_lang": "en",
            "spellcheck": 0,
            "safesearch": "off",
        }
        try:
            response = requests.get(self.base_url, headers=headers, params=params)
            response.raise_for_status()  # Raise HTTPError for bad responses
            result_data = response.json()                        
            search_results = result_data.get('web', {}).get('results', []) # filter to get results only
            data = { "observable": self.observable, "rawData": search_results,
            "meta": {
                "ts": timestamp_iso,
                "taskId": self.task_id,
                "analyzerName": self.analyzer_name,},}
            
            return self.superDB_client.load_data_to_branch(self.poolname,"main", json.dumps(data, indent=4)
        )
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            return None
        
    def _get_domain_dorking(self):        
        search_term = f'inurl:{self.observable} OR intitle:{self.observable} OR inpage:{self.observable}'
        now = datetime.utcnow()
        timestamp_iso = now.strftime('%Y-%m-%dT%H:%M:%S') + 'Z'        
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "X-Subscription-Token": self.api_key
        }
        params = {
            "q": search_term,
            "count": 5,
            "country": "us",
            "search_lang": "en",
            "spellcheck": 0,
            "safesearch": "off",
        }
        try:
            response = requests.get(self.base_url, headers=headers, params=params)
            response.raise_for_status()  # Raise HTTPError for bad responses
            result_data = response.json()                        
            search_results = result_data.get('web', {}).get('results', []) # filter to get results only
            data = { "observable": self.observable, "rawData": search_results,
            "meta": {
                "ts": timestamp_iso,
                "taskId": self.task_id,
                "analyzerName": self.analyzer_name,},}
            
            return self.superDB_client.load_data_to_branch(self.poolname,"main", json.dumps(data, indent=4)
        )
        except requests.exceptions.RequestException as e:
            # Handle errors (network issues, API errors, etc.)
            print(f"An error occurred: {e}")
            return None

    def execute(self):
        commits = []    
        if self.ioctype == 'ipv4s':
            commits.append(self._get_ip_dorking())
            result = [{"taskid": self.task_id, "commits": commits}]
            return result
        if self.ioctype == 'domains':
            commits.append(self._get_domain_dorking())
            result = [{"taskid": self.task_id, "commits": commits}]
            return result
        return None
