from hunt.models import AbstractAnalyzer
import logging

class Threatfox(AbstractAnalyzer):
    """
    A child class that extends the functionality of APIClientBase to interact with the threatfox API.
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="threatfox")
        self.ioctype = ioctype
        self.observable = observable
        self.task_id = task_id
        self.default_headers ={"accept": "application/json", "Auth-Key": self.api_key}    
        
    def _get_ioc(self):
        payload = { "query": "search_ioc", "search_term": self.observable }
        response = self._make_request(observable=self.observable, method="POST", data_json=payload)
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")
            
    def _get_ioc_by_hash(self):
        payload = { "query": "search_hash", "hash": self.observable }
        response = self._make_request(observable=self.observable, method="POST", data=payload)
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")

            
    def execute(self):
        commits = []
        if self.ioctype == 'md5s':
            #commits.append(self._get_ioc_by_hash())
            commits.append(self._get_ioc())
        if self.ioctype == 'sha256s':
            #commits.append(self._get_ioc_by_hash())
            commits.append(self._get_ioc())
        if self.ioctype == 'ipv4s':
            commits.append(self._get_ioc())
        if self.ioctype == 'domains':
            commits.append(self._get_ioc())        
        result = [{"taskid": self.task_id, "commits": commits}]
        return result
    