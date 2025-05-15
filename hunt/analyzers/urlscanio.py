from hunt.models import AbstractAnalyzer
import logging

class Urlscanio(AbstractAnalyzer):
    """
    A child class that extends the functionality of AbstractAnalyzer to interact with the Urlscan.IO API.
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="urlscanio")
        self.default_headers ={"Content-Type": "application/json", "API-Key": self.api_key}    
        self.ioctype = ioctype
        self.observable = observable
        self.task_id = task_id
    
    def _get_domain_report(self, limit=1):
        params = {
            "q": f"task.domain:{self.observable} AND task.url:{self.observable} AND page.domain:{self.observable}",
            "size": limit
        }
        response = self._make_request(observable=self.observable, endpoint="search/", params=params)
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")
    
    def execute(self):
        commits = []    
        if self.ioctype == 'domains':
            commits.append(self._get_domain_report()) 
        result = [{"taskid": self.task_id, "commits": commits}]
        return result