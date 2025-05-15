
from hunt.models import AbstractAnalyzer
import logging

class Ipinfo(AbstractAnalyzer):
    """
    A child class that extends the functionality of AbstractAnalyzer to interact with the IP Info API.
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="ipinfo")
        self.default_headers ={"accept": "application/json", "Authorization": f"Bearer {self.api_key}"}
        self.ioctype = ioctype
        self.observable = observable
        self.task_id = task_id
    
    def _get_ip_report(self):
        response = self._make_request(observable=self.observable, endpoint=self.observable)
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")

        
    def execute(self):
        commits = []    
        if self.ioctype == 'ipv4s':
            commits.append(self._get_ip_report())
            result = [{"taskid": self.task_id, "commits": commits}]
            return result            
        if self.ioctype == 'ipv6s':
            if not self._is_valid_ipv6(self.observable):
                return None            
            commits.append(self._get_ip_report())
            result = [{"taskid": self.task_id, "commits": commits}]
            return result        
        return None