

from hunt.models import AbstractAnalyzer
import logging

class Proxycheckio(AbstractAnalyzer):
    """
    A child class that extends the functionality of AbstractAnalyzer to interact with the Proxy Check API.
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="proxycheckio")
        self.default_headers ={"accept": "application/json"}
        self.ioctype = ioctype
        self.observable = observable
        self.task_id = task_id
    
    def _get_ip_proxy_report(self):
        params = { "key": self.api_key, "vpn":"3", "asn":"1", "risk":"1","port":"1", "seen":"1", "days":"7"}
        response = self._make_request(observable=self.observable, endpoint=self.observable, params=params)        
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")
                        
    def execute(self):
        commits = []    
        if self.ioctype == 'ipv4s':
            commits.append(self._get_ip_proxy_report())
        if self.ioctype == 'ipv6s':
            if not self._is_valid_ipv6(self.observable):
                return None            
            commits.append(self._get_ip_proxy_report())
        result = [{"taskid": self.task_id, "commits": commits}]
        return result