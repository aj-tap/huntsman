from hunt.models import AbstractAnalyzer
import logging

class Misp(AbstractAnalyzer):
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="misp")
        self.default_headers ={"accept": "application/json", "Authorization": self.api_key}    
        self.ioctype = ioctype
        self.observable = observable
        self.task_id = task_id
    
    def _get_report(self, value):
        payload = {
                "type": value,
                "value": self.observable
            }
        response = self._make_request(observable=self.observable, method="POST", payload=payload)
        if response:
            return response
        else:
            logging.error(f"MISP - Failed to fetch report for {self.observable}")
    
    def execute(self):
        commits = []    
        if self.ioctype == 'ipv4s':
            commits.append(self._get_report(value="ip-src"))
        if self.ioctype == 'ipv6s':
            if not self._is_valid_ipv6(self.observable):
                return None            
            commits.append(self._get_report(value="ip-src"))
        if self.ioctype == 'md5s':
            commits.append(self._get_report(value="md5"))
        if self.ioctype == 'sha256s':
            commits.append(self._get_report(value="sha256"))
        if self.ioctype == 'domains':
            commits.append(self._get_report(value="domain"))
        result = [{"taskid": self.task_id, "commits": commits}]
        return result