from hunt.models import AbstractAnalyzer
import logging

class Abuseipdb(AbstractAnalyzer):
    """
    A child class that extends the functionality of APIClientBase to interact with the AbuseIPDB API.
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="abuseipdb")
        self.default_headers ={"accept": "application/json", "Key": self.api_key}    
        self.ioctype = ioctype
        self.observable = observable
        self.task_id = task_id

    def _get_ip_report(self):
        params = { "ipAddress": self.observable,"MaxAgeInDays": 90, "verbose": ""}
        response = self._make_request(observable=self.observable, endpoint="check/", params=params)
        if response:
            return response
        else:
            logging.error(f"Abuseipdb - Failed to fetch report for {self.observable}")
    
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
        