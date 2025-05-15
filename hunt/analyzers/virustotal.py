from hunt.models import AbstractAnalyzer
import logging

class Virustotal(AbstractAnalyzer):
    """
    A child class that extends the functionality of APIClientBase to interact with the Virustotal API.
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="virustotal")
        self.default_headers ={"accept": "application/json", "x-apikey": self.api_key}    
        self.ioctype = ioctype
        self.observable = observable
        self.task_id = task_id
    
    def _get_file_report(self):
        response = self._make_request(observable=self.observable, endpoint=self.observable, preffix_endpoint="files/")
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")
    
    def _get_file_contactedip_report(self):
        response = self._make_request(observable=self.observable, endpoint=self.observable, preffix_endpoint="files/",suffix_endpoint="/contacted_ips")
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")    

    def _get_domain_report(self):
        response = self._make_request(observable=self.observable, endpoint=self.observable, preffix_endpoint="domains/")
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")
    
    def _get_ip_report(self):
        response = self._make_request(observable=self.observable, endpoint=self.observable, preffix_endpoint="ip_addresses/")
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")
    
    def _get_ip_domain_report(self):
        response = self._make_request(observable=self.observable, endpoint=self.observable, preffix_endpoint="ip_addresses/",suffix_endpoint="/resolutions")
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
        if self.ioctype == 'domains':
            commits.append(self._get_domain_report())
            result = [{"taskid": self.task_id, "commits": commits}]
            return result            
        if self.ioctype == 'md5s':
            commits.append(self._get_file_report())    
            result = [{"taskid": self.task_id, "commits": commits}]
            return result                    
        if self.ioctype == 'sha256s':
            commits.append(self._get_file_report())
            # commits.append(self._get_file_contactedip_report())
            result = [{"taskid": self.task_id, "commits": commits}]
            return result
        return None