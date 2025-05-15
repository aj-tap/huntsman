from hunt.models import AbstractAnalyzer
import logging

class Alienvault(AbstractAnalyzer):
    """
    A child class that extends the functionality of APIClientBase to interact with the AlienVault API.
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="alienvault")
        self.ioctype = ioctype
        self.observable = observable
        self.task_id = task_id
        
    def _get_file_report(self, section):
        # Use the inherited request method from the parent class
        response = self._make_request(observable=self.observable, endpoint=self.observable, preffix_endpoint="/indicators/file/", suffix_endpoint=section)
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")

    def _get_domain_report(self, section):
        # Use the inherited request method from the parent class
        response = self._make_request(observable=self.observable, endpoint=self.observable, preffix_endpoint="/indicators/domain/", suffix_endpoint=section)
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")
            
    def _get_ip_report_v4(self, section):
        # Use the inherited request method from the parent class
        response = self._make_request(observable=self.observable, endpoint=self.observable, preffix_endpoint="/indicators/IPv4/", suffix_endpoint=section)
        if response:
            # Use the inherited telemetry method to store the response data
            #return self._store_telemetry(observable=self.observable, task_id=self.task_id, response=response) #self, observable, task_id, response, request_type
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")

    def _get_ip_report_v6(self, section):
        # Use the inherited request method from the parent class
        response = self._make_request(observable=self.observable, endpoint=self.observable, preffix_endpoint="/indicators/IPv6/", suffix_endpoint=section)
        if response:
            # Use the inherited telemetry method to store the response data
            #return self._store_telemetry(observable=self.observable, task_id=self.task_id, response=response) #self, observable, task_id, response, request_type
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")        
            
    def execute(self):
        commits = []
        if self.ioctype == 'ipv4s':
            commits.append(self._get_ip_report_v4("/general"))
            #commits.append(self._get_ip_report("/passive_dns"))
            #commits.append(self._get_ip_report("/reputation"))
            #commits.append(self._get_ip_report("/url_list"))
            #commits.append(self._get_ip_report("/http_scans"))
        if self.ioctype == 'ipv6s':
            if not self._is_valid_ipv6(self.observable):
                return None
            commits.append(self._get_ip_report_v6("/general")) 
            result = [{"taskid": self.task_id, "commits": commits}]
            return result                       
        if self.ioctype == 'domains':
            commits.append(self._get_domain_report("/general"))
            result = [{"taskid": self.task_id, "commits": commits}]
            return result            
        if self.ioctype == 'sha256s':
            commits.append(self._get_file_report("/general"))
            result = [{"taskid": self.task_id, "commits": commits}]
            return result            
        return None
    