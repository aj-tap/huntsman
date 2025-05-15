from hunt.models import AbstractAnalyzer
import logging

class Urlhaus(AbstractAnalyzer):
    """
    A child class that extends the functionality of APIClientBase to interact with the url hauz API.
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="urlhaus")
        self.ioctype = ioctype
        self.observable = observable
        self.task_id = task_id
        self.default_headers ={"Auth-Key": self.api_key}    
        
    def _get_host_info(self):
        payload = {"host": self.observable}
        response = self._make_request(observable=self.observable, endpoint="host/", method="POST", payload=payload)
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")
            
    def _get_payload_md5_info(self):
        payload = {"md5_hash": self.observable}
        response = self._make_request(observable=self.observable, endpoint="payload/", method="POST", payload=payload)
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")            

    def _get_payload_sha256_info(self):
        payload = {"sha256_hash": self.observable}
        response = self._make_request(observable=self.observable, endpoint="payload/", method="POST", payload=payload)
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")                   

    def _get_url_info(self):
         payload = {"url": self.observable}
        response = self._make_request(observable=self.observable, endpoint="url/", method="POST", payload=payload)
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")      
            
    def execute(self):
        commits = []
        if self.ioctype == 'ipv4s':
            commits.append(self._get_host_info())
        if self.ioctype == 'domains':
            commits.append(self._get_host_info())
        if self.ioctype == 'md5s':
            commits.append(self._get_payload_md5_info())
        if self.ioctype == 'sha256s':
            commits.append(self._get_payload_sha256_info())                    
        if self.ioctype == 'urls':
            commits.append(self._get_url_info())                            
        result = [{"taskid": self.task_id, "commits": commits}]
        return result
    