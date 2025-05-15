from hunt.models import AbstractAnalyzer
import logging

class Certificatesearch(AbstractAnalyzer):
    """
    A child class that extends the functionality of AbstractAnalyzer to interact with the crt.sh
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="certificatesearch")
        self.ioctype = ioctype
        self.observable = observable
        self.task_id = task_id

    def _get_domain_certs(self):
        params = { "q": self.observable}
        response = self._make_request(observable=self.observable,endpoint='json', params=params)        
        if response:                       
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")

    def execute(self):
        commits = []    
        if self.ioctype == 'domains':
            commits.append(self._get_domain_certs())
        result = [{"taskid": self.task_id, "commits": commits}]
        return result
