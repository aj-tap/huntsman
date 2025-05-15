from hunt.models import AbstractAnalyzer
import logging

class Internetdb(AbstractAnalyzer):
    """
    A child class that extends the functionality of AbstractAnalyzer to interact with the InternetDB API.
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="internetdb")
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
