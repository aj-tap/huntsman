from hunt.models import AbstractAnalyzer
import logging
import re

class Bgpview(AbstractAnalyzer):
    """
    A child class that extends the functionality of AbstractAnalyzer to interact with the BGPView API.
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="bgpview")
        self.ioctype = ioctype
        self.observable = observable
        self.task_id = task_id

    def _get_asn_report(self):
        # https://api.bgpview.io/asn/as_number
        if not isinstance(self.observable, str) or not self.observable:
            logging.error(f"Invalid observable: {self.observable}. Expected a non-empty string.")
            return None
        asn_number = re.sub(r'^ASN', '', self.observable) # <-- Improvement here
        if not asn_number.isdigit():
            logging.error(f"Failed to extract a valid numeric ASN from '{self.observable}'. Got: '{asn_number}'")
            return None
        response = self._make_request(
            observable=self.observable,
            endpoint="asn/",
            suffix_endpoint=asn_number
        )
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for observable '{self.observable}' (ASN: {asn_number})")
            return None
    def _get_ip_report(self):
        # https://api.bgpview.io/ip/ip_address
        response = self._make_request(observable=self.observable, endpoint="ip/", suffix_endpoint=self.observable)
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")

    def execute(self):
        commits = []    
        if self.ioctype == 'ipv4s':
            commits.append(self._get_ip_report())
        if self.ioctype == 'ipv6s':
            commits.append(self._get_ip_report())           
        if self.ioctype == 'asns':
            commits.append(self._get_asn_report())                        
        result = [{"taskid": self.task_id, "commits": commits}]
        return result
