from hunt.models import AbstractAnalyzer
import logging

class Shodan(AbstractAnalyzer):
    """
    A child class that extends the functionality of APIClientBase to interact with the Shodan API. https://api.shodan.io/ https://developer.shodan.io/api
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="shodan")
        #self.default_headers ={"accept": "application/json", "x-apikey": self.api_key}    
        self.ioctype = ioctype
        self.observable = observable
        self.task_id = task_id
    
    def _get_host_report(self):
        params = { "key": self.api_key}
        response = self._make_request(observable=self.observable, preffix_endpoint="shodan/host/", endpoint=self.observable, params=params)
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")
    
    def _get_host_query_report(self, query=None, facets=None):
        params = { "key": self.api_key, "query": query, "facets":facets}
        # params = { "key": self.api_key, "query": "port:22", "facets":"org,os"}        
        response = self._make_request(observable=self.observable, preffix_endpoint="shodan/host/", params=params)
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")
    
    def _get_subdomain_report(self):
        params = { "key": self.api_key}
        response = self._make_request(observable=self.observable, preffix_endpoint="dns/domain/", endpoint=self.observable, params=params)
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")                      
    
    def _get_dnslookup_report(self):
        params = { "hostnames":self.observable, "key": self.api_key}
        response = self._make_request(observable=self.observable, preffix_endpoint="dns/resolve", params=params)
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")      
            
    def _get_dnsreverse_report(self):
        params = { "ips":self.observable, "key": self.api_key}
        response = self._make_request(observable=self.observable, preffix_endpoint="dns/reverse", params=params)
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")                 
    
    def execute(self):
        commits = []    
        if self.ioctype == 'ipv4s':
            commits.append(self._get_host_report())
            #commits.append(self._get_dnsreverse_report()) 
        if self.ioctype == 'domains':
            commits.append(self._get_dnslookup_report())
        if self.ioctype == 'asns':
            commits.append(self._get_host_query_report(query=asn1234))           
            
        result = [{"taskid": self.task_id, "commits": commits}]
        return result