from hunt.models import AbstractAnalyzer
import logging
import urllib.parse
import re

class Github(AbstractAnalyzer):
    """
    A child class that extends the functionality of APIClientBase to interact with the Github API.
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="github")
        # self.default_headers ={"accept": "application/vnd.github.text-match+json"}
        self.default_headers ={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {self.api_key}",
        "X-GitHub-Api-Version": "2022-11-28",}
        self.ioctype = ioctype
        self.observable = str(observable)
        self.task_id = task_id
        
    def sanitize_string(self, input_string):
        raw_string = str(input_string)
        sanitized_string = ' '.join(raw_string.strip().split())
        return sanitized_string        

    def extract_keywords(self, raw_string):
        sanitized_string = self.sanitize_string(raw_string)
        keywords = re.findall(r'\$[\w:]+|\w+', sanitized_string)
        
        return keywords

    def construct_search_query(self, keywords):
        # Join the keywords into a single query string
        search_query = ' '.join(keywords)
        
        # Add language filter (e.g., PowerShell, Python, etc.)
        # search_query += " language:ps"  # Change "ps" to another language if needed        
        return search_query
    
    def _get_code_search_report(self):
        keywords = self.extract_keywords(self.observable)
        search_query = self.construct_search_query(keywords)
        #encoded_query = urllib.parse.quote(search_query)
        params = {"q": search_query, "per_page": 1, "page": 1}
        response = self._make_request(observable="code search", endpoint="search/code", params=params)
        if response:
            return response
        else:
            logging.error(f"Failed to fetch report for {self.observable}")
    
    def execute(self):
        commits = []    
        if self.ioctype == 'freetext':
            commits.append(self._get_code_search_report())                        
        result = [{"taskid": self.task_id, "commits": commits}]
        return result