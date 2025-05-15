import whois
from hunt.models import AbstractAnalyzer
import logging
from datetime import datetime
import json

class Whois(AbstractAnalyzer):
    """
    A child class that extends the functionality of APIClientBase to make request to Whois
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="whois")
        self.ioctype = ioctype
        self.observable = observable
        self.task_id = task_id    
            
    def _serialize_datetime(self, obj):
        if isinstance(obj, dict):
            return {key: self._serialize_datetime(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._serialize_datetime(element) for element in obj]
        elif isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S') + 'Z'
        else:
            return obj

    def _get_whois(self, domain, task_id):
        now = datetime.utcnow()
        timestamp_iso = now.strftime('%Y-%m-%dT%H:%M:%S') + 'Z'
        
        try:
            w = whois.whois(domain)
            whois_dict = self._serialize_datetime(dict(w))
        except Exception as e:
            return {"error": str(e)}

        data = {
            "ts": timestamp_iso,
            "observable": domain,
            "rawData": whois_dict,
            "meta": {
                "taskId": task_id,
                "analyzerName": self.analyzer_name,
            },
        }
        
        return self.superDB_client.load_data_to_branch(
            self.poolname,
            "main",
            json.dumps(data, indent=2)
        )

    def execute(self):
        commits = []    
        if self.ioctype == 'domains':
            commits.append(self._get_whois(self.observable, self.task_id))   
        result = [{"taskid": self.task_id, "commits": commits}]
        return result