from hunt.models import AbstractAnalyzer
import requests
import logging
import xmltodict
import json
from datetime import datetime, timezone
import time 

class Wildfire(AbstractAnalyzer):
    """
    A child class that extends the functionality of APIClientBase to interact with the Wildfire API. https://wildfire.paloaltonetworks.com/publicapi/
    https://docs.paloaltonetworks.com/wildfire/u-v/wildfire-api/about-the-wildfire-api/wildfire-api-resources
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="wildfire")
        self.ioctype = ioctype
        self.observable = observable
        self.task_id = task_id

    def _fetch_url_verdict(self):
        endpoint = "get/verdict"
        http_method = "POST"
        url = f"{self.base_url}{endpoint}"
        request_timestamp = datetime.now(timezone.utc)
        start_time = time.monotonic()
        response = None
        status_code = None
        elapsed_seconds = None
        result_data = {}         

        files_payload = {
            "agent": (None, "prismaaccessapi"),
            "url": (None, self.observable),
            "apikey": (None, self.api_key),
        }

        try:
            logging.info(f"Requesting {http_method} {url} for verdict: {self.observable}")
            response = requests.post(url, files=files_payload, timeout=30)
            elapsed_seconds = time.monotonic() - start_time
            status_code = response.status_code

            if 200 <= status_code < 300:
                logging.info(f"Success ({status_code}) for verdict: {self.observable} ({elapsed_seconds:.2f}s)")
                if response.text and response.text.strip().startswith('<'):
                    try:
                        result_data = xmltodict.parse(response.text)
                    except Exception as parse_error:
                        logging.error(f"XML parsing failed for verdict ({self.observable}): {parse_error}")
                        result_data = {"error": "XML parsing failed", "raw_response": response.text}
                else:
                    logging.warning(f"Non-XML success response for verdict ({self.observable})")
                    result_data = {"warning": "Non-XML success response", "raw_response": response.text}
            else:
                logging.error(f"HTTP Error {status_code} for verdict ({self.observable}) ({elapsed_seconds:.2f}s)")
                result_data = {"error": f"HTTP Error: {status_code}", "raw_response": response.text}

        except requests.exceptions.RequestException as req_err:
            elapsed_seconds = time.monotonic() - start_time 
            logging.error(f"Request failed for verdict ({self.observable}): {req_err} ({elapsed_seconds:.2f}s)")
            result_data = {"error": f"Request failed: {req_err.__class__.__name__}", "details": str(req_err)}
            if hasattr(req_err, 'response') and req_err.response is not None:
                 status_code = req_err.response.status_code 

        timestamp_iso = request_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        data_to_store = {
            "observable": self.observable,
            "rawData": result_data, 
            "meta": {
                "ts": timestamp_iso,
                "taskId": self.task_id,
                "analyzerName": self.analyzer_name,
                "httpMethod": http_method,
                "statusCode": status_code, 
                "responseTimeSec": round(elapsed_seconds, 3) if elapsed_seconds is not None else None,
            }
        }
        return self.superDB_client.load_data_to_branch(
            self.poolname,
            "main",
            json.dumps(data_to_store, indent=4)
        )                
            
    def _fetch_file_verdict_hash(self):
        endpoint = "get/verdict"
        http_method = "POST"
        url = f"{self.base_url}{endpoint}"
        request_timestamp = datetime.now(timezone.utc)
        start_time = time.monotonic()
        response = None
        status_code = None
        elapsed_seconds = None
        result_data = {}         

        files_payload = {
            "agent": (None, "prismaaccessapi"),
            "hash": (None, self.observable),
            "apikey": (None, self.api_key),
        }

        try:
            logging.info(f"Requesting {http_method} {url} for verdict: {self.observable}")
            response = requests.post(url, files=files_payload, timeout=30)
            elapsed_seconds = time.monotonic() - start_time
            status_code = response.status_code

            if 200 <= status_code < 300:
                logging.info(f"Success ({status_code}) for verdict: {self.observable} ({elapsed_seconds:.2f}s)")
                if response.text and response.text.strip().startswith('<'):
                    try:
                        result_data = xmltodict.parse(response.text)
                    except Exception as parse_error:
                        logging.error(f"XML parsing failed for verdict ({self.observable}): {parse_error}")
                        result_data = {"error": "XML parsing failed", "raw_response": response.text}
                else:
                    logging.warning(f"Non-XML success response for verdict ({self.observable})")
                    result_data = {"warning": "Non-XML success response", "raw_response": response.text}
            else:
                logging.error(f"HTTP Error {status_code} for verdict ({self.observable}) ({elapsed_seconds:.2f}s)")
                result_data = {"error": f"HTTP Error: {status_code}", "raw_response": response.text}

        except requests.exceptions.RequestException as req_err:
            elapsed_seconds = time.monotonic() - start_time 
            logging.error(f"Request failed for verdict ({self.observable}): {req_err} ({elapsed_seconds:.2f}s)")
            result_data = {"error": f"Request failed: {req_err.__class__.__name__}", "details": str(req_err)}
            if hasattr(req_err, 'response') and req_err.response is not None:
                 status_code = req_err.response.status_code 

        timestamp_iso = request_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        data_to_store = {
            "observable": self.observable,
            "rawData": result_data,
            "meta": {
                "ts": timestamp_iso,
                "taskId": self.task_id,
                "analyzerName": self.analyzer_name,
                "httpMethod": http_method,
                "statusCode": status_code, 
                "responseTimeSec": round(elapsed_seconds, 3) if elapsed_seconds is not None else None,
            }
        }
        return self.superDB_client.load_data_to_branch(
            self.poolname,
            "main",
            json.dumps(data_to_store, indent=4)
        )        

    def _fetch_file_report_hash(self):
        endpoint = "get/report"
        http_method = "POST"
        url = f"{self.base_url}{endpoint}" 
        request_timestamp = datetime.now(timezone.utc)
        start_time = time.monotonic()
        response = None
        status_code = None
        elapsed_seconds = None
        result_data = {} 
        files_payload = {
            "agent": (None, "prismaaccessapi"),
            "hash": (None, self.observable),
            "apikey": (None, self.api_key),
            'format': (None, 'xml') # <--- Added format for report
        }
        try:
            logging.info(f"Requesting {http_method} {url} for report: {self.observable}")
            response = requests.post(url, files=files_payload, timeout=60) # <--- Increased timeout
            elapsed_seconds = time.monotonic() - start_time
            status_code = response.status_code

            if 200 <= status_code < 300:
                logging.info(f"Success ({status_code}) for report: {self.observable} ({elapsed_seconds:.2f}s)")
                if response.text and response.text.strip().startswith('<'):
                    try:
                        result_data = xmltodict.parse(response.text)
                    except Exception as parse_error:
                        logging.error(f"XML parsing failed for report ({self.observable}): {parse_error}")
                        result_data = {"error": "XML parsing failed", "raw_response": response.text}
                else:
                    logging.warning(f"Non-XML success response for report ({self.observable})")
                    result_data = {"warning": "Non-XML success response", "raw_response": response.text}
            else:
                logging.error(f"HTTP Error {status_code} for report ({self.observable}) ({elapsed_seconds:.2f}s)")
                result_data = {"error": f"HTTP Error: {status_code}", "raw_response": response.text}

        except requests.exceptions.RequestException as req_err:
            elapsed_seconds = time.monotonic() - start_time
            logging.error(f"Request failed for report ({self.observable}): {req_err} ({elapsed_seconds:.2f}s)")
            result_data = {"error": f"Request failed: {req_err.__class__.__name__}", "details": str(req_err)}
            if hasattr(req_err, 'response') and req_err.response is not None:
                 status_code = req_err.response.status_code # Attempt to get status code

        timestamp_iso = request_timestamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        data_to_store = {
            "observable": self.observable,
            "rawData": result_data,
            "meta": {
                "ts": timestamp_iso,
                "taskId": self.task_id,
                "analyzerName": self.analyzer_name,
                "httpMethod": http_method,
                "statusCode": status_code,
                "responseTimeSec": round(elapsed_seconds, 3) if elapsed_seconds is not None else None,
            }
        }
        return self.superDB_client.load_data_to_branch(
            self.poolname,
            "main",
            json.dumps(data_to_store, indent=4)
        )        
           
    def execute(self):
        commits = []
        if self.ioctype == 'md5s':
            commits.append(self._fetch_file_verdict_hash())
            commits.append(self._fetch_file_report_hash())
        if self.ioctype == 'sha256s':
            commits.append(self._fetch_file_verdict_hash())
            commits.append(self._fetch_file_report_hash())
        if self.ioctype == 'urls':
            commits.append(self._fetch_url_verdict())            
        result = [{"taskid": self.task_id, "commits": commits}]
        return result
    