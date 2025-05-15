from hunt.models import AbstractAnalyzer
from lxml import html
import json
import logging
import requests
from datetime import datetime
from datetime import datetime, timezone, timedelta


class Spurus(AbstractAnalyzer):
    """
    A child class that extends the functionality of AbstractAnalyzer to scrape with the Spur.us page
    """
    def __init__(self, ioctype:str, observable: str, task_id: str):
        super().__init__(analyzer_name="spurus")
        self.default_headers ={"accept": "application/json"}
        self.ioctype = ioctype
        self.observable = observable
        self.task_id = task_id
        
    def _get_ip_proxy_report(self):
        current_utc_time = datetime.now(timezone.utc)
        timestamp_iso = current_utc_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        
        url = f"{self.base_url}{self.observable}"        
        headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive"}
        
        response = requests.get(url, headers=headers)        
        if response.status_code == 200:
            tree = html.fromstring(response.content)
            
            # Extract data using the given XPaths
            attribution = tree.xpath("//div[@id='preview']/div/div/p/text()")
            proxies_traffic = tree.xpath("//div[@id='preview']/div/div/div[2]/div[2]/p/text()")
            datacenter = tree.xpath("//div[@id='preview']/div/div/div[2]/div[3]/p/text()")
            # Clean and join the extracted text
            attribution_text = " ".join(" ".join(attribution).replace('\n', ' ').split()).strip() if attribution else "No attribution found"
            proxies_traffic_text = " ".join(" ".join(proxies_traffic).replace('\n', ' ').split()).strip() if proxies_traffic else "No proxies traffic info found"
            datacenter_text = " ".join(" ".join(datacenter).replace('\n', ' ').split()).strip() if datacenter else "No datacenter info found"
            # Organize the content into a structured dictionary
            result_data = {
                "ip_address": self.observable,
                "attribution": attribution_text,
                "proxies_traffic": proxies_traffic_text,
                "datacenter": datacenter_text
            }            

        data = {
            "observable": self.observable,
            "rawData": result_data,
            "meta": {
                "ts": timestamp_iso,
                "taskId": self.task_id,
                "analyzerName": self.analyzer_name,
            },
        }        
        # Serialize to JSON and load data to the database
        return self.superDB_client.load_data_to_branch(
            self.poolname,
            "main",
            json.dumps(data, indent=4)
        )
        
    def execute(self):
        commits = []    
        if self.ioctype == 'ipv4s':
            commits.append(self._get_ip_proxy_report())
            result = [{"taskid": self.task_id, "commits": commits}]
            return result
        if self.ioctype == 'ipv6s':
            commits.append(self._get_ip_proxy_report())
            result = [{"taskid": self.task_id, "commits": commits}]
            return result        
        return None