from django.db import models
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator
import json
import os
from django.db import models
from django.conf import settings
import requests
import importlib
from datetime import datetime, timedelta, timezone
import logging
import feedparser
import xmltodict
import glob
import yaml

logger = logging.getLogger(__name__)

def get_analyzer_choices():
    analyzers_dir = os.path.join(settings.BASE_DIR, "hunt", "analyzers")
    modules = [
        os.path.splitext(os.path.basename(file))[0]
        for file in glob.glob(os.path.join(analyzers_dir, "*.py"))
        if os.path.isfile(file) and os.path.basename(file) != "__init__.py"
    ]
    return [(module, module.replace("_", " ").title()) for module in modules]

class Analyzer(models.Model):
    name = models.CharField(max_length=100, help_text="Name of the analyzer", unique=True)
    description = models.TextField(null=True, blank=True, help_text="Optional description of the analyzer")
    api_key = models.CharField(null=True, blank=True, max_length=255, help_text="API key for external service access")
    base_url = models.CharField(null=True, max_length=255, help_text="Base URL for external service access")
    plugin_settings = models.JSONField(default=dict, blank=True, help_text="Plugin-specific configuration in JSON format")
    created_at = models.DateTimeField(auto_now_add=True, help_text="Time when the analyzer was created")
    updated_at = models.DateTimeField(auto_now=True, help_text="Time when the analyzer was last updated")
    analyzer_module = models.CharField(
        max_length=100,
        choices=get_analyzer_choices(),
        help_text="Select the analyzer module",
        null=True,
        blank=True,  
        editable=False  
    )
    rate_limit = models.PositiveIntegerField(
        default=1000,
        validators=[MaxValueValidator(10000)],
        help_text="Maximum number of requests per time unit (e.g., per minute)."
    )
    rate_limit_time_unit = models.CharField(
        max_length=10,
        choices=[('minute', 'Minute'), ('hour', 'Hour'), ('day', 'Day')],
        default='minute',
        help_text="Time unit for the rate limit."
    )

    class Meta:
        verbose_name = "Analyzer"
        verbose_name_plural = "Analyzers"
        ordering = ['name']

    def __str__(self):
        return self.name
    
    def save(self, *args, **kwargs):
        if not self.analyzer_module:
            snake_case_name = "".join(["_"+c.lower() if c.isupper() else c for c in self.name]).lstrip("_").replace(" ", "_")
            analyzer_choices = [choice[0] for choice in get_analyzer_choices()]
            if snake_case_name in analyzer_choices:
              self.analyzer_module = snake_case_name
            else:
              logger.warning(f"No matching analyzer module found for name: '{self.name}'. Module will be left blank.")

        super().save(*args, **kwargs)

    def get_module_instance(self, **kwargs):
        if not self.analyzer_module:
            raise ValueError(f"Analyzer module is not selected for analyzer: {self.name}.")

        try:
            module_path = f"hunt.analyzers.{self.analyzer_module}"
            module = importlib.import_module(module_path)
            class_name = ''.join(word.capitalize() for word in self.analyzer_module.split('_'))
            analyzer_class = getattr(module, class_name)
            return analyzer_class(**kwargs) 
        except (ImportError, AttributeError) as e:
            raise ImportError(f"Could not load analyzer module '{self.analyzer_module}': {e}")

class ObservableType(models.Model):
    IOCTYPE_CHOICES = [
        ("asns", "ASNs"),
        ("authentihashes", "Authentihashes"),
        ("bitcoin_addresses", "Bitcoin Addresses"),
        ("cves", "CVEs"),
        ("domains", "Domains"),
        ("email_addresses", "Email Addresses"),
        ("email_addresses_complete", "Complete Email Addresses"),
        ("file_paths", "File Paths"),
        ("google_adsense_publisher_ids", "Google Adsense Publisher IDs"),
        ("google_analytics_tracker_ids", "Google Analytics Tracker IDs"),
        ("imphashes", "Imphashes"),
        ("ipv4_cidrs", "IPv4 CIDRs"),
        ("ipv4s", "IPv4s"),
        ("ipv6s", "IPv6s"),
        ("mac_addresses", "MAC Addresses"),
        ("md5s", "MD5s"),
        ("monero_addresses", "Monero Addresses"),
        ("registry_key_paths", "Registry Key Paths"),
        ("sha1s", "SHA1s"),
        ("sha256s", "SHA256s"),
        ("sha512s", "SHA512s"),
        ("ssdeeps", "SSDEEPs"),
        ("tlp_labels", "TLP Labels"),
        ("urls", "URLs"),
        ("user_agents", "User Agents"),
        ("xmpp_addresses", "XMPP Addresses"),
        ("freetext", "FreeText"),  # Add freetext
    ]
    name = models.CharField(max_length=50, unique=True, choices=IOCTYPE_CHOICES, help_text="Name of the observable type (e.g., 'ipv4s', 'domains')")

    class Meta:
        verbose_name = "Observable Type"
        verbose_name_plural = "Observable Types"
        ordering = ["name"]

    def __str__(self):
        return self.get_name_display()

class DetectionRule(models.Model):
    title = models.CharField(max_length=255, help_text="Title of the detection rule", unique=True)
    description = models.TextField(null=True, blank=True, help_text="Detailed description of the rule")
    syntax = models.TextField(help_text="SuperDB syntax for the detection rule")
    tags = models.CharField(max_length=255, blank=True, help_text="Comma-separated tags for the rule")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title 
    
    def to_dict(self):        
        return {
            'title': self.title,
            'description': self.description,
            'syntax': self.syntax,
            'tags': self.tags,
        }
        
class Playbook(models.Model):
    name = models.CharField(max_length=100, help_text="Name of the playbook")
    description = models.TextField(null=True, blank=True, help_text="Optional description of the playbook")
    analyzers = models.ManyToManyField("Analyzer", related_name="playbooks", help_text="List of associated analyzers")
    observable_types = models.ManyToManyField(
        ObservableType, related_name="playbooks", help_text="Types of observables this playbook can handle"
    )

    class Meta:
        verbose_name = "Playbook"
        verbose_name_plural = "Playbooks"
        ordering = ['name']

    def __str__(self):
        return self.name

class QueriesTemplate(models.Model):
    title = models.CharField(max_length=255)
    query_string = models.TextField()

    def __str__(self):
        return self.title

class Config(models.Model):
    gemini_api = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Gemini API key"
    )

    class Meta:
        verbose_name = "Config Hunt"
        verbose_name_plural = "Config Hunt" 
        ordering = ['id']

    def save(self, *args, **kwargs):
        if not self.pk and Config.objects.exists():
            raise ValueError("Only one instance of Config is allowed.")
        super().save(*args, **kwargs)

    def __str__(self):
        return "Global Configuration"
    
class HuntsmanSuperDB:
    def __init__(self):
        self.base_url =  'http://superdb:9867'      
        self.headers = {'Accept': 'application/json','Content-Type': 'application/json'}    

    def load_data_to_branch(self, pool_id_or_name, branch_name, data, csv_delim=','):
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{branch_name}"
        params = {
            'csv.delim': csv_delim
        }
        try:         
            response = requests.post(url, headers=self.headers, data=data)
            response.raise_for_status()  
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error loading data to branch: {e}")
            return None

    def get_branch_info(self, pool_id_or_name, branch_name):
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{branch_name}"

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()  
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error getting branch info: {e}")
            return None

    def delete_branch(self, pool_id_or_name, branch_name):
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{branch_name}"

        try:
            response = requests.delete(url)
            response.raise_for_status()  
            if response.status_code == 204:
                print(f"Branch '{branch_name}' deleted successfully.")
            else:
                print(f"Unexpected response: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error deleting branch: {e}")

    def delete_data_from_branch(self, pool_id_or_name, branch_name, object_ids=None, where=None):
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{branch_name}/delete"
        payload = {}
        if object_ids:
            payload['object_ids'] = object_ids
        if where:
            payload['where'] = where

        try:
            response = requests.post(url, headers=self.headers, data=json.dumps(payload))
            response.raise_for_status() 
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error deleting data from branch: {e}")
            return None

    def merge_branches(self, pool_id_or_name, destination_branch, source_branch):
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{destination_branch}/merge/{source_branch}"

        try:
            response = requests.post(url, headers=self.headers)
            response.raise_for_status() 
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error merging branches: {e}")
            return None

    def revert_commit(self, pool_id_or_name, branch_name, commit_id):
        url = f"{self.base_url}/pool/{pool_id_or_name}/branch/{branch_name}/revert/{commit_id}"

        try:
            response = requests.post(url, headers=self.headers)
            response.raise_for_status() 
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error reverting commit: {e}")
            return None

    def create_pool(self, name, layout_order='asc', layout_keys=[['ts']], thresh=None):
        url = f"{self.base_url}/pool"
        payload = {
            'name': name,
            'layout': {
                'order': layout_order,
                'keys': layout_keys
            }
        }
        if thresh is not None:
            payload['thresh'] = thresh

        try:
            response = requests.post(url, headers=self.headers, data=json.dumps(payload))
            response.raise_for_status() 
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error creating pool: {e}")
            return None

    def vacuum_pool(self, pool_id_or_name, revision, dryrun=False):
        url = f"{self.base_url}/pool/{pool_id_or_name}/revision/{revision}/vacuum"
        params = {
            'dryrun': 'T' if dryrun else 'F'
        }

        try:
            response = requests.post(url, headers=self.headers, params=params)
            response.raise_for_status()  

            if response.status_code == 200:
                data = response.json()
                if dryrun:
                    print("Objects that could be vacuumed:")
                    for obj in data.get('objects', []):
                        print(obj)
                else:
                    print("Pool vacuumed successfully.")
            else:
                print(f"Unexpected response: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error vacuuming pool: {e}")

    def execute_query(self, query, pool=None, branch='main', ctrl='F'):
        url = f"{self.base_url}/query"
        params = {'ctrl': ctrl}
        payload = {'query': query}
        
        if pool:
            payload['head.pool'] = pool
        payload['head.branch'] = branch
    
        try:
            print(f"Sending request to {url} with params={params} and payload={payload}")
            
            response = requests.post(
                url, 
                headers=self.headers, 
                params=params, 
                data=json.dumps(payload)
            )
            print(f"Response Status: {response.status_code}")
            print(f"Response Text: {response.text}")
    
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error executing query: {e}")
            return None
    
class AbstractAnalyzer:
    def __init__(self, analyzer_name: str):
        self.analyzer_name = analyzer_name
        analyzer = Analyzer.objects.filter(name=analyzer_name).first()
        if analyzer is None:
            logger.warning(f"Analyzer '{analyzer_name}' not found")

        self.superDB_client = HuntsmanSuperDB()
        self.poolname = "ThreatData"
        
        self.base_url = analyzer.base_url
        self.api_key =  analyzer.api_key
        self.rate_limit = analyzer.rate_limit
        self.rate_limit_time_unit = analyzer.rate_limit_time_unit
        self.default_headers = {"accept": "application/json"}    
            
    def _is_valid_ipv6(self, ip_address):
        if not isinstance(ip_address, str):
            return False

        if ip_address.count(":") > 7 or ip_address.count(":") < 2:
            return False
        
        parts = ip_address.split(":")
        
        if "" in parts and parts.count("") > 2:
            return False
        
        if "" in parts and parts.count("") == 2 and parts[0] != "" and parts[-1] != "":
            return False
        
        for part in parts:
            if part == "":
                continue
            if len(part) > 4:
                return False
            try:
                int(part, 16)
            except ValueError:
                return False
        return True

    def _make_request(self, observable, endpoint="", preffix_endpoint="", suffix_endpoint="", method="GET", data_json=None, params=None, payload=None, files=None):
        url = f"{self.base_url}{preffix_endpoint}{endpoint}{suffix_endpoint}"
        if params is None:
            params = {}
        try:
            if method == "GET":
                response = requests.get(url, headers=self.default_headers, params=params)
            elif method == "POST":                
                response = requests.post(url, headers=self.default_headers, data=payload, json=data_json, files=files)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()  # Raise an exception for 4xx/5xx responses            
            return self._store_telemetry(method=method,observable=observable,task_id=self.task_id,response=response)
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {e}")
            return None

    def _store_telemetry(self, method, observable, task_id, response):
        telemetry_data = {}
        current_utc_time = datetime.now(timezone.utc)
        timestamp_iso = current_utc_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        try:
            response_body_json = response.json()
        except json.JSONDecodeError:
            try:
                import xmltodict 
                response_body_json = xmltodict.parse(response.content)
            except Exception as e:  
                response_body_json = {
                    "error": "Failed to decode JSON or XML",
                    "response_text": response.text[:1000] 
                }

        telemetry_data.update({
            "observable": observable,                      
            "rawData": response_body_json,
            "meta":{
                "ts": timestamp_iso,
                "taskId": task_id,
                "analyzerName": self.analyzer_name,
                "httpMethod": method,
                "statusCode": response.status_code,
                "responseTimeSec": response.elapsed.total_seconds(),
                },                          
        })
        
        return self.superDB_client.load_data_to_branch(self.poolname, "main", json.dumps(telemetry_data))

    def execute(self, observable, task_id):
        """
        To be implemented in child classes to define specific API logic.
        """
        raise NotImplementedError("Execute method must be implemented by the subclass.")
