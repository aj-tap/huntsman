import re
import uuid
from collections import defaultdict
from celery import shared_task
from .models import Analyzer, Playbook, HuntsmanSuperDB, Config, DetectionRule
from tldextract import extract
import requests
import logging
from stix2 import Indicator, Relationship, Report, Bundle, AutonomousSystem, IPv4Address, DomainName, URL, EmailAddress, IPv6Address, File, Location, Software, Vulnerability, Note, Infrastructure
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
import os
from datetime import datetime, timezone, timedelta
import time
import google.generativeai as genai
import asyncio
from .agent import setup_agent_runner, call_agent_async

logger = logging.getLogger(__name__)

CACHE_FILE = 'valid_tlds.txt'
CACHE_EXPIRATION_TIME = 86400 

ISO_COUNTRY_CODES = set([
    "US", "GB", "IN", "CN", "DE", "FR", "IT", "ES", "RU", "JP", "KR", "BR", "CA", "AU", "MX",
    "NL", "SE", "CH", "PL", "NO", "BE", "AT", "FI", "DK", "IE", "GR", "PT", "HU", "RO", "CZ", 
    "BG", "TR", "UA", "SK", "HR", "SI", "EE", "LV", "LT", "IS", "MT", "CY", "LU", "GE", "AM"
])


class TaskInvoker:
    def __init__(self):
        self.commands = {}

    def register(self, command_name, command):
        self.commands[command_name] = command

    def execute(self, command_name):
        command = self.commands.get(command_name)
        if command is None:
            raise ValueError(f"Command '{command_name}' not found")
        return command.execute()

def fetch_and_cache_valid_tlds(timeout=5):
    url = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()  
        tlds = response.text.splitlines()
        valid_tlds = set(tld.lower() for tld in tlds if tld and not tld.startswith("#"))
        with open(CACHE_FILE, 'w') as f:
            f.write("\n".join(valid_tlds))
        return valid_tlds
    except requests.exceptions.Timeout:
        print(f"Request timed out after {timeout} seconds.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error fetching TLD list: {e}")
        return set()

def load_valid_tlds():
    if os.path.exists(CACHE_FILE):
        file_age = time.time() - os.path.getmtime(CACHE_FILE)
        if file_age < CACHE_EXPIRATION_TIME:
            with open(CACHE_FILE, 'r') as f:
                tlds = f.read().splitlines()
            return set(tlds)
    return fetch_and_cache_valid_tlds()

VALID_TLDS = load_valid_tlds()

if not VALID_TLDS:
    VALID_TLDS = {
    "aaa", "aarp", "abarth", "abb", "abbott", "abbvie", "abc", "able", "abogado", "abudhabi", "academy",
    "accenture", "accountant", "accountants", "aco", "actor", "adac", "ads", "adult", "aeg", "aetna", "afl",
    "africa", "agakhan", "agency", "aig", "airbus", "airforce", "airtel", "akdn", "alibaba", "alipay", "allfinanz",
    "allstate", "ally", "alsace", "alstom", "amazon", "americanexpress", "americanfamily", "amex", "amfam",
    "amica", "amsterdam", "analytics", "android", "anquan", "anz", "aol", "apartments", "app", "apple",
    "aquarelle", "arab", "aramco", "archi", "army", "art", "arte", "asda", "asia", "associates", "athleta",
    "attorney", "auction", "audi", "audible", "audio", "auspost", "author", "auto", "autos", "avianca", "aws",
    "axa", "azure", "baby", "baidu", "banamex", "bananarepublic", "band", "bank", "bar", "barcelona", "barclaycard",
    "barclays", "barefoot", "bargains", "baseball", "basketball", "bauhaus", "bayern", "bbc", "bbt", "bbva",
    "bcg", "bcn", "beats", "beauty", "beer", "bentley", "berlin", "best", "bestbuy", "bet", "bharti", "bible",
    "bid", "bike", "bing", "bingo", "bio", "black", "blackfriday", "blanco", "blockbuster", "blog", "bloomberg",
    "blue", "bms", "bmw", "bnl", "bnpparibas", "boats", "boehringer", "bofa", "bom", "bond", "boo", "book",
    "booking", "bosch", "bostik", "boston", "bot", "boutique", "box", "bradesco", "bridgestone", "broadway",
    "broker", "brother", "brussels", "budapest", "bugatti", "build", "builders", "business", "buy", "buzz",
    "bzh", "cab", "cafe", "cal", "call", "calvinklein", "cam", "camera", "camp", "canon", "capetown", "capital",
    "capitalone", "car", "caravan", "cards", "care", "career", "careers", "cars", "casa", "case", "caseih",
    "cash", "casino", "catering", "catholic", "cba", "cbn", "cbre", "cbs", "ceb", "center", "ceo", "cern",
    "cfa", "cfd", "chanel", "channel", "charity", "chase", "chat", "cheap", "chintai", "chloe", "christmas",
    "chrome", "church", "cipriani", "circle", "cisco", "citadel", "citi", "citic", "city", "cityeats", "claims",
    "cleaning", "click", "clinic", "clinique", "clothing", "cloud", "club", "clubmed", "coach", "codes", "coffee",
    "college", "cologne", "com", "comcast", "commbank", "community", "company", "compare", "computer", "comsec",
    "condos", "construction", "consulting", "contact", "contractors", "cooking", "cool", "coop", "corsica",
    "country", "coupon", "coupons", "courses", "credit", "creditcard", "creditunion", "cricket", "crown",
    "crs", "cruise", "cruises", "csc", "cu", "cuisinella", "cymru", "cyou", "dabur", "dad", "dance", "data",
    "date", "dating", "datsun", "day", "dclk", "dds", "deal", "dealer", "deals", "degree", "delivery", "dell",
    "deloitte", "delta", "democrat", "dental", "dentist", "desi", "design", "dev", "dhl", "diamonds", "diet",
    "digital", "direct", "directory", "discount", "discover", "dish", "diy", "dnp", "docs", "doctor", "dog",
    "domains", "dot", "download", "drive", "dtv", "dubai", "duck", "dunlop", "dupont", "durban", "dvag", "dvr",
    "earth", "eat", "eco", "edeka", "education", "email", "emerck", "energy", "engineer", "engineering",
    "enterprises", "epson", "equipment", "ericsson", "erni", "esq", "estate", "etisalat", "eu", "eurovision",
    "eus", "events", "exchange", "expert", "exposed", "express", "extraspace", "fage", "fail", "fairwinds",
    "faith", "family", "fan", "fans", "farm", "fashion", "fast", "fedex", "feedback", "ferrari", "ferrero",
    "fiat", "fidelity", "fido", "film", "final", "finance", "financial", "fire", "firestone", "firmdale", "fish",
    "fishing", "fit", "fitness", "flickr", "flights", "flir", "florist", "flowers", "fly", "foo", "food",
    "foodnetwork", "football", "ford", "forex", "forsale", "forum", "foundation", "fox", "free", "fresenius",
    "frl", "frogans", "frontdoor", "frontier", "ftr", "fujitsu", "fun", "fund", "furniture", "futbol", "fyi"
}

def find_iocs_regex(text, max_iocs_per_type=10):
    patterns = {
        "ipv4s": r'\b(?<!\d\.)(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b(?!\.\d|[^\s.,;()\[\]{}<>])',
        "asns": r"\b(?:AS\s?|ASN)\d{1,10}\b",
        "ipv6s": r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        "domains": r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
        "sha256s": r'\b[0-9a-fA-F]{64}\b',
        "email_addresses": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        "country_codes": r'\b[A-Z]{2}\b',
        "cpes": r'cpe:/[aho]:[a-zA-Z0-9._-]+:[a-zA-Z0-9._:-]*',
        "vulns": r'CVE-\d{4}-\d{4,7}',
        "jarm": r'\b[a-f0-9]{62}\b',
        "ja3": r'\b[a-f0-9]{32}\b',
    }
    
    iocs = defaultdict(list)
    
    for ioc_type, pattern in patterns.items():
        matches = re.findall(pattern, text)
        
        if ioc_type == "country_codes":
            filtered_matches = [m for m in matches if m in ISO_COUNTRY_CODES]
            iocs[ioc_type].extend(filtered_matches[:max_iocs_per_type])
        
        elif ioc_type == "domains":
            filtered_domains = []
            for domain in matches:
                domain = domain.strip(".,;()[]{}<>")                
                extracted = extract(domain)
                if extracted.suffix in VALID_TLDS:
                    filtered_domains.append(domain)
                    
            iocs[ioc_type].extend(filtered_domains[:max_iocs_per_type])
        
        elif ioc_type in {"sha256s", "jarm", "ja3"}:
            filtered_hashes = [h for h in matches if text.lower().count(h) > 0]
            iocs[ioc_type].extend(filtered_hashes[:max_iocs_per_type])
        
        else:
            iocs[ioc_type].extend(matches[:max_iocs_per_type])
    
    return iocs

def process_report(report, seen_observables):
    report_name = report.get("ReportName", "Unnamed Report")
    raw_data = report.get("rawData", "")
    observable = report.get("observable", "Unknown")

    try:
        iocs = find_iocs_regex(str(raw_data))
    except Exception as e:
        logging.error(f"Error extracting IOCs: {e}")
        return None, None

    stix_observables = []
    current_refs = []

    if report_name.lower() == "virustotal":
        ioc_handlers = {
            "ipv4s": lambda ioc: IPv4Address(value=ioc),
            "ipv6s": lambda ioc: IPv6Address(value=ioc),
            "domains": lambda ioc: DomainName(value=ioc),
            "sha256s": lambda ioc: File(name=ioc,hashes={"SHA-256": ioc}),
            "asns": lambda ioc: AutonomousSystem(number=int(ioc[3:]), name=ioc) if ioc.startswith("ASN") else None,
            "email_addresses": lambda ioc: EmailAddress(value=ioc),
            "country_codes": lambda ioc: Location(name=ioc, country=ioc),
            "ja3": lambda ioc: Infrastructure(name=f"{ioc}", description=f"JA3 Fingerprint: {ioc}"),
            "jarm": lambda ioc: Infrastructure(name=f"{ioc}", description=f"JARM Fingerprint: {ioc}"),      
        }
        logging.info(f"Processing report: {report_name}")
    elif report_name.lower() == "abuseipdb":
        ioc_handlers = {
            "ipv4s": lambda ioc: IPv4Address(value=ioc),
            "ipv6s": lambda ioc: IPv6Address(value=ioc),
            "domains": lambda ioc: DomainName(value=ioc),
            "asns": lambda ioc: AutonomousSystem(number=int(ioc[3:]), name=ioc) if ioc.startswith("ASN") else None,
            "emails": lambda ioc: EmailAddress(value=ioc),
        }
        logging.info(f"Processing report: {report_name}")
    else:
        ioc_handlers = {
            "ipv4s": lambda ioc: IPv4Address(value=ioc),
            "ipv6s": lambda ioc: IPv6Address(value=ioc),
            "domains": lambda ioc: DomainName(value=ioc),
            "sha256s": lambda ioc: File(name=ioc,hashes={"SHA-256": ioc}),
            "asns": lambda ioc: AutonomousSystem(number=int(ioc[3:]), name=ioc),
            "email_addresses": lambda ioc: EmailAddress(value=ioc),
            "country_codes": lambda ioc: Location(name=ioc, country=ioc),
            "cpes": lambda ioc: Software(type="software", name=ioc.split(":")[2], cpe=ioc),
            "vulns": lambda ioc: Vulnerability(name=ioc, id=f"vulnerability--{uuid.uuid4()}"),
            "ja3": lambda ioc: Infrastructure(name=f"{ioc}", description=f"JA3 Fingerprint: {ioc}"),
            "jarm": lambda ioc: Infrastructure(name=f"{ioc}", description=f"JARM Fingerprint: {ioc}"),
        }

    batch_observables = {}  

    for ioc_type, ioc_list in iocs.items():
        if ioc_type not in ioc_handlers:
            continue

        for ioc in set(ioc_list):
            if ioc in seen_observables:
                current_refs.append(seen_observables[ioc].id)
                continue

            if validate_ioc(ioc, ioc_type): 
                try:
                    handler = ioc_handlers.get(ioc_type)
                    stix_obj = handler(ioc) if handler else None
                    if stix_obj:
                        stix_observables.append(stix_obj)
                        batch_observables[ioc] = stix_obj
                        current_refs.append(stix_obj.id)
                except Exception as e:
                    logging.error(f"Error creating STIX object for {ioc}: {e}")

    seen_observables.update(batch_observables)

    if current_refs:
        try:
            report_obj = Report(
                name=f"{report_name}: {observable}",
                report_types=["observed-data"],
                description=str(raw_data),
                published=datetime.now(timezone.utc),                
                object_refs=current_refs,
            )
            return report_obj, stix_observables
        except Exception as e:
            logging.error(f"Error creating STIX report: {e}")
            return None, stix_observables

    return None, stix_observables

def validate_ioc(ioc, ioc_type):
    if ioc_type == "ipv4s":
        ipv4_regex = r"^(?!10\.\d{1,3}\.\d{1,3}\.\d{1,3}$)(?!172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$)(?!192\.168\.\d{1,3}\.\d{1,3}$)(?!127\.\d{1,3}\.\d{1,3}\.\d{1,3}$)(?!169\.254\.\d{1,3}\.\d{1,3}$)(?!224\.\d{1,3}\.\d{1,3}\.\d{1,3}$)(?!233\.\d{1,3}\.\d{1,3}\.\d{1,3}$)(?!240\.\d{1,3}\.\d{1,3}\.\d{1,3}$)(?!255\.\d{1,3}\.\d{1,3}\.\d{1,3}$)(?=\d{1,3}(\.\d{1,3}){3}$)(?!255\.)\d{1,3}(\.\d{1,3}){3}$"
        if re.match(ipv4_regex, ioc):
            octets = ioc.split(".")
            if all(0 <= int(octet) <= 255 for octet in octets):
                return True
        return False 

    elif ioc_type == "domains":
        if ioc.endswith((".crt", ".crl", ".png")):
            return False
            
        benign_domains = [
            "github.com", "www.virustotal.com", "rdap.arin.net", "example.com", "localhost", 
            "test.com", "alphaMountain.ai", "benkow.cc", "Bfore.Ai", "desenmascara.me", 
            "Dr.Web", "Hunt.io", "malwares.com", "SCUMWARE.org", "whois.domaintools.com", "otx.alienvault.com", "whois.arin.net", "whois.apnic.net", "www.iana.org", "www.arin.net", 
            "imgs.search.brave.com", "IPinfo.io", "ipinfo.io", "urlscan.io"
        ]
        if ioc in benign_domains:
            return False
                
    return True  

@shared_task(name="create_stix")
def create_stix(task_ids):
    now_utc = datetime.now(timezone.utc)
    timeframe = now_utc - timedelta(minutes=5)            
    start_time_str = timeframe.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    end_time_str = now_utc.strftime('%Y-%m-%dT%H:%M:%S.%fZ')           
    time_filter = f"meta.ts >= '{start_time_str}' and meta.ts <= '{end_time_str}'"             
    task_conditions = " or ".join([f"meta.taskId=='{tid}'" for tid in task_ids.split(",")])
    query = f"from 'ThreatData' | {time_filter} | ({task_conditions}) | cut observable, ReportName:=meta.analyzerName, rawData"
    
    superDB_client = HuntsmanSuperDB()
    raw_reports = superDB_client.execute_query(query=query)

    if not isinstance(raw_reports, list):
        logging.error("Expected a list of reports.")
        return "Invalid data format. Expected a list of dictionaries."

    seen_observables = {}
    stix_reports = []
    stix_observables = []
    errors = []

    CHUNK_SIZE = 20
    report_chunks = [raw_reports[i:i + CHUNK_SIZE] for i in range(0, len(raw_reports), CHUNK_SIZE)]

    with ThreadPoolExecutor(max_workers=8) as executor:
        for chunk in report_chunks:
            process_func = partial(process_report, seen_observables=seen_observables)  

            results = list(executor.map(process_func, chunk))  

            for report, observables in results:
                if report:
                    stix_reports.append(report)
                if observables:
                    stix_observables.extend(observables)
    try:
        bundle = Bundle(objects=stix_observables + stix_reports)
        superDB_client.load_data_to_branch("StixObjects", "main", bundle.serialize(pretty=False))
        return bundle.serialize(pretty=False)
    except Exception as e:
        logging.error(f"Error creating STIX bundle: {e}")
        errors.append(str(e))
    if errors:
        logging.error(f"Errors encountered: {errors}")
    return "STIX bundle creation completed with errors." if errors else "STIX bundle successfully created."

@shared_task(name="create_task_analyzer")
def create_task_analyzer(playbook_id: int, raw_string: str, observable_type: str):
    task_id = create_task_analyzer.request.id
    try:
        playbook = Playbook.objects.get(id=playbook_id)
    except Playbook.DoesNotExist:
        raise ValueError(f"Playbook with ID {playbook_id} not found")
    invoker = TaskInvoker()
    results = {}
    for analyzer in playbook.analyzers.all():
        try:
            analyzer_instance = analyzer.get_module_instance(
                ioctype=observable_type,
                observable=raw_string,
                task_id=task_id
            )
            invoker.register(f"{analyzer.name}:{observable_type}", analyzer_instance)

        except Exception as e:
            error_msg = f"Error initializing analyzer {analyzer.name} for {observable_type}: {e}"                    
            results[f"{analyzer.name}:{observable_type}"] = error_msg
    for command_name in invoker.commands.keys():
        try:
            results[command_name] = invoker.execute(command_name)
        except Exception as e:
            results[command_name] = f"Error executing {command_name}: {e}"
    return results

@shared_task
def execute_superdb_query(query):
    superDB_client = HuntsmanSuperDB()
    return superDB_client.execute_query(query=query)

def preprocess_data(data_str: str, reduction_percentage: float = 0.3) -> str:
    cleaned_data = re.sub(r'[^\w\s:/,.-]', '', data_str)
    words = cleaned_data.split()
    reduced_size = int(len(words) * reduction_percentage)
    processed_data = ' '.join(words[:reduced_size])
    
    return processed_data

@shared_task(name="get_ai_insights")
def get_ai_insights(task_ids):
    task_ids_list = task_ids if isinstance(task_ids, list) else task_ids.split(",")
    all_generated_insights = [] 

    try:
        config = Config.objects.first()
        if config and config.gemini_api:
            gemini_api_key = config.gemini_api
            os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"
            os.environ["GOOGLE_API_KEY"] = gemini_api_key
    except Config.DoesNotExist:
        raise ValueError("Gemini configuration not found in Config model.")    

    try:
        runner, user_id, session_id = setup_agent_runner()
        if not runner: 
             raise ValueError("Agent Runner setup failed.")
        print("Agent runner setup successful.")
    except Exception as e:
        print(f"FATAL: Failed to setup agent runner: {e}")
        return {"error": "Agent setup failed", "details": str(e)} 

    for task_id in task_ids_list:
        query = f"from 'ThreatData' | meta.taskId=='{task_id}' | cut rawData "
        superDB_client = HuntsmanSuperDB()
        data = superDB_client.execute_query(query=query)        
        processed_data_chunk = str(data)  
        processed_data_chunk = preprocess_data(processed_data_chunk)[:8000] 
        queries_to_agent = [
                f"Review the following raw json data. Focus on successful results. Identify any potential cyber threats, anomalies, or threat actor activity. Summarize findings and recommend actionable next steps:\n\n{processed_data_chunk}",
                 "Perform a targeted news and threat feed search based on the provided data. Identify any recent incidents, campaigns, or relevant threat actor activities. Summarize findings in bullet style."
            ]
        aggregated_response = ""
        print(f"Calling Agent for task {task_id}...")
        for agent_query in queries_to_agent:
            try:
                response_string = asyncio.run(call_agent_async(
                    query=agent_query,
                    runner=runner,
                    user_id=user_id,  
                    session_id=session_id
                ))
                print(f"  - Agent response received for query: '{agent_query[:50]}...'")                
                aggregated_response += f"{response_string}\n\n---\n\n"
            except Exception as agent_error:
                    print(f"ERROR calling agent for task {task_id}: {agent_error}")
                    aggregated_response += f"Query: {agent_query}\nResponse: Error - {agent_error}\n\n---\n\n"

        if not aggregated_response:
                print(f"Warning: No response aggregated from agent for task {task_id}")
                aggregated_response = "Agent did not provide a response."

        current_utc_time = datetime.now(timezone.utc)
        timestamp_str = current_utc_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        all_generated_insights.append({            
            "description": aggregated_response.strip(),            
            "meta": {
                "ts": timestamp_str,
                "taskId": task_id,
                "analyzerName": "ai-insight",
                "aiInsightTaskId": get_ai_insights.request.id,
                "model": "gemini-2.0-flash",
            }
        })

    for insight in all_generated_insights:        
        superDB_client.load_data_to_branch("AIInsights", "main", json.dumps(insight))

    return all_generated_insights

@shared_task(name="run_detections")
def run_detections(task_ids):
    if isinstance(task_ids, str):
        task_ids_list = [tid.strip() for tid in task_ids.split(",") if tid.strip()]
    elif isinstance(task_ids, list):
        task_ids_list = [str(tid).strip() for tid in task_ids if str(tid).strip()]
    else:
        return {"error": "Invalid format for task_ids"}

    if not task_ids_list:
         return {"error": "No valid task IDs provided."}

    try:
        now_utc = datetime.now(timezone.utc)
        timeframe = now_utc - timedelta(minutes=5)
        start_time_str = timeframe.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        end_time_str = now_utc.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        time_filter = f"meta.ts >= '{start_time_str}' and meta.ts <= '{end_time_str}'"
        task_conditions = " or ".join([f"meta.taskId=='{task_id}'" for task_id in task_ids_list])
        
        base_filters = f"{time_filter} and ({task_conditions})" 

        try:
            detection_rules = list(DetectionRule.objects.all()) # Fetch all rules into memory
        except Exception as db_err:
             logger.error(f"Error fetching detection rules: {db_err}")
             return {"error": f"Could not retrieve detection rules: {db_err}"}

        if not detection_rules:
            return {"message": "No detection rules found in the database."}

        hits = []
        superDB_client = HuntsmanSuperDB() 
        tasks_to_submit = []
        for rule in detection_rules:
            if rule.syntax and rule.syntax.strip():
                 final_query = f"from 'ThreatData' | {base_filters} | {rule.syntax.strip()} | cut observable | quiet(this)"
                 tasks_to_submit.append((rule, final_query))
            else:
                 logger.warning(f"Skipping rule '{rule.title}' (ID: {rule.id}) due to empty syntax.")

        max_workers = min(10, len(tasks_to_submit)) 
        
        if max_workers > 0: 
             futures = {}
             with ThreadPoolExecutor(max_workers=max_workers) as executor:
                 for rule, query_str in tasks_to_submit:
                     logger.info(f"Submitting query for rule: {rule.title}")
                     future = executor.submit(superDB_client.execute_query, query=query_str)
                     futures[future] = rule 

                 for future in as_completed(futures):
                     rule = futures[future] 
                     try:
                         data = future.result() 
                         if data and len(data) > 0:
                              logger.info(f"Hit found for rule: {rule.title}")
                              hits.append({
                                  "rule_title": rule.title,
                                  "rule_description": rule.description,
                                  "hits": data
                              })
                     except Exception as exc:
                         logger.error(f"Query for rule '{rule.title}' generated an exception: {exc}")
        if not hits:
            return {"message": "No detection rules matched."}
        return {"results": hits}

    except Exception as e:
        logger.exception(f"An unexpected error occurred in run_detections: {e}") 
        return {"error": f"An unexpected error occurred: {str(e)}"}

