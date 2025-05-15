import os
import django
import logging
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction 
from dotenv import load_dotenv
import yaml 
import glob


load_dotenv()


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')


django.setup()



from hunt.models import Analyzer, ObservableType, QueriesTemplate, Config, DetectionRule, Playbook


GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

API_KEYS = {
    "abuseipdb": os.environ.get("ABUSEIPDB_API_KEY", None),
    "virustotal": os.environ.get("VIRUSTOTAL_API_KEY", None),
    "alienvault": os.environ.get("ALIENVAULT_API_KEY", None),
    "bravesearch": os.environ.get("BRAVESEARCH_API_KEY", None),
    "shodan": os.environ.get("SHODAN_API_KEY", None),
    "ipinfo": os.environ.get("IPINFO_API_KEY", None),
    "proxycheckio": os.environ.get("PROXYCHECKIO_API_KEY", None),
    "threatfox": os.environ.get("THREATFOX_API_KEY", None),
    "malwarebazaar": os.environ.get("MALWAREBAZAAR_API_KEY", None),
    "urlhaus": os.environ.get("URLHAUS_API_KEY", None),
    "urlscanio": os.environ.get("URLSCANIO_API_KEY", None),
    "github": os.environ.get("GITHUB_API_KEY", None),
    "wildfire": os.environ.get("WILDFIRE_API_KEY", None),
    "crowdsec": os.environ.get("CROWDSEC_API_KEY", None),
    "misp": os.environ.get("MISP_API_KEY", None),
}

ANALYZERS = [
    {"name": "internetdb", "base_url": "https://internetdb.shodan.io/", "api_key": None},
    {"name": "bgpview", "base_url": "https://api.bgpview.io/", "api_key": None},    
    {"name": "abuseipdb", "base_url": "https://api.abuseipdb.com/api/v2/", "api_key": "abuseipdb"},
    {"name": "virustotal", "base_url": "https://www.virustotal.com/api/v3/", "api_key": "virustotal"},
    {"name": "alienvault", "base_url": "https://otx.alienvault.com/api/v1/", "api_key": "alienvault"},
    {"name": "bravesearch", "base_url": "https://api.search.brave.com/res/v1/web/search", "api_key": "bravesearch"},
    {"name": "whois", "base_url": None, "api_key": None},
    {"name": "dnsresolver", "base_url": None, "api_key": None},
    {"name": "certificatesearch", "base_url": "https://crt.sh/", "api_key": None},
    {"name": "shodan", "base_url": "https://api.shodan.io/", "api_key": "shodan"},
    {"name": "ipinfo", "base_url": "https://ipinfo.io/", "api_key": "ipinfo"},
    {"name": "proxycheckio", "base_url": "http://proxycheck.io/v2/", "api_key": "proxycheckio"},
    {"name": "spurus", "base_url": "https://spur.us/context/", "api_key": None},
    {"name": "threatfox", "base_url": "https://threatfox-api.abuse.ch/api/v1/", "api_key": "threatfox"},
    {"name": "malwarebazaar", "base_url": "https://mb-api.abuse.ch/api/v1/", "api_key": "malwarebazaar"},
    {"name": "urlhaus", "base_url": "https://urlhaus-api.abuse.ch/v1/", "api_key": "urlhaus"},
    {"name": "urlscanio", "base_url": "https://urlscan.io/api/v1/", "api_key": "urlscanio"},
    {"name": "internetstormcast", "base_url": "https://isc.sans.edu/api/", "api_key": None},
    {"name": "github", "base_url": "https://api.github.com/", "api_key": "github"},
    {"name": "wildfire", "base_url": "https://wildfire.paloaltonetworks.com/publicapi/", "api_key": "wildfire"},
    {"name": "crowdsec", "base_url": "https://cti.api.crowdsec.net/v2/", "api_key": "crowdsec"},
    {"name": "misp", "base_url": "https://misp/events/restSearch", "api_key": "misp"},
]

OBSERVABLE_TYPES = [
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
    ("freetext", "FreeText"),
]

@transaction.atomic
def populate_analyzers():
    """Populates the Analyzer model."""
    logger.info("Populating Analyzer model...")
    analyzers_processed_count = 0
    analyzers_created_count = 0
    for analyzer_data in ANALYZERS:
        try:
            api_key_name = analyzer_data.get("api_key") 
            api_key = API_KEYS.get(api_key_name) if api_key_name else None
            description = analyzer_data.get("description", f"Analyzer for {analyzer_data['name']}, providing integration with {analyzer_data['name'].capitalize()} services.")
            rate_limit = analyzer_data.get("rate_limit", 1000)
            rate_limit_time_unit = analyzer_data.get("rate_limit_time_unit", 'minute')
            plugin_settings = analyzer_data.get("plugin_settings", {})
            base_url = analyzer_data.get("base_url") 

            
            defaults_dict = {
                    "description": description,
                    "api_key": api_key,
                    "base_url": base_url,
                    "plugin_settings": plugin_settings,
                    "analyzer_module": None, 
                    "rate_limit": rate_limit,
                    "rate_limit_time_unit": rate_limit_time_unit,
            }

            analyzer, created = Analyzer.objects.update_or_create(
                name=analyzer_data["name"],
                defaults=defaults_dict,
            )
            analyzers_processed_count += 1

            
            if analyzer and analyzer.pk:
                if created:
                    logger.info(f"  Successfully CREATED Analyzer: {analyzer_data['name']} (PK: {analyzer.pk})")
                    analyzers_created_count += 1
                else:
                    logger.info(f"  Successfully UPDATED/Verified Analyzer: {analyzer_data['name']} (PK: {analyzer.pk})")
            else:
                 logger.error(f"  FAILED to create/update Analyzer: {analyzer_data['name']} - Object or PK not found after operation.")
            

        except IntegrityError as e:
            logger.error(f"Integrity error processing analyzer {analyzer_data['name']}: {e}")
        except ValidationError as e:
            logger.error(f"Validation error processing analyzer {analyzer_data['name']}: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error processing analyzer {analyzer_data['name']}: {e}") 

    logger.info(f"Finished populating analyzers. Processed: {analyzers_processed_count}, Created: {analyzers_created_count}")



def populate_observable_types():
    """Populates the ObservableType model."""
    logger.info("Populating ObservableType model...")
    observable_types_created_count = 0
    for name, display_name in OBSERVABLE_TYPES:
        try:
            
            obj, created = ObservableType.objects.get_or_create(name=name)
            if created:
                logger.info(f"ObservableType created: {name}")
                observable_types_created_count += 1
            else:
                logger.info(f"ObservableType already exists: {name}")
        except IntegrityError as e:
            logger.error(f"Integrity error creating ObservableType {name}: {e}")
        except ValidationError as e:
            logger.error(f"Validation error creating ObservableType {name}: {e}")
        except Exception as e:
            logger.exception(f"Error creating ObservableType {name}: {e}")
    logger.info(f"Finished populating observable types. Created: {observable_types_created_count}")



def populate_config():
    """Populates the Config model with default values."""
    logger.info("Populating Config model...")
    try:
        
        config, created = Config.objects.update_or_create(
            pk=1, 
            defaults={
                "gemini_api": GEMINI_API_KEY
            }
        )
        if created:
            logger.info("Config created.")
        else:
            logger.info("Config updated or already exists.")
    except IntegrityError as e:
        logger.error(f"Integrity error creating/updating Config: {e}")
    except ValidationError as e:
        logger.error(f"Validation error creating/updating Config: {e}")
    except Exception as e:
        logger.exception(f"Error creating/updating Config: {e}")


def populate_detection_rules(rules_dir):
    """Populates the DetectionRule model from YAML files."""
    logger.info("Populating DetectionRule model from YAML files...")
    yaml_files = glob.glob(os.path.join(rules_dir, "*.yaml"))
    if not yaml_files:
        logger.warning(f"No YAML files found in {rules_dir}. Skipping DetectionRule population.")
        return

    for yaml_file in yaml_files:
        try:
            with open(yaml_file, 'r') as f:
                rules_data = yaml.safe_load(f)
                
                if isinstance(rules_data, dict):
                    rules_data = [rules_data] 
                elif not isinstance(rules_data, list):
                     logger.error(f"Invalid YAML format in {yaml_file}: Expected a dict or list of rules.")
                     continue

                for rule_data in rules_data:
                    title = rule_data.get('title')
                    description = rule_data.get('description', '')
                    syntax = rule_data.get('syntax')
                    tags = rule_data.get('tags', '') 

                    if not title or not syntax:
                        logger.error(f"Skipping rule in {yaml_file}: Missing title or syntax.")
                        continue
                    try:
                        
                        defaults_dict = {
                                'description': description,
                                'syntax': syntax,
                                'tags': tags,
                        }
                        rule, created = DetectionRule.objects.update_or_create(
                            title=title,
                            defaults=defaults_dict
                        )
                        if created:
                            logger.info(f"Created new DetectionRule: {title}")
                        else:
                            logger.info(f"Updated existing DetectionRule: {title}")
                    except IntegrityError as e:
                        logger.error(f"Integrity error creating/updating DetectionRule {title}: {e}")
                    except ValidationError as e:
                        logger.error(f"Validation error creating/updating DetectionRule {title}: {e}")
                    except Exception as e:
                        logger.exception(f"Error creating/updating DetectionRule {title}: {e}")
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML in {yaml_file}: {e}")
        except FileNotFoundError:
            logger.error(f"File not found: {yaml_file}")
        except Exception as e:
            logger.exception(f"Error processing YAML file {yaml_file}: {e}")


def populate_queries_templates(queries_dir):
    """Populates the QueriesTemplate model from YAML files."""
    logger.info("Populating QueriesTemplate model from YAML files...")
    yaml_files = glob.glob(os.path.join(queries_dir, "*.yaml"))
    if not yaml_files:
        logger.warning(f"No YAML files found in {queries_dir}. Skipping QueriesTemplate population.")
        return

    for yaml_file in yaml_files:
        try:
            with open(yaml_file, 'r') as f:
                queries_data = yaml.safe_load(f)
                
                if isinstance(queries_data, dict):
                     queries_data = [queries_data] 
                elif not isinstance(queries_data, list):
                     logger.error(f"Invalid YAML format in {yaml_file}: Expected a dict or list of queries.")
                     continue

                for query_data in queries_data:
                    title = query_data.get('title')
                    query_string = query_data.get('query_string')

                    if not title or not query_string:
                        logger.error(f"Skipping query in {yaml_file}: Missing title or query_string.")
                        continue
                    try:
                        
                        defaults_dict = {
                                'query_string': query_string,
                        }
                        query, created = QueriesTemplate.objects.update_or_create(
                            title=title,
                            defaults=defaults_dict
                        )
                        if created:
                            logger.info(f"Created new QueriesTemplate: {title}")
                        else:
                            logger.info(f"Updated existing QueriesTemplate: {title}")
                    except IntegrityError as e:
                        logger.error(f"Integrity error creating/updating QueriesTemplate {title}: {e}")
                    except ValidationError as e:
                        logger.error(f"Validation error creating/updating QueriesTemplate {title}: {e}")
                    except Exception as e:
                        logger.exception(f"Error creating/updating QueriesTemplate {title}: {e}")
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML in {yaml_file}: {e}")
        except FileNotFoundError:
            logger.error(f"File not found: {yaml_file}")
        except Exception as e:
            logger.exception(f"Error processing YAML file {yaml_file}: {e}")



def populate_playbooks_from_yaml(playbooks_dir):
    """Populates the Playbook model from YAML files and links Analyzers and Observable Types."""
    logger.info("Populating Playbook model from YAML files...")

    
    try:
        all_analyzers = {analyzer.name: analyzer for analyzer in Analyzer.objects.all()}
        logger.info(f"Found {len(all_analyzers)} analyzers in DB before linking.")
    except Exception as e:
        logger.error(f"Could not fetch Analyzers from database: {e}. Analyzer linking will be skipped.")
        all_analyzers = {} 

    try:
        all_observable_types = {obs_type.name: obs_type for obs_type in ObservableType.objects.all()}
        logger.info(f"Found {len(all_observable_types)} observable types in DB before linking.")
    except Exception as e:
        logger.error(f"Could not fetch ObservableTypes from database: {e}. Observable type linking will be skipped.")
        all_observable_types = {} 

    if not all_analyzers:
         logger.warning("  WARNING: No Analyzers found in the database (or failed to fetch). Cannot link analyzers to playbooks.")
    if not all_observable_types:
         logger.warning("  WARNING: No ObservableTypes found in the database (or failed to fetch). Cannot link observable types to playbooks.")

    yaml_files = glob.glob(os.path.join(playbooks_dir, "*.yaml"))
    if not yaml_files:
        logger.warning(f"No YAML files found in {playbooks_dir}. Skipping Playbook population.")
        return

    for yaml_file in yaml_files:
        logger.info(f"Processing playbook file: {yaml_file}")
        try:
            with open(yaml_file, 'r') as f:
                playbooks_data = yaml.safe_load(f)
                
                if isinstance(playbooks_data, dict):
                     playbooks_data = [playbooks_data]
                elif not isinstance(playbooks_data, list):
                     logger.error(f"Invalid YAML format in {yaml_file}: Expected a dict or list of playbooks.")
                     continue

                for pb_data in playbooks_data:
                    playbook_definition = pb_data.copy() 
                    analyzer_names = playbook_definition.pop("analyzer_names", []) 
                    observable_type_names = playbook_definition.pop("observable_type_names", []) 
                    playbook_name = playbook_definition.get("name")
                    description = playbook_definition.get("description", "")

                    if not playbook_name:
                        logger.error(f"Skipping playbook in {yaml_file}: Missing 'name'.")
                        continue

                    try:
                        
                        defaults_dict = {
                                'description': description,
                        }
                        playbook, created = Playbook.objects.update_or_create(
                            name=playbook_name,
                            defaults=defaults_dict
                        )

                        if created:
                            logger.info(f"  Created playbook: {playbook.name} (PK: {playbook.pk})") 
                        else:
                            logger.info(f"  Found existing playbook, updated: {playbook.name} (PK: {playbook.pk})") 

                        
                        analyzers_to_link = []
                        missing_analyzers = []
                        if all_analyzers: 
                            if not isinstance(analyzer_names, list):
                                logger.warning(f"    WARNING: 'analyzer_names' for playbook '{playbook.name}' is not a list. Skipping linking.")
                            else:
                                for name in analyzer_names:
                                    analyzer = all_analyzers.get(name)
                                    if analyzer:
                                        analyzers_to_link.append(analyzer)
                                    else:
                                        missing_analyzers.append(name)

                            if missing_analyzers:
                                logger.warning(f"    WARNING: Could not find analyzers for playbook '{playbook.name}': {', '.join(missing_analyzers)}")

                            playbook.analyzers.set(analyzers_to_link) 
                            if analyzers_to_link:
                                linked_names = [a.name for a in analyzers_to_link]
                                logger.info(f"    Linked {len(analyzers_to_link)} analyzers: {', '.join(linked_names)}")
                            else:
                                logger.info(f"    No analyzers specified or found to link for {playbook.name}.")
                        else:
                            logger.info(f"    Skipping analyzer linking for {playbook.name} as no analyzers were found/fetched.")

                        
                        observable_types_to_link = []
                        missing_observable_types = []
                        if all_observable_types: 
                            if not isinstance(observable_type_names, list):
                                logger.warning(f"    WARNING: 'observable_type_names' for playbook '{playbook.name}' is not a list. Skipping linking.")
                            else:
                                for name in observable_type_names:
                                    obs_type = all_observable_types.get(name)
                                    if obs_type:
                                        observable_types_to_link.append(obs_type)
                                    else:
                                        missing_observable_types.append(name)

                            if missing_observable_types:
                                logger.warning(f"    WARNING: Could not find observable types for playbook '{playbook.name}': {', '.join(missing_observable_types)}")

                            playbook.observable_types.set(observable_types_to_link) 
                            if observable_types_to_link:
                                linked_names = [ot.name for ot in observable_types_to_link]
                                logger.info(f"    Linked {len(observable_types_to_link)} observable types: {', '.join(linked_names)}")
                            else:
                                logger.info(f"    No observable types specified or found to link for {playbook.name}.")
                        else:
                            logger.info(f"    Skipping observable type linking for {playbook.name} as no observable types were found/fetched.")


                    except IntegrityError as e:
                        logger.error(f"Integrity error processing playbook {playbook_name}: {e}")
                    except ValidationError as e:
                        logger.error(f"Validation error processing playbook {playbook_name}: {e}")
                    except Exception as e:
                        logger.exception(f"Unexpected error processing playbook {playbook_name}: {e}")

        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML in {yaml_file}: {e}")
        except FileNotFoundError:
            logger.error(f"File not found: {yaml_file}")
        except Exception as e:
            logger.exception(f"Error processing playbook YAML file {yaml_file}: {e}")



if __name__ == "__main__":
    logger.info("Starting database population...")

    
    populate_analyzers()
    populate_observable_types()
    populate_config()

    
    try:
        analyzer_count = Analyzer.objects.count()
        obs_type_count = ObservableType.objects.count()
        logger.info(f"DEBUG: Counts before playbook population - Analyzers: {analyzer_count}, ObservableTypes: {obs_type_count}")
    except Exception as e:
        logger.error(f"DEBUG: Error counting objects before playbook population: {e}")
    


    
    
    rules_dir = os.path.join(settings.BASE_DIR, 'rules')
    queries_dir = os.path.join(settings.BASE_DIR, 'queries')
    playbooks_dir = os.path.join(settings.BASE_DIR, 'playbooks') 

    
    os.makedirs(rules_dir, exist_ok=True)
    os.makedirs(queries_dir, exist_ok=True)
    os.makedirs(playbooks_dir, exist_ok=True) 

    
    populate_playbooks_from_yaml(playbooks_dir) 

    populate_detection_rules(rules_dir)
    populate_queries_templates(queries_dir)

    logger.info("All data populated successfully!")
