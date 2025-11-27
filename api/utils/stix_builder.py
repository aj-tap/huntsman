"""A utility for building STIX objects."""
from stix2 import (
    File,
    DomainName,
    IPv4Address,
    IPv6Address,
    EmailAddress,
    EmailMessage,
    URL,
    WindowsRegistryKey,
    AttackPattern,
    AutonomousSystem,
    Software,
    Vulnerability,
    Relationship,
    Report,
    Bundle,
    MACAddress,
    UserAccount,
    CourseOfAction,
    X509Certificate,
    Process,
    Directory,
    Mutex,
    NetworkTraffic,
    Artifact,
    Campaign,
    Identity,
    Indicator,
    IntrusionSet,
    Malware,
    ThreatActor,
    Tool,
    Location,
    CustomObject,
    properties
)
from collections import defaultdict
from datetime import datetime
from typing import Dict, Any, List, Optional

@CustomObject('jarm', [
    ('value', properties.StringProperty(required=True)),
])
class Jarm(object):
    """A custom STIX object for representing a JARM hash."""

    def __init__(self, value: Optional[str] = None, **kwargs: Any) -> None:
        pass

def _create_sdo(ioc_type: str, value: Any) -> Optional[Any]:
    """
    Create a STIX Domain Object (SDO) from an IOC type and value.

    Parameters
    ----------
    ioc_type : str
        The type of the Indicator of Compromise.
    value : Any
        The value of the IOC.

    Returns
    -------
    Any, optional
        A STIX Domain Object, or None if the IOC type is not supported.
    """
    try:
        if ioc_type in ("ipv4-addr", "ipv4"):
            return IPv4Address(value=value, allow_custom=True)
        if ioc_type in ("ipv6-addr", "ipv6"):
            return IPv6Address(value=value, allow_custom=True)
        if ioc_type in ("domain-name", "domain"):
            return DomainName(value=value, allow_custom=True)
        if ioc_type == "url":
            return URL(value=value, allow_custom=True)
        if ioc_type in ("mac-addr", "mac"):
            return MACAddress(value=value, allow_custom=True)
        if ioc_type == "autonomous-system":
            try:
                clean_val = str(value).upper().replace('AS', '').strip()
                return AutonomousSystem(name=str(value), number=int(clean_val), allow_custom=True)
            except ValueError:
                return AutonomousSystem(name=str(value), allow_custom=True)
        if ioc_type == "network-traffic":
            return NetworkTraffic(start=datetime.utcnow(), allow_custom=True)

        if ioc_type in ("email-addr", "email"):
            return EmailAddress(value=value, allow_custom=True)
        if ioc_type == "email-message":
            return EmailMessage(subject=str(value), allow_custom=True)
        if ioc_type == "identity":
            return Identity(name=value, identity_class="unknown", allow_custom=True)
        if ioc_type == "user-account":
            return UserAccount(account_login=value, allow_custom=True)

        if ioc_type in ["md5", "sha1", "sha256", "sha512", "ssdeep", "imphash"]:
            hash_type = ioc_type.upper()
            return File(name=str(value), hashes={hash_type: value}, allow_custom=True)
        if ioc_type == "authentihash":
            return File(name=str(value), hashes={"AUTHENTIHASH": value}, allow_custom=True)
        if ioc_type in ("file", "file-name", "filename"):
            return File(name=str(value), allow_custom=True)
        if ioc_type == "artifact":
            return Artifact(payload_bin=str(value).encode(), allow_custom=True)
        if ioc_type == "directory":
            return Directory(path=str(value), allow_custom=True)

        if ioc_type in ("win-reg-key", "windows-registry-key"):
            return WindowsRegistryKey(name=str(value), key=value, allow_custom=True)
        if ioc_type in ("process", "process-name"):
            return Process(name=str(value), allow_custom=True)
        if ioc_type == "mutex":
            return Mutex(name=str(value), allow_custom=True)
        if ioc_type in ("software", "software-cpe"):
            return Software(name=value, allow_custom=True)

        if ioc_type in ("cve", "vulnerability"):
            return Vulnerability(name=value.upper(), allow_custom=True)
        if ioc_type == "attack-pattern":
            return AttackPattern(name=value, allow_custom=True)
        if ioc_type == "campaign":
            return Campaign(name=value, allow_custom=True)
        if ioc_type == "course-of-action":
            return CourseOfAction(name=value, allow_custom=True)
        if ioc_type == "indicator":
            return Indicator(pattern=f"[file:name = '{value}']", pattern_type="stix", allow_custom=True)
        if ioc_type == "intrusion-set":
            return IntrusionSet(name=value, allow_custom=True)
        if ioc_type == "malware":
            return Malware(name=value, is_family=False, allow_custom=True)
        if ioc_type == "threat-actor":
            return ThreatActor(name=value, allow_custom=True)
        if ioc_type == "tool":
            return Tool(name=value, allow_custom=True)
            
        if ioc_type == "cryptocurrency-address":
            return UserAccount(
                account_login=value, 
                account_type="cryptocurrency-wallet", 
                allow_custom=True
            )
        if ioc_type == "jarm":
            return Jarm(name=value, value=value, allow_custom=True)

        if ioc_type == "x509-certificate":
            return X509Certificate(name=value, hashes={"SHA-1": value}, allow_custom=True)

        if ioc_type == "location":
            return Location(name=value, country=value, allow_custom=True)

        return None
    except Exception as e:
        print(f"STIX Builder Error: Failed to create SDO for type '{ioc_type}' value '{value}'. Error: {e}")
        return None

def _get_or_create_observables(iocs: Dict[str, List[Any]], existing_observables: Dict[str, Any]) -> List[Any]:
    """
    Get or create STIX observable objects from a dictionary of IOCs.

    Parameters
    ----------
    iocs : dict
        A dictionary of IOCs, with IOC types as keys and lists of values as values.
    existing_observables : dict
        A dictionary of existing observables, to avoid creating duplicates.

    Returns
    -------
    list
        A list of STIX observable objects for the current report.
    """
    current_report_observables = []
    
    for ioc_type, values in iocs.items():
        for value in values:
            sdo = _create_sdo(ioc_type, value)
            if sdo:
                if sdo.id not in existing_observables:
                    existing_observables[sdo.id] = sdo
                
                current_report_observables.append(existing_observables[sdo.id])
                
    return current_report_observables

def create_stix_report_bundle(report_name: str, iocs: Dict[str, List[Any]], source_ioc: Dict[str, Any]) -> Bundle:
    """
    Create a STIX report bundle from a set of IOCs.

    Parameters
    ----------
    report_name : str
        The name of the report.
    iocs : dict
        A dictionary of IOCs to be included in the report.
    source_ioc : dict
        The source IOC from which the other IOCs were derived.

    Returns
    -------
    Bundle
        A STIX Bundle object containing the report and all related objects.

    Raises
    ------
    ValueError
        If the source SDO cannot be created.
    """
    final_objects = []    
    all_observables_map = {}    
    
    source_sdo_list = _get_or_create_observables(
        {source_ioc['identifier_type']: [source_ioc['identifier']]},
        all_observables_map
    )
    
    if not source_sdo_list:
        raise ValueError(f"Could not create source SDO for {source_ioc['identifier_type']} {source_ioc['identifier']}")
    
    source_sdo = source_sdo_list[0]
    
    report_observables = _get_or_create_observables(iocs, all_observables_map)
    
    final_objects.extend(all_observables_map.values())
    
    all_report_refs = report_observables + [source_sdo]
    
    report = Report(
        name=report_name,
        published=datetime.utcnow(),
        object_refs=[obs.id for obs in all_report_refs],
        allow_custom=True
    )
    final_objects.append(report)
    
    for obs in all_report_refs:
        relationship = Relationship(
            obs, 
            'related-to', 
            report, 
            allow_custom=True
        )
        final_objects.append(relationship)

    for obs in report_observables:
        if source_sdo.id != obs.id:
            rel_to_source = Relationship(
                source_sdo,
                'related-to',
                obs,
                allow_custom=True
            )
            final_objects.append(rel_to_source)
    
    return Bundle(objects=final_objects, allow_custom=True)

def create_bulk_stix_report_bundle(reports_data: List[Dict[str, Any]]) -> Bundle:
    """
    Create a single STIX bundle containing multiple reports.

    Parameters
    ----------
    reports_data : list of dict
        A list of dictionaries, where each dictionary contains the data for
        a single report (report_name, iocs, source_ioc).

    Returns
    -------
    Bundle
        A STIX Bundle object containing all the reports and related objects.
    """
    final_objects = []
    report_objects = []
    all_observables_map = {}
    report_to_obs_map = defaultdict(list)
    report_name_to_source_sdo_map = {}

    for report_info in reports_data:
        report_name = report_info['report_name']
        iocs = report_info['iocs']
        source_ioc = report_info['source_ioc']

        source_sdo_list = _get_or_create_observables(
            {source_ioc['identifier_type']: [source_ioc['identifier']]},
            all_observables_map
        )
        
        if not source_sdo_list:
            continue
            
        source_sdo = source_sdo_list[0]
        report_name_to_source_sdo_map[report_name] = source_sdo
        
        report_observables = _get_or_create_observables(iocs, all_observables_map)
        
        report_to_obs_map[report_name].extend(report_observables)
        report_to_obs_map[report_name].append(source_sdo)

    final_objects.extend(all_observables_map.values())

    for report_name, obs_list in report_to_obs_map.items():
        report = Report(
            name=report_name,
            published=datetime.utcnow(),
            object_refs=[obs.id for obs in obs_list],
            allow_custom=True
        )
        report_objects.append(report)
    
    final_objects.extend(report_objects)

    for report_obj in report_objects:
        if report_obj.name not in report_name_to_source_sdo_map:
            continue
            
        obs_list_for_this_report = report_to_obs_map[report_obj.name]
        source_sdo = report_name_to_source_sdo_map[report_obj.name]
        
        for obs in obs_list_for_this_report:
            relationship = Relationship(
                obs, 
                'related-to', 
                report_obj, 
                allow_custom=True
            )
            final_objects.append(relationship)
            
            if obs.id != source_sdo.id:
                rel_to_source = Relationship(
                    source_sdo,
                    'related-to',
                    obs,
                    allow_custom=True
                )
                final_objects.append(rel_to_source)

    return Bundle(objects=final_objects, allow_custom=True)
