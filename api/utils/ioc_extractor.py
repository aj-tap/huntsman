"""A utility for extracting IOCs from text."""
import re
from collections import defaultdict
from typing import Dict, List, Optional, Pattern
from api.config import load_ioc_patterns

def _compile_patterns() -> Dict[str, Pattern[str]]:
    """
    Load and compile regex patterns for IOCs from the configuration.

    Returns
    -------
    dict
        A dictionary where keys are IOC types and values are compiled regex patterns.
    """
    raw_patterns = load_ioc_patterns()
    compiled = {}
    for key, pattern_str in raw_patterns.items():
        try:
            compiled[key] = re.compile(pattern_str, re.IGNORECASE)
        except re.error as e:
            print(f"Error compiling regex for {key}: {e}")
    return compiled

def extract_iocs(raw_data: str, ioc_types: Optional[List[str]] = None) -> Dict[str, List[str]]:
    """
    Extract Indicators of Compromise (IOCs) from a raw string of data.

    This function scans the input data for patterns that match known IOC types
    and returns a dictionary of all found IOCs, grouped by type.

    Parameters
    ----------
    raw_data : str
        The raw string data to extract IOCs from.
    ioc_types : list of str, optional
        A list of specific IOC types to look for. If not provided, all
        configured IOC types will be searched.

    Returns
    -------
    dict
        A dictionary where keys are IOC types and values are lists of the
        unique IOCs found for that type.
    """
    if not raw_data:
        return {}

    patterns = _compile_patterns()
    iocs: Dict[str, List[str]] = defaultdict(list)
    
    keys_to_scan = ioc_types if ioc_types else patterns.keys()

    for ioc_type in keys_to_scan:
        pattern = patterns.get(ioc_type)
        if not pattern:
            continue
            
        found = pattern.findall(raw_data)
        if found:
            cleaned = list(set(f.strip() for f in found))
            iocs[ioc_type].extend(cleaned)
            
    return dict(iocs)
