"""A smart IOC extractor that uses LLMs or Regex."""
import os
import json
import logging
import re
from typing import Dict, Any, List
from .ioc_extractor import extract_iocs

try:
    import litellm
except ImportError:
    litellm = None

logger = logging.getLogger(__name__)

class SmartExtractor:
    """
    A utility for extracting IOCs from text using LLMs or Regex.

    This class provides a centralized way to extract Indicators of Compromise
    (IOCs) from text. It will use a Language Learning Model (LLM) if configured,
    otherwise it will fall back to using regular expressions.
    """

    _SAFE_CONTEXT_LIMIT: int = 10000

    def __init__(self) -> None:
        """
        Initialize the SmartExtractor.

        This will check for the necessary environment variables to configure
        the LLM provider.
        """
        self.llm_model: str = os.environ.get("LITELLM_MODEL")
        self.llm_api_key: str = os.environ.get("LITELLM_API_KEY")
        self.llm_api_base: str = os.environ.get("LITELLM_API_BASE")
        
        if self.llm_model and litellm:
            logger.info(f"SmartExtractor initialized with LLM model: {self.llm_model}")
        else:
            logger.info("SmartExtractor initialized in Regex-only mode (no LLM_MODEL set or litellm missing).")

    def extract(self, text: str) -> Dict[str, List[str]]:
        """
        Extract IOCs from the provided text.

        If an LLM is configured, it will be used for extraction. Otherwise,
        it will fall back to a regex-based approach.

        Parameters
        ----------
        text : str
            The text to extract IOCs from.

        Returns
        -------
        dict
            A dictionary of IOCs, with IOC types as keys and lists of values as values.
        """
        if not text:
            return {}

        if self.llm_model and litellm:
            return self._extract_with_llm(text)
        
        return extract_iocs(text)

    def _extract_with_llm(self, text: str) -> Dict[str, List[str]]:
        """
        Extract IOCs from text using a configured LLM.

        Parameters
        ----------
        text : str
            The text to extract IOCs from.

        Returns
        -------
        dict
            A dictionary of IOCs extracted by the LLM.
        """
        try:
            safe_text = text[:self._SAFE_CONTEXT_LIMIT]
            
            messages = [
                {
                    "role": "system", 
                    "content": (
                        "You are a cybersecurity analyst. Extract technical Indicators of Compromise (IOCs) from the provided text. "
                        "Map them to standard STIX 2.1 observable pattern types. "
                        "Focus on categories: 'ipv4-addr', 'ipv6-addr', 'domain-name', 'url', 'email-addr', "
                        "'file-name', 'file-hash-md5', 'file-hash-sha1', 'file-hash-sha256', 'mac-addr', 'windows-registry-key', 'autonomous-system'. "
                        "CRITICAL: Filter out obvious false positives (e.g., vendor contact emails, social media links, loopback IPs, version numbers). "
                        "Return ONLY a valid JSON object where keys are the STIX types and values are lists of unique strings. "
                        "Do not include markdown formatting or explanations."
                    )
                },
                {"role": "user", "content": f"Analyze the following text and extract IOCs:\n\n{safe_text}"}
            ]

            completion_args: Dict[str, Any] = {
                "model": self.llm_model,
                "messages": messages,
            }
            
            if self.llm_api_key:
                completion_args["api_key"] = self.llm_api_key
            if self.llm_api_base:
                completion_args["api_base"] = self.llm_api_base

            response = litellm.completion(**completion_args)
            content = response.choices[0].message.content.strip()
            
            logger.debug(f"LLM Extraction Raw Output: {content[:500]}...") 

            try:
                json_match = re.search(r'\{.*\}', content, re.DOTALL)
                if json_match:
                    content = json_match.group(0)
                llm_data = json.loads(content)
            except json.JSONDecodeError:
                if content.startswith("```"):
                    content = re.sub(r'^```[a-zA-Z]*\n', '', content)
                    content = re.sub(r'\n```$', '', content)
                llm_data = json.loads(content)

            final_iocs: Dict[str, List[str]] = {}
            for key, val in llm_data.items():
                if isinstance(val, list):
                    clean_list = [str(v) for v in val if v]
                    if clean_list:
                        final_iocs[key] = list(set(clean_list))
                elif isinstance(val, (str, int)):
                    final_iocs[key] = [str(val)]

            if not final_iocs:
                logger.info("LLM returned valid JSON but no IOCs found. Falling back to Regex scan.")
                return extract_iocs(text)

            return final_iocs

        except Exception as e:
            logger.warning(f"LLM extraction failed: {e}. Falling back to Regex.")
            return extract_iocs(text)
