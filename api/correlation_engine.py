"""The correlation engine for Huntsman."""
import os
import yaml
from typing import List, Dict, Any, Optional
from django.conf import settings
from .db.superdb_client import SuperDBClient


class CorrelationRule:
    """
    Represents a single correlation rule.

    Attributes
    ----------
    id : str
        The unique identifier of the rule.
    title : str
        The title of the rule.
    description : str
        A description of what the rule does.
    syntax : str
        The query syntax for the rule.
    author : str
        The author of the rule.
    source : str
        The source of the rule.
    tags : List[str]
        A list of tags associated with the rule.
    file_path : str
        The file path where the rule is defined.
    """

    def __init__(self, rule_data: Dict[str, Any], file_path: str) -> None:
        """
        Initialize a CorrelationRule object.

        Parameters
        ----------
        rule_data : dict
            The dictionary containing the rule data.
        file_path : str
            The file path where the rule is defined.

        Raises
        ------
        ValueError
            If a required field is missing in the rule data.
        """
        required_fields = ['id', 'title', 'description', 'syntax']
        if not all(field in rule_data for field in required_fields):
            raise ValueError(f"Rule file {file_path} is missing one or more required fields: {required_fields}")

        self.id: str = rule_data['id']
        self.title: str = rule_data['title']
        self.description: str = rule_data['description']
        self.syntax: str = rule_data['syntax'].strip()
        self.author: str = rule_data.get('author', 'Unknown')
        self.source: str = rule_data.get('source', 'Unknown')
        self.tags: List[str] = rule_data.get('tags', [])
        self.file_path: str = file_path

    def execute_query(self, task_id: str, superdb_client: SuperDBClient) -> Dict[str, Any]:
        """
        Execute the rule's query.

        Parameters
        ----------
        task_id : str
            The ID of the task to correlate.
        superdb_client : SuperDBClient
            The SuperDB client to use for executing the query.

        Returns
        -------
        dict
            A dictionary containing the results of the query execution.
        """
        query = f"{self.syntax} | task_id == '{task_id}'"

        try:
            if " | " in self.syntax:
                pool_part = self.syntax.split(" | ")[0]
                pool_name = pool_part.replace("from ", "").replace("'", "").strip()
            else:
                pool_name = "default"

            result = superdb_client.execute_query(query=query, pool=pool_name)

            if result is None:
                raise Exception("Query execution failed - likely pool not found or query syntax error")

            return {
                "rule_id": self.id,
                "rule_title": self.title,
                "tags": self.tags,
                "description": self.description,
                "query": query,
                "matches": len(result) if result else 0,
                "results": result,
                "status": "success"
            }
        except Exception as e:
            return {
                "rule_id": self.id,
                "rule_title": self.title,
                "tags": self.tags,
                "description": self.description,
                "query": query,
                "matches": 0,
                "results": [],
                "status": "error",
                "error": str(e)
            }


class CorrelationEngine:
    """
    Main correlation engine for loading and executing rules.

    Attributes
    ----------
    rules_directory_path : str
        The path to the directory containing the correlation rules.
    rules : List[CorrelationRule]
        A list of loaded correlation rules.
    superdb_client : SuperDBClient
        The SuperDB client used for executing queries.
    """

    def __init__(self, rules_directory_path: Optional[str] = None) -> None:
        """
        Initialize a CorrelationEngine object.

        Parameters
        ----------
        rules_directory_path : str, optional
            The path to the directory containing the correlation rules. If not
            provided, it will be loaded from the Django settings.
        """
        self.rules_directory_path: Optional[str] = rules_directory_path or getattr(settings, 'CORRELATION_RULES_PATH', None)
        self.rules: List[CorrelationRule] = []
        self.superdb_client: SuperDBClient = SuperDBClient()
        self.load_rules()

    def load_rules(self) -> None:
        """
        Load correlation rules from the specified directory.

        Raises
        ------
        FileNotFoundError
            If the rules directory is not found or is not a directory.
        """
        if not self.rules_directory_path or not os.path.isdir(self.rules_directory_path):
            raise FileNotFoundError(f"Rules directory not found or is not a directory: {self.rules_directory_path}")

        self.rules = []
        print(f"--- Loading correlation rules from: {self.rules_directory_path} ---")

        for root, _, files in os.walk(self.rules_directory_path):
            for file in files:
                if file.endswith((".yml", ".yaml")):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            rule_data_list = yaml.safe_load_all(f)

                            for rule_data in rule_data_list:
                                if not rule_data:
                                    continue
                                rule = CorrelationRule(rule_data=rule_data, file_path=file_path)
                                self.rules.append(rule)
                                print(f"  [+] Loaded rule: {rule.title}")

                    except yaml.YAMLError as e:
                        print(f"  [!] ERROR parsing YAML file {file_path}: {e}")
                    except ValueError as e:
                        print(f"  [!] ERROR validating rule data in {file_path}: {e}")
                    except Exception as e:
                        print(f"  [!] ERROR loading rule file {file_path}: {e}")

        print(f"--- Successfully loaded {len(self.rules)} rules. ---")

    def get_rules(self,
                  rule_titles: Optional[List[str]] = None,
                  tags_filter: Optional[List[str]] = None) -> List[CorrelationRule]:
        """
        Get a filtered list of correlation rules.

        Parameters
        ----------
        rule_titles : list of str, optional
            A list of rule titles to filter by.
        tags_filter : list of str, optional
            A list of tags to filter by.

        Returns
        -------
        list of CorrelationRule
            A list of correlation rules that match the filter criteria.
        """
        filtered_rules = self.rules

        if rule_titles:
            filtered_rules = [rule for rule in filtered_rules if rule.title in rule_titles]

        if tags_filter:
            tags_set = set(tags_filter)
            filtered_rules = [
                rule for rule in filtered_rules
                if tags_set.intersection(rule.tags)
            ]

        return filtered_rules

    def run_correlation_analysis(self,
                                task_id: str,
                                rule_titles: Optional[List[str]] = None,
                                tags_filter: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run correlation analysis for a specific task ID.

        Parameters
        ----------
        task_id : str
            The ID of the task to analyze.
        rule_titles : list of str, optional
            A list of rule titles to run. If not provided, all rules will be run.
        tags_filter : list of str, optional
            A list of tags to filter the rules to be run.

        Returns
        -------
        dict
            A dictionary containing the results of the correlation analysis.
        """
        rules_to_run = self.get_rules(rule_titles, tags_filter)

        if not rules_to_run:
            return {
                "task_id": task_id,
                "total_rules": len(self.rules),
                "rules_executed": 0,
                "matches_found": 0,
                "results": [],
                "status": "no_rules_matched_filters"
            }

        results = []
        total_matches = 0

        for rule in rules_to_run:
            rule_result = rule.execute_query(task_id, self.superdb_client)
            results.append(rule_result)
            total_matches += rule_result.get('matches', 0)

        results.sort(key=lambda x: x['matches'], reverse=True)

        return {
            "task_id": task_id,
            "total_rules": len(self.rules),
            "rules_executed": len(rules_to_run),
            "matches_found": total_matches,
            "results": results,
            "status": "completed",
            "summary": self._generate_summary(results)
        }

    def _generate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary of the correlation analysis results.

        Parameters
        ----------
        results : list of dict
            A list of dictionaries, where each dictionary is the result of a
            single rule execution.

        Returns
        -------
        dict
            A dictionary summarizing the results.
        """
        summary = {
            "total_matches": 0,
            "rules_with_matches": 0,
            "failed_rules": 0
        }

        for result in results:
            matches = result.get('matches', 0)
            status = result.get('status', 'unknown')

            summary["total_matches"] += matches

            if matches > 0:
                summary["rules_with_matches"] += 1

            if status == "error":
                summary["failed_rules"] += 1

        return summary


def create_correlation_engine_instance() -> CorrelationEngine:
    """
    Create a new instance of the CorrelationEngine.

    Returns
    -------
    CorrelationEngine
        A new instance of the CorrelationEngine.
    """
    return CorrelationEngine()
