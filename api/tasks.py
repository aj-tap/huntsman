"""Celery tasks for the Huntsman API."""
from celery import shared_task, Task
from django.utils import timezone
from django.db import transaction
import json
import logging
from collections import defaultdict
import re
import requests
import os
from typing import Dict, Any, List, Optional

from .factories.connector_factory import get_connector
from .models import AnalysisTask
from .db.superdb_client import SuperDBClient
from .serializers import LoadDataToBranchSerializer
from .config import load_rss_recipes, load_all_recipes
from .utils.stix_builder import create_stix_report_bundle, create_bulk_stix_report_bundle
from .utils.ioc_extractor import extract_iocs
from .utils.smart_extractor import SmartExtractor

try:
    import litellm
except ImportError:
    litellm = None

logger = logging.getLogger(__name__)

@shared_task(bind=True, autoretry_for=(requests.exceptions.RequestException,), retry_kwargs={'max_retries': 3, 'countdown': 5})
def run_analysis_task(self: Task, task_db_id: str) -> Dict[str, Any]:
    """
    Run an analysis task using a dynamically selected connector.

    This Celery task fetches data using a connector based on the service name,
    stores the data, and updates the task status.

    Parameters
    ----------
    self : celery.Task
        The Celery task instance.
    task_db_id : str
        The database ID of the AnalysisTask to be processed.

    Returns
    -------
    dict
        The result of the analysis task.
    """
    try:
        task = AnalysisTask.objects.get(id=task_db_id)
    except AnalysisTask.DoesNotExist:
        logger.error(f"AnalysisTask with id {task_db_id} not found.")
        return {"success": False, "error": "Task not found."}

    task.status = AnalysisTask.Status.IN_PROGRESS
    task.celery_task_id = self.request.id
    task.save()

    logger.info(f"CELERY TASK STARTED: DB ID {task.id}, Service '{task.service_name}'")
    try:
        connector = get_connector(task.service_name)
        result_reference = connector.fetch_and_store(task.identifier, task.identifier_type, str(task.id))
        task.status = AnalysisTask.Status.SUCCESS
        task.result = result_reference
    except Exception as e:
        logger.exception(f"AnalysisTask {task.id} failed.")
        task.status = AnalysisTask.Status.FAILURE
        task.result = {"success": False, "error": str(e)}
    finally:
        task.completed_at = timezone.now()
        task.save()
        logger.info(f"CELERY TASK FINISHED: DB ID {task.id} with status {task.status}")
    
    return task.result

@shared_task(bind=True)
def run_superdb_query_task(self: Task, task_db_id: str) -> Dict[str, Any]:
    """
    Execute a SuperDB query as a Celery task.

    Parameters
    ----------
    self : celery.Task
        The Celery task instance.
    task_db_id : str
        The database ID of the AnalysisTask containing the query.

    Returns
    -------
    dict
        The result of the SuperDB query.
    """
    try:
        task = AnalysisTask.objects.get(id=task_db_id)
    except AnalysisTask.DoesNotExist:
        logger.error(f"AnalysisTask with id {task_db_id} not found.")
        return {"success": False, "error": "Task not found."}

    task.status = AnalysisTask.Status.IN_PROGRESS
    task.celery_task_id = self.request.id
    task.save()

    logger.info(f"CELERY QUERY TASK STARTED: DB ID {task.id}")
    try:
        query_string = task.identifier
        
        logger.debug(f"CELERY QUERY: {query_string}")
        
        client = SuperDBClient()
        query_result = client.execute_query(query=query_string)
        
        if query_result is not None:
            task.status = AnalysisTask.Status.SUCCESS
            task.result = query_result
        else:
            task.status = AnalysisTask.Status.FAILURE
            task.result = {"success": False, "error": "Query execution failed - no results returned"}
            
    except Exception as e:
        task.status = AnalysisTask.Status.FAILURE
        task.result = {"success": False, "error": str(e)}
        logger.error(f"CELERY QUERY ERROR: {str(e)}")
    finally:
        task.completed_at = timezone.now()
        task.save()
    
    return task.result

@shared_task(bind=True)
def run_create_pool_task(self: Task, task_db_id: str, name: str, layout_order: str, layout_keys: list, thresh: Optional[int] = None) -> Dict[str, Any]:
    """
    Create a SuperDB pool as a Celery task.

    Parameters
    ----------
    self : celery.Task
        The Celery task instance.
    task_db_id : str
        The database ID of the AnalysisTask for this operation.
    name : str
        The name of the pool to be created.
    layout_order : str
        The layout order for the pool ('asc' or 'desc').
    layout_keys : list
        The layout keys for the pool.
    thresh : int, optional
        The threshold for the pool.

    Returns
    -------
    dict
        The result of the pool creation operation.
    """
    try:
        task = AnalysisTask.objects.get(id=task_db_id)
    except AnalysisTask.DoesNotExist:
        logger.error(f"AnalysisTask with id {task_db_id} not found.")
        return {"success": False, "error": "Task not found."}

    task.status = AnalysisTask.Status.IN_PROGRESS
    task.celery_task_id = self.request.id
    task.save()

    logger.info(f"CELERY CREATE POOL TASK STARTED: DB ID {task.id}, Pool Name: '{name}'")
    try:
        client = SuperDBClient()
        pool_creation_result = client.create_pool(
            name=name,
            layout_order=layout_order,
            layout_keys=layout_keys,
            thresh=thresh
        )
        
        if pool_creation_result is not None:
            task.status = AnalysisTask.Status.SUCCESS
            task.result = pool_creation_result
        else:
            task.status = AnalysisTask.Status.FAILURE
            task.result = {"success": False, "error": "Pool creation failed - no results returned"}
            
    except Exception as e:
        task.status = AnalysisTask.Status.FAILURE
        task.result = {"success": False, "error": str(e)}
        logger.error(f"CELERY CREATE POOL ERROR: {str(e)}")
    finally:
        task.completed_at = timezone.now()
        task.save()
        logger.info(f"CELERY CREATE POOL TASK FINISHED: DB ID {task.id} with status {task.status}")
    
    return task.result

@shared_task(bind=True)
def run_load_data_to_branch_task(self: Task, task_db_id: str, pool_id_or_name: str, branch_name: str, data: dict, csv_delim: str = ',') -> Dict[str, Any]:
    """
    Load data into a SuperDB branch as a Celery task.

    Parameters
    ----------
    self : celery.Task
        The Celery task instance.
    task_db_id : str
        The database ID of the AnalysisTask for this operation.
    pool_id_or_name : str
        The ID or name of the SuperDB pool.
    branch_name : str
        The name of the branch to load data into.
    data : dict
        The data to be loaded.
    csv_delim : str, optional
        The CSV delimiter to use if the data is in CSV format.

    Returns
    -------
    dict
        The result of the data loading operation.
    """
    try:
        task = AnalysisTask.objects.get(id=task_db_id)
    except AnalysisTask.DoesNotExist:
        logger.error(f"AnalysisTask with id {task_db_id} not found.")
        return {"success": False, "error": "Task not found."}

    task.status = AnalysisTask.Status.IN_PROGRESS
    task.celery_task_id = self.request.id
    task.save()

    logger.info(f"CELERY LOAD DATA TO BRANCH TASK STARTED: DB ID {task.id}, Pool: '{pool_id_or_name}', Branch: '{branch_name}'")
    try:
        client = SuperDBClient()
        load_result = client.load_data_to_branch(
            pool_id_or_name=pool_id_or_name,
            branch_name=branch_name,
            data=data,
            csv_delim=csv_delim
        )
        
        if load_result is not None:
            task.status = AnalysisTask.Status.SUCCESS
            task.result = load_result
        else:
            task.status = AnalysisTask.Status.FAILURE
            task.result = {"success": False, "error": "Data loading failed - no results returned"}
            
    except Exception as e:
        task.status = AnalysisTask.Status.FAILURE
        task.result = {"success": False, "error": str(e)}
        logger.error(f"CELERY LOAD DATA TO BRANCH ERROR: {str(e)}")
    finally:
        task.completed_at = timezone.now()
        task.save()
        logger.info(f"CELERY LOAD DATA TO BRANCH TASK FINISHED: DB ID {task.id} with status {task.status}")
    
    return task.result

def _is_valid_value(value: Any) -> bool:
    """
    Check if a value is valid for IOC extraction.

    Parameters
    ----------
    value : Any
        The value to check.

    Returns
    -------
    bool
        True if the value is valid, False otherwise.
    """
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        value_lower = value.lower().strip()
        if value_lower in ['missing', 'null', 'none', 'error']:
            return False
        if not value_lower:
            return False
        if 'error' in value_lower and (value_lower.startswith('{') or value_lower.startswith('[')):
             return False
    return True

def _flatten_ioc_results(data: Any) -> List[str]:
    """
    Flatten a nested structure of IOCs into a single list of strings.

    Parameters
    ----------
    data : Any
        The data to flatten.

    Returns
    -------
    list of str
        A flattened list of IOCs as strings.
    """
    flattened = []
    if isinstance(data, dict):
        for value in data.values():
            flattened.extend(_flatten_ioc_results(value))
    elif isinstance(data, list):
        for item in data:
            flattened.extend(_flatten_ioc_results(item))
    elif isinstance(data, (str, int, float)):
        flattened.append(str(data))
    return flattened

def _extract_iocs_from_task(source_task: AnalysisTask, client: SuperDBClient) -> Dict[str, List[str]]:
    """
    Extract IOCs from the results of an analysis task.

    This function uses various strategies to extract IOCs, including pivot
    queries defined in recipes and raw data scanning.

    Parameters
    ----------
    source_task : AnalysisTask
        The task from which to extract IOCs.
    client : SuperDBClient
        The SuperDB client for running queries.

    Returns
    -------
    dict
        A dictionary of IOCs, with IOC types as keys and lists of values as values.
    """
    iocs_to_create = defaultdict(list)
    
    all_recipes = load_all_recipes()
    service_recipe = all_recipes.get(source_task.service_name, {})
    
    db_pool = source_task.service_name
    task_result: Dict[str, Any] = {}
    if source_task.result and isinstance(source_task.result, dict):
        task_result = source_task.result
        db_pool = task_result.get('pool', db_pool)
    
    endpoint_config = service_recipe.get('endpoints', {}).get(source_task.identifier_type, {})
    pivots = endpoint_config.get('pivots')
    base_query_pattern = endpoint_config.get('query_pattern')
    llm_ioc_extract = endpoint_config.get('llm_ioc_extract', False)

    smart_extractor = None
    if llm_ioc_extract:
        smart_extractor = SmartExtractor()

    direct_data = task_result.get('data')
    if direct_data is not None and isinstance(direct_data, list):
        logger.info(f"Processing {len(direct_data)} in-memory items for service: {source_task.service_name}")
        
        for item in direct_data:
            if not item: continue
            
            val_str = ""
            
            if isinstance(item, dict):
                narrative_parts = []
                for key in ['full_text', 'body', 'content', 'summary', 'description', 'title']:
                    if key in item and _is_valid_value(item[key]):
                        narrative_parts.append(str(item[key]))
                
                if narrative_parts:
                    val_str = "\n\n".join(narrative_parts)
                else:
                    val_str = json.dumps(item)
            else:
                val_str = str(item)
                
            if not _is_valid_value(val_str):
                continue
            
            try:
                if llm_ioc_extract and smart_extractor:
                    extracted_data = smart_extractor.extract(val_str)
                    for k, v in extracted_data.items():
                        iocs_to_create[k].extend(v)
                else:
                    found_iocs = extract_iocs(val_str)
                    for k, v in found_iocs.items():
                        iocs_to_create[k].extend(v)
            except Exception as e:
                logger.warning(f"Error extracting IOCs from in-memory item: {e}")
        
        return {k: list(set(v)) for k, v in iocs_to_create.items()}

    if pivots and isinstance(pivots, dict):
        logger.info(f"Using endpoint pivot queries for service: {source_task.service_name}, endpoint: {source_task.identifier_type}")
        
        for ioc_type, pivot_cmd in pivots.items():
            if not pivot_cmd:
                continue
            
            format_args = {
                'task_id': str(source_task.id),
                'identifier': source_task.identifier
            }
            
            if base_query_pattern:
                try:
                    base_query = base_query_pattern.format(**format_args).strip()
                    pivot_query = f"{base_query} | {pivot_cmd}"
                except KeyError as e:
                    logger.warning(f"Skipping pivot query due to missing format key: {e}.")
                    continue
            else:
                try:
                    pivot_cmd_formatted = pivot_cmd.format(**format_args).strip()
                except KeyError:
                    pivot_cmd_formatted = pivot_cmd

                pivot_query = f"from '{db_pool}' | where task_id == '{source_task.id}' | {pivot_cmd_formatted}"

            try:
                query_results = client.execute_query(query=pivot_query)
            except Exception as e:
                logger.error(f"Error executing pivot query: {e}")
                continue

            if not query_results:
                continue

            for item in query_results:
                if isinstance(item, dict) and 'error' in item:
                    continue
                if not item:
                    continue
                
                values_scope = []
                if isinstance(item, dict):
                    if len(item) == 1:
                        val = next(iter(item.values()), None)
                        if val: values_scope.append(val)
                    else:
                        values_scope.extend(item.values())
                elif isinstance(item, list):
                    values_scope.extend(item)
                else:
                    values_scope.append(item)

                for val in values_scope:
                    if not _is_valid_value(val):
                        continue
                    
                    val_str = str(val)
                    
                    try:
                        if llm_ioc_extract and smart_extractor:
                            extracted_data = smart_extractor.extract(val_str)
                            for k, v in extracted_data.items():
                                iocs_to_create[k].extend(v)
                        else:
                            extracted_data = extract_iocs(val_str, ioc_types=[ioc_type])
                            
                            if ioc_type in extracted_data:
                                found_items_flat = _flatten_ioc_results(extracted_data[ioc_type])
                                
                                if found_items_flat:
                                    iocs_to_create[ioc_type].extend(found_items_flat)

                    except Exception as e:
                        logger.warning(f"Error running extract_iocs on value: {e}")

    else:
        logger.info(f"No pivot queries found for {source_task.service_name}/{source_task.identifier_type}. Falling back to raw data scan.")
        
        if base_query_pattern:
             format_args = {'identifier': source_task.identifier}
             query = base_query_pattern.format(**format_args)
        else:
             query = f"from '{db_pool}' | task_id=='{source_task.id}'"
             
        raw_data_to_scan = []
        def _extract_all_strings(data: Any) -> List[str]:
            strings = []
            if isinstance(data, dict):
                if 'error' in data: return []
                for key, value in data.items():
                    strings.extend(_extract_all_strings(value))
            elif isinstance(data, list):
                for item in data:
                    strings.extend(_extract_all_strings(item))
            elif isinstance(data, (str, int, float)):
                if _is_valid_value(data):
                    strings.append(str(data))
            return strings

        try:
            raw_results = client.execute_query(query=query)
            if raw_results:
                raw_data_to_scan.extend(_extract_all_strings(raw_results))
        except Exception as e:
            logger.error(f"Error executing raw scan query: {e}")

        unclean_text_blob = " \n ".join(raw_data_to_scan)

        if unclean_text_blob:
            if llm_ioc_extract and smart_extractor:
                found_iocs = smart_extractor.extract(unclean_text_blob)
                for ioc_type, values in found_iocs.items():
                    iocs_to_create[ioc_type].extend(values)
            else:
                found_iocs = extract_iocs(unclean_text_blob)
                for ioc_type, values in found_iocs.items():
                    iocs_to_create[ioc_type].extend(values)

    return {k: list(set(v)) for k, v in iocs_to_create.items()}

@shared_task(name="run_all_rss_feeds")
def run_all_rss_feeds_task() -> str:
    """
    Trigger analysis tasks for all configured RSS feeds.

    This is a scheduled task that iterates through all RSS feed recipes and
    queues an analysis task for each one.

    Returns
    -------
    str
        A summary of the triggered feeds.
    """
    logger.info("SCHEDULED TASK: Starting to trigger all RSS feeds.")
    
    rss_recipes = load_rss_recipes()
    if not rss_recipes:
        logger.warning("SCHEDULED TASK: No RSS feed recipes found.")
        return "No RSS recipes found."

    triggered_feeds = []
    for service_name in rss_recipes.keys():
        try:           
            task_model = AnalysisTask.objects.create(
                service_name=service_name,
                identifier="latest_scheduled",
                identifier_type="rss_feed_scheduled"
            )
            run_analysis_task.delay(task_db_id=str(task_model.id))
            logger.info(f"SCHEDULED TASK: Queued task for RSS feed '{service_name}'")
            triggered_feeds.append(service_name)
        except Exception as e:
            logger.error(f"SCHEDULED TASK: Failed to queue task for '{service_name}'. Error: {e}")

    summary = f"Successfully queued {len(triggered_feeds)} RSS feeds: {triggered_feeds}"
    logger.info(f"SCHEDULED TASK: {summary}")
    return summary

@shared_task(bind=True)
def run_stix_report_creation_task(self: Task, task_db_id: str, source_task_id: str) -> Dict[str, Any]:
    """
    Create a STIX report from the results of a source task.

    This task extracts IOCs from a given source task, builds a STIX report,
    and stores it in the 'stixdata' SuperDB pool.

    Parameters
    ----------
    self : celery.Task
        The Celery task instance.
    task_db_id : str
        The database ID for the STIX report creation task.
    source_task_id : str
        The database ID of the source task to generate the report from.

    Returns
    -------
    dict
        The result of the STIX report creation.
    """
    try:
        task = AnalysisTask.objects.get(id=task_db_id)
    except AnalysisTask.DoesNotExist:
        return {"success": False, "error": "Task not found."}

    task.status = AnalysisTask.Status.IN_PROGRESS
    task.celery_task_id = self.request.id
    task.save()

    try:
        try:
            source_task = AnalysisTask.objects.get(id=source_task_id)
        except AnalysisTask.DoesNotExist:
            raise ValueError(f"Source task {source_task_id} not found.")

        report_name = f"{source_task.service_name} - {source_task.identifier}"
        
        client = SuperDBClient()

        final_iocs = _extract_iocs_from_task(source_task, client)

        source_ioc_info = {
            'identifier': source_task.identifier,
            'identifier_type': source_task.identifier_type,
        }

        bundle = create_stix_report_bundle(report_name, final_iocs, source_ioc_info)
        
        bundle_dict = json.loads(bundle.serialize())
        bundle_dict["task_id"] = task_db_id
        json_data_to_store = json.dumps(bundle_dict, indent=2)
        
        stix_pool_name = "stixdata"
        client.load_data_to_branch(
            pool_id_or_name=stix_pool_name,
            branch_name="main",
            data=json_data_to_store
        )

        task.status = AnalysisTask.Status.SUCCESS
        task.result = {
            "success": True, 
            "stix_objects_created": len(bundle.objects),
            "bundle_id": bundle.id
        }

    except Exception as e:
        task.status = AnalysisTask.Status.FAILURE
        task.result = {"success": False, "error": str(e)}
        logger.error(f"STIX Report Creation ERROR: {str(e)}")
    finally:
        task.completed_at = timezone.now()
        task.save()
    
    return task.result

@shared_task(bind=True)
def run_bulk_stix_report_creation_task(self: Task, task_db_id: str, report_mappings: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Create a bulk STIX report from multiple source tasks.

    This task aggregates IOCs from multiple source tasks and creates a single
    STIX bundle containing all the information.

    Parameters
    ----------
    self : celery.Task
        The Celery task instance.
    task_db_id : str
        The database ID for the bulk STIX report creation task.
    report_mappings : list of dict
        A list of mappings, where each mapping contains a 'task_id'.

    Returns
    -------
    dict
        The result of the bulk STIX report creation.
    """
    try:
        task = AnalysisTask.objects.get(id=task_db_id)
    except AnalysisTask.DoesNotExist:
        return {"success": False, "error": "Task not found."}

    task.status = AnalysisTask.Status.IN_PROGRESS
    task.celery_task_id = self.request.id
    task.save()

    try:
        client = SuperDBClient()
        reports_data = []

        for mapping in report_mappings:
            source_task_id = mapping['task_id']

            try:
                source_task = AnalysisTask.objects.get(id=source_task_id)
            except AnalysisTask.DoesNotExist:
                logger.warning(f"Skipping STIX report for non-existent task: {source_task_id}")
                continue

            final_iocs = _extract_iocs_from_task(source_task, client)
            
            report_name = f"{source_task.service_name} - {source_task.identifier}"
            
            source_ioc_info = {
                'identifier': source_task.identifier,
                'identifier_type': source_task.identifier_type,
            }
            
            reports_data.append({
                "report_name": report_name, 
                "iocs": final_iocs,
                "source_ioc": source_ioc_info
            })
            
        if not reports_data:
            task.status = AnalysisTask.Status.SUCCESS
            task.result = {"message": "No valid tasks found to report on."}
            task.save()
            return task.result
            
        bundle = create_bulk_stix_report_bundle(reports_data)
        
        bundle_dict = json.loads(bundle.serialize())
        bundle_dict["task_id"] = task_db_id
        json_data_to_store = json.dumps(bundle_dict, indent=2)
        
        stix_pool_name = "stixdata"
        client.load_data_to_branch(
            pool_id_or_name=stix_pool_name,
            branch_name="main",
            data=json_data_to_store
        )
        
        task.status = AnalysisTask.Status.SUCCESS
        task.result = {
            "success": True, 
            "stix_objects_created": len(bundle.objects),
            "bundle_id": bundle.id 
        }
    
    except Exception as e:
        task.status = AnalysisTask.Status.FAILURE
        task.result = {"success": False, "error": str(e)}
        logger.error(f"Bulk STIX Report ERROR: {str(e)}")
    finally:
        task.completed_at = timezone.now()
        task.save()
    
    return task.result

@shared_task(bind=True)
def run_ai_analysis_task(self: Task, task_db_id: str, data: List[Dict[str, Any]], prompt: str, system_prompt: str) -> Dict[str, Any]:
    """
    Perform AI analysis on a given dataset using LiteLLM.

    Parameters
    ----------
    self : celery.Task
        The Celery task instance.
    task_db_id : str
        The database ID of the AI analysis task.
    data : list of dict
        The data to be analyzed.
    prompt : str
        The user prompt for the AI model.
    system_prompt : str
        The system prompt to guide the AI model's behavior.

    Returns
    -------
    dict
        The result of the AI analysis.
    """
    try:
        task = AnalysisTask.objects.get(id=task_db_id)
    except AnalysisTask.DoesNotExist:
        logger.error(f"AnalysisTask with id {task_db_id} not found.")
        return {"success": False, "error": "Task not found."}

    task.status = AnalysisTask.Status.IN_PROGRESS
    task.celery_task_id = self.request.id
    task.save()

    logger.info(f"CELERY AI TASK STARTED: DB ID {task.id}")
    
    try:
        if not litellm:
             raise ImportError("LiteLLM library not installed.")

        api_key = os.environ.get('LITELLM_API_KEY')
        api_base = os.environ.get('LITELLM_API_BASE')
        model_name = os.environ.get('LITELLM_MODEL')

        if not api_key:
             raise ValueError("LITELLM_API_KEY not set in environment variables.")

        data_json = json.dumps(data, indent=2)
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"{prompt}\n\nDataset:\n{data_json}"}
        ]

        completion_args: Dict[str, Any] = {
            "model": model_name,
            "messages": messages,
            "api_key": api_key
        }
        
        if api_base:
            completion_args["api_base"] = api_base

        response = litellm.completion(**completion_args)
        content = response.choices[0].message.content
        
        task.status = AnalysisTask.Status.SUCCESS
        task.result = {"result": content}

    except Exception as e:
        task.status = AnalysisTask.Status.FAILURE
        task.result = {"success": False, "error": str(e)}
        logger.error(f"CELERY AI TASK ERROR: {str(e)}")
    finally:
        task.completed_at = timezone.now()
        task.save()
    
    return task.result
