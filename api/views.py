"""Views for the Huntsman API."""
from django.db import transaction
from django.db import connection
from django.db.utils import OperationalError
from django.views.generic import TemplateView
from django.http import HttpRequest, JsonResponse
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from huntsman.celery import app as celery_app
from typing import Dict, Any, List

from .config import (
    load_api_recipes, load_internal_services_recipes, 
    load_scraping_recipes, load_ioc_patterns, 
    load_predefined_queries
)
from .models import AnalysisTask
from .serializers import (
    AnalysisTaskSerializer, BulkTaskSubmissionSerializer,
    TaskSubmissionSerializer, SuperDBQuerySerializer,
    BulkTaskStatusRequestSerializer, CorrelationEngineSerializer,
    CreatePoolSerializer, LoadDataToBranchSerializer,
    STIXReportSerializer, BulkSTIXReportSerializer,
    AIAnalysisSerializer
)
from .tasks import (
    run_analysis_task, run_superdb_query_task, run_create_pool_task, 
    run_load_data_to_branch_task, run_stix_report_creation_task,
    run_bulk_stix_report_creation_task, run_ai_analysis_task
)
from .correlation_engine import create_correlation_engine_instance
import json
from django.conf import settings

@method_decorator(login_required, name='dispatch')
class DashboardView(TemplateView):
    """A view to render the main dashboard."""

    template_name = "api/dashboard.html"

    def get_context_data(self, **kwargs: Any) -> Dict[str, Any]:
        """
        Get the context data for rendering the dashboard.

        This method loads IOC patterns and adds them to the context.

        Parameters
        ----------
        **kwargs : Any
            Arbitrary keyword arguments.

        Returns
        -------
        dict
            The context data for the template.
        """
        context = super().get_context_data(**kwargs)
        context['ioc_patterns'] = json.dumps(load_ioc_patterns())
        context['max_ioc_submission_limit'] = settings.MAX_IOC_SUBMISSION_LIMIT
        return context

class AnalysisTriggerView(APIView):
    """An API view to trigger a single analysis task."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        """
        Handle POST requests to trigger an analysis task.

        Parameters
        ----------
        request : HttpRequest
            The HTTP request object.
        *args : Any
            Variable length argument list.
        **kwargs : Any
            Arbitrary keyword arguments.

        Returns
        -------
        Response
            A DRF Response object.
        """
        serializer = TaskSubmissionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        data = serializer.validated_data
        try:
            with transaction.atomic():
                task_record = AnalysisTask.objects.create(
                    service_name=data['service_name'],
                    identifier=data['identifier'],
                    identifier_type=data['identifier_type'],
                    status=AnalysisTask.Status.PENDING
                )
                transaction.on_commit(lambda: run_analysis_task.delay(task_db_id=str(task_record.id)))
        except Exception as e:
            return Response({"error": "Failed to create task in database.", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(
            {"message": "Analysis task has been queued.", "task_id": task_record.id},
            status=status.HTTP_202_ACCEPTED
        )

class BulkAnalysisTriggerView(APIView):
    """An API view to trigger multiple analysis tasks in bulk."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        """
        Handle POST requests to trigger bulk analysis tasks.

        Parameters
        ----------
        request : HttpRequest
            The HTTP request object.
        *args : Any
            Variable length argument list.
        **kwargs : Any
            Arbitrary keyword arguments.

        Returns
        -------
        Response
            A DRF Response object.
        """
        serializer = BulkTaskSubmissionSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        tasks_data = serializer.validated_data['tasks']
        task_ids = []
        try:
            with transaction.atomic():
                for task_data in tasks_data:
                    task_record = AnalysisTask.objects.create(
                        service_name=task_data['service_name'],
                        identifier=task_data['identifier'],
                        identifier_type=task_data['identifier_type'],
                        status=AnalysisTask.Status.PENDING
                    )
                    transaction.on_commit(lambda t=task_record: run_analysis_task.delay(task_db_id=str(t.id)))
                    task_ids.append(task_record.id)
        except Exception as e:
            return Response({"error": "Failed to create bulk tasks in database.", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(
            {"message": f"{len(task_ids)} analysis tasks have been queued.", "task_ids": task_ids},
            status=status.HTTP_202_ACCEPTED
        )

class TaskStatusView(generics.RetrieveAPIView):
    """An API view to retrieve the status of a single analysis task."""

    queryset = AnalysisTask.objects.all()
    serializer_class = AnalysisTaskSerializer
    lookup_field = 'id'

class TaskListView(generics.ListAPIView):
    """An API view to list all analysis tasks, with optional filtering by status."""

    queryset = AnalysisTask.objects.all().order_by('-created_at')
    serializer_class = AnalysisTaskSerializer
    def get_queryset(self) -> Any:
        """
        Get the queryset for listing tasks.

        This method filters the queryset based on the 'status' query parameter.

        Returns
        -------
        QuerySet
            The filtered queryset of AnalysisTask objects.
        """
        queryset = super().get_queryset()
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status__iexact=status_filter)
        return queryset

class SuperDBQueryView(APIView):
    """An API view to execute a query on SuperDB."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        """
        Handle POST requests to execute a SuperDB query.

        Parameters
        ----------
        request : HttpRequest
            The HTTP request object.
        *args : Any
            Variable length argument list.
        **kwargs : Any
            Arbitrary keyword arguments.

        Returns
        -------
        Response
            A DRF Response object.
        """
        serializer = SuperDBQuerySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        data = serializer.validated_data
        
        if data.get('query'):
            query_string = data['query']
        else:
            from_pool = data['from_pool']
            commands = data.get('commands', [])
            
            query_parts = [f"from {from_pool}"]
            query_parts.extend(commands)
            query_string = " | ".join(query_parts)

        try:
            with transaction.atomic():
                task_record = AnalysisTask.objects.create(
                    service_name='superdb_query',
                    identifier=query_string,
                    identifier_type='etl_query',
                    status=AnalysisTask.Status.PENDING
                )
                task_record.save()
                
                transaction.on_commit(lambda: run_superdb_query_task.delay(task_db_id=str(task_record.id)))
        except Exception as e:
            return Response({"error": "Failed to create query task in database.", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(
            {
                "message": "Database query task has been queued.", 
                "task_id": task_record.id,
                "query": query_string,
            },
            status=status.HTTP_202_ACCEPTED
        )

class PredefinedQueriesListView(APIView):
    """An API view to list all predefined SuperDB queries."""

    def get(self, request: HttpRequest, format: Any = None) -> Response:
        """
        Handle GET requests to list predefined queries.

        Parameters
        ----------
        request : HttpRequest
            The HTTP request object.
        format : Any, optional
            The format of the response.

        Returns
        -------
        Response
            A DRF Response object containing the predefined queries.
        """
        queries = load_predefined_queries()
        return Response(queries, status=status.HTTP_200_OK)

class CreatePoolView(APIView):
    """An API view to create a new pool in SuperDB."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        """
        Handle POST requests to create a SuperDB pool.

        Parameters
        ----------
        request : HttpRequest
            The HTTP request object.
        *args : Any
            Variable length argument list.
        **kwargs : Any
            Arbitrary keyword arguments.

        Returns
        -------
        Response
            A DRF Response object.
        """
        serializer = CreatePoolSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        pool_name = data['name']
        layout_order = data.get('layout_order', 'asc')
        layout_keys = data.get('layout_keys', [['ts']])
        thresh = data.get('thresh')

        try:
            with transaction.atomic():
                task_record = AnalysisTask.objects.create(
                    service_name='superdb_create_pool',
                    identifier=pool_name,
                    identifier_type='pool_creation',
                    status=AnalysisTask.Status.PENDING
                )
                task_record.save()
                
                transaction.on_commit(
                    lambda: run_create_pool_task.delay(
                        task_db_id=str(task_record.id),
                        name=pool_name,
                        layout_order=layout_order,
                        layout_keys=layout_keys,
                        thresh=thresh
                    )
                )
        except Exception as e:
            return Response({"error": "Failed to create pool task in database.", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(
            {
                "message": f"SuperDB pool creation task for '{pool_name}' has been queued.", 
                "task_id": task_record.id,
                "pool_name": pool_name
            },
            status=status.HTTP_202_ACCEPTED
        )

class LoadDataToBranchView(APIView):
    """An API view to load data into a branch of a SuperDB pool."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        """
        Handle POST requests to load data into a SuperDB branch.

        Parameters
        ----------
        request : HttpRequest
            The HTTP request object.
        *args : Any
            Variable length argument list.
        **kwargs : Any
            Arbitrary keyword arguments.

        Returns
        -------
        Response
            A DRF Response object.
        """
        serializer = LoadDataToBranchSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        pool_id_or_name = data['pool_id_or_name']
        branch_name = data['branch_name']
        load_data = data['data']
        csv_delim = data.get('csv_delim', ',')

        try:
            with transaction.atomic():
                task_record = AnalysisTask.objects.create(
                    service_name='superdb_load_data',
                    identifier=f"Load data to {branch_name} in {pool_id_or_name}",
                    identifier_type='data_loading',
                    status=AnalysisTask.Status.PENDING
                )
                task_record.save()
                
                transaction.on_commit(
                    lambda: run_load_data_to_branch_task.delay(
                        task_db_id=str(task_record.id),
                        pool_id_or_name=pool_id_or_name,
                        branch_name=branch_name,
                        data=load_data,
                        csv_delim=csv_delim
                    )
                )
        except Exception as e:
            return Response({"error": "Failed to create load data task in. database.", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(
            {
                "message": f"Data loading task for branch '{branch_name}' in pool '{pool_id_or_name}' has been queued.", 
                "task_id": task_record.id,
                "pool_id_or_name": pool_id_or_name,
                "branch_name": branch_name
            },
            status=status.HTTP_202_ACCEPTED
        )

class ServiceListView(APIView):
    """An API view to list all available services and their supported types."""

    def get(self, request: HttpRequest, format: Any = None) -> Response:
        """
        Handle GET requests to list available services.

        Parameters
        ----------
        request : HttpRequest
            The HTTP request object.
        format : Any, optional
            The format of the response.

        Returns
        -------
        Response
            A DRF Response object containing the list of services.
        """
        api_recipes = load_api_recipes()
        internal_recipes = load_internal_services_recipes()
        scraping_recipes = load_scraping_recipes()
        
        combined_recipes = {**api_recipes, **internal_recipes, **scraping_recipes}
        
        service_list = []
        for name, recipe in combined_recipes.items():
            if not recipe.get('enabled', True):
                continue
            if "endpoints" not in recipe or not isinstance(recipe["endpoints"], dict):
                continue

            supported_types = list(recipe["endpoints"].keys())

            service_list.append({
                "name": name,
                "label": recipe.get("label", name.replace("_", " ").title()),
                "supported_types": supported_types
            })
            
        return Response(service_list)

class HealthCheckView(APIView):
    """An API view to perform health checks on the system components."""

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        """
        Handle GET requests to perform health checks.

        Parameters
        ----------
        request : HttpRequest
            The HTTP request object.
        *args : Any
            Variable length argument list.
        **kwargs : Any
            Arbitrary keyword arguments.

        Returns
        -------
        Response
            A DRF Response object with the health check results.
        """
        checks = {
            "database": self.check_database(),
            "celery_redis": self.check_celery(),
        }
        if any(check["status"] == "error" for check in checks.values()):
            return Response(checks, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        return Response(checks, status=status.HTTP_200_OK)

    def check_database(self) -> Dict[str, str]:
        """
        Check the status of the database connection.

        Returns
        -------
        dict
            A dictionary with the status and a message.
        """
        try:
            connection.ensure_connection()
            return {"status": "ok", "message": "Database connection successful."}
        except OperationalError as e:
            return {"status": "error", "message": f"Database connection failed: {str(e)}"}

    def check_celery(self) -> Dict[str, str]:
        """
        Check the status of the Celery workers.

        Returns
        -------
        dict
            A dictionary with the status and a message.
        """
        try:
            ping = celery_app.control.ping(timeout=3)
            if ping:
                worker_count = len(ping)
                return {"status": "ok", "message": f"{worker_count} Celery worker(s) responded."}
            else:
                return {"status": "error", "message": "No Celery workers responded to ping."}
        except Exception as e:
            return {"status": "error", "message": f"Celery check failed: {str(e)}"}

import logging

logger = logging.getLogger(__name__)

class BulkTaskStatusView(APIView):
    """An API view to retrieve the status of multiple tasks in bulk."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        """
        Handle POST requests to get the status of bulk tasks.

        Parameters
        ----------
        request : HttpRequest
            The HTTP request object.
        *args : Any
            Variable length argument list.
        **kwargs : Any
            Arbitrary keyword arguments.

        Returns
        -------
        Response
            A DRF Response object with the status of the requested tasks.
        """
        logger.info(f"Received bulk task status request with data: {request.data}")
        serializer = BulkTaskStatusRequestSerializer(data=request.data)
        if not serializer.is_valid():
            logger.error(f"Bulk task status request validation failed: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        task_ids = serializer.validated_data['task_ids']
        tasks = AnalysisTask.objects.filter(id__in=task_ids)
        logger.info(f"Found {tasks.count()} tasks for IDs: {task_ids}")
        results_serializer = AnalysisTaskSerializer(tasks, many=True)

        return Response(results_serializer.data, status=status.HTTP_200_OK)

class CorrelationEngineView(APIView):
    """An API view to interact with the Correlation Engine."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        """
        Handle POST requests to run the correlation engine.

        Parameters
        ----------
        request : HttpRequest
            The HTTP request object.
        *args : Any
            Variable length argument list.
        **kwargs : Any
            Arbitrary keyword arguments.

        Returns
        -------
        Response
            A DRF Response object with the correlation analysis results.
        """
        serializer = CorrelationEngineSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        data = serializer.validated_data
        task_id = data['task_id']
        
        try:
            task = AnalysisTask.objects.get(id=task_id)
        except AnalysisTask.DoesNotExist:
            return Response(
                {"error": f"Task with ID {task_id} not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        if task.status not in [AnalysisTask.Status.SUCCESS, AnalysisTask.Status.FAILURE]:
            return Response(
                {
                    "warning": f"Task {task_id} is in '{task.status}' status. Results may be incomplete.",
                    "task_status": task.status
                },
                status=status.HTTP_202_ACCEPTED
            )
        
        try:
            engine = create_correlation_engine_instance()
            
            analysis_result = engine.run_correlation_analysis(
                task_id=str(task_id),
                rule_titles=data.get('rules'),
                tags_filter=data.get('tags_filter')
            )
            
            analysis_result['task_metadata'] = {
                'task_id': str(task.id),
                'service_name': task.service_name,
                'identifier': task.identifier,
                'identifier_type': task.identifier_type,
                'task_status': task.status,
                'created_at': task.created_at,
                'completed_at': task.completed_at
            }
            
            return Response(analysis_result, status=status.HTTP_200_OK)
            
        except FileNotFoundError as e:
            return Response(
                {"error": "Rules configuration file not found", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except ValueError as e:
            return Response(
                {"error": "Invalid rules configuration", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            return Response(
                {"error": "Correlation analysis failed", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        """
        Handle GET requests to list correlation rules and tags.

        Parameters
        ----------
        request : HttpRequest
            The HTTP request object.
        *args : Any
            Variable length argument list.
        **kwargs : Any
            Arbitrary keyword arguments.

        Returns
        -------
        Response
            A DRF Response object with the list of rules and tags.
        """
        try:
            engine = create_correlation_engine_instance()
            
            rules_info = []
            for rule in engine.rules:
                rules_info.append({
                    "title": rule.title,
                    "description": rule.description,
                    "tags": rule.tags,
                    "syntax_template": rule.syntax
                })
            
            return Response({
                "total_rules": len(rules_info),
                "rules": rules_info,
                "available_tags": list(set(tag for rule in engine.rules for tag in rule.tags))
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {"error": "Failed to load rules information", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class STIXReportView(APIView):
    """An API view to create a STIX report."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        """
        Handle POST requests to create a STIX report.

        Parameters
        ----------
        request : HttpRequest
            The HTTP request object.
        *args : Any
            Variable length argument list.
        **kwargs : Any
            Arbitrary keyword arguments.

        Returns
        -------
        Response
            A DRF Response object.
        """
        serializer = STIXReportSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        source_task_id = data['task_id']
        
        try:
            source_task = AnalysisTask.objects.get(id=source_task_id)
        except AnalysisTask.DoesNotExist:
             return Response({"error": f"Source task {source_task_id} not found"}, status=status.HTTP_404_NOT_FOUND)

        try:
            with transaction.atomic():
                task_record = AnalysisTask.objects.create(
                    service_name='stix_report_creation',
                    identifier=f"STIX Report for {source_task.identifier}",
                    identifier_type='report_generation',
                    status=AnalysisTask.Status.PENDING
                )
                transaction.on_commit(
                    lambda: run_stix_report_creation_task.delay(
                        task_db_id=str(task_record.id),
                        source_task_id=str(source_task_id)
                    )
                )
        except Exception as e:
            return Response({"error": "Failed to create STIX report task.", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(
            {"message": "STIX report creation task has been queued.", "task_id": task_record.id},
            status=status.HTTP_202_ACCEPTED
        )

class BulkSTIXReportView(APIView):
    """An API view to create a bulk STIX report from multiple tasks."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        """
        Handle POST requests to create a bulk STIX report.

        Parameters
        ----------
        request : HttpRequest
            The HTTP request object.
        *args : Any
            Variable length argument list.
        **kwargs : Any
            Arbitrary keyword arguments.

        Returns
        -------
        Response
            A DRF Response object.
        """
        serializer = BulkSTIXReportSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        report_mappings = serializer.validated_data['reports']

        try:
            with transaction.atomic():
                task_record = AnalysisTask.objects.create(
                    service_name='stix_bulk_report_creation',
                    identifier=f"Bulk report job with {len(report_mappings)} reports",
                    identifier_type='bulk_report',
                    status=AnalysisTask.Status.PENDING
                )
                transaction.on_commit(
                    lambda: run_bulk_stix_report_creation_task.delay(
                        task_db_id=str(task_record.id),
                        report_mappings=report_mappings
                    )
                )
        except Exception as e:
            return Response({"error": "Failed to create bulk STIX report task.", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(
            {"message": "Bulk STIX report creation task has been queued.", "task_id": task_record.id},
            status=status.HTTP_202_ACCEPTED
        )

class AIAnalysisView(APIView):
    """An API view to perform AI analysis on a given dataset."""

    def post(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        """
        Handle POST requests to perform AI analysis.

        Parameters
        ----------
        request : HttpRequest
            The HTTP request object.
        *args : Any
            Variable length argument list.
        **kwargs : Any
            Arbitrary keyword arguments.

        Returns
        -------
        Response
            A DRF Response object.
        """
        serializer = AIAnalysisSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        data = serializer.validated_data['data']
        prompt = serializer.validated_data['prompt']
        system_prompt = serializer.validated_data.get('system_prompt', 'You are a world class CTI Analyst. Give brief summary and provide actionable insights.')

        try:
            with transaction.atomic():
                task_record = AnalysisTask.objects.create(
                    service_name='ai_analysis',
                    identifier=f"AI Analysis - {len(data)} records",
                    identifier_type='ai_insight',
                    status=AnalysisTask.Status.PENDING
                )
                
                transaction.on_commit(
                    lambda: run_ai_analysis_task.delay(
                        task_db_id=str(task_record.id),
                        data=data,
                        prompt=prompt,
                        system_prompt=system_prompt
                    )
                )
                
            return Response(
                {"message": "AI Analysis task queued.", "task_id": task_record.id},
                status=status.HTTP_202_ACCEPTED
            )
            
        except Exception as e:
            return Response({"error": f"Failed to queue AI task: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
