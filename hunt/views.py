import uuid
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse, JsonResponse, HttpResponseForbidden
from hunt.task import create_task_analyzer, create_stix, get_ai_insights, run_detections
from .models import Analyzer, Playbook, HuntsmanSuperDB, Config, ObservableType, QueriesTemplate, DetectionRule
from .forms import DetectionRuleForm, RuleImportForm
from django.views.decorators.csrf import csrf_exempt
from ioc_finder import find_iocs
from celery.result import AsyncResult
from datetime import datetime, timedelta, timezone
from django.views.generic import TemplateView
from django.views.generic import CreateView, ListView, UpdateView, DeleteView
from django.urls import reverse_lazy
from rest_framework import viewsets, status, permissions
from rest_framework.response import Response
from rest_framework.decorators import action
from .serializers import AnalyzerSerializer, PlaybookSerializer, ConfigSerializer, DetectionRuleSerializer
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.http import HttpRequest, JsonResponse
import logging
import json
import yaml
import os
from django.views import View
from django.core.paginator import Paginator

logger = logging.getLogger(__name__)

@login_required
def get_superdb_queries(request):
    queries = QueriesTemplate.objects.all()
    data = [{'title': q.title, 'query_string': q.query_string} for q in queries]
    return JsonResponse(data, safe=False)


class IndexView(LoginRequiredMixin, TemplateView):
    template_name = 'index.html'
    login_url = '/accounts/login/'

class LoadingView(LoginRequiredMixin, TemplateView):
    template_name = 'loading.html'
    login_url = '/accounts/login/'

class ResultView(LoginRequiredMixin, TemplateView):
    template_name = 'results.html'
    login_url = '/accounts/login/'

class RuleCreateView(LoginRequiredMixin, CreateView):
    model = DetectionRule
    form_class = DetectionRuleForm
    template_name = 'rule_management/rule_create.html'
    success_url = reverse_lazy('rule_list')  

class RuleListView(LoginRequiredMixin, ListView):
    model = DetectionRule
    template_name = 'rule_management/rule_list.html'  
    context_object_name = 'rules'
    paginate_by = 25  

    def get_queryset(self):
        queryset = DetectionRule.objects.all()
        search_term = self.request.GET.get('search')
        if search_term:
            queryset = queryset.filter(title__icontains=search_term) | queryset.filter(tags__icontains=search_term)
        return queryset

class RuleUpdateView(LoginRequiredMixin, UpdateView):
    model = DetectionRule
    form_class = DetectionRuleForm
    template_name = 'rule_management/rule_update.html'  
    success_url = reverse_lazy('rule_list')

class RuleDeleteView(LoginRequiredMixin, DeleteView):
    model = DetectionRule
    template_name = 'rule_management/rule_delete.html'  
    success_url = reverse_lazy('rule_list')

class RuleExportView(LoginRequiredMixin, View):
    def get(self, request):
        rules = DetectionRule.objects.all()
        rules_data = [rule.to_dict() for rule in rules]
        yaml_data = yaml.dump(rules_data, indent=2)

        response = HttpResponse(yaml_data, content_type='text/yaml')
        response['Content-Disposition'] = 'attachment; filename="detection_rules.yaml"'
        return response

class RuleImportView(LoginRequiredMixin, View):
    template_name = 'rule_management/rule_import.html'

    def get(self, request):
        form = RuleImportForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = RuleImportForm(request.POST, request.FILES)
        if form.is_valid():
            yaml_file = request.FILES['yaml_file']
            update_existing = form.cleaned_data['update_existing']
            try:
                rules_data = yaml.safe_load(yaml_file)
                if isinstance(rules_data, list):
                    for rule_data in rules_data:
                        title = rule_data['title']
                        description = rule_data.get('description', '')
                        syntax = rule_data['syntax']
                        tags = rule_data.get('tags', '')

                        try:
                            rule, created = DetectionRule.objects.get_or_create(
                                title=title,
                                defaults={
                                    'description': description,
                                    'syntax': syntax,
                                    'tags': tags
                                }
                            )
                            if not created and update_existing:
                                rule.description = description
                                rule.syntax = syntax
                                rule.tags = tags
                                rule.save()
                        except IntegrityError as e:
                            form.add_error(None, f"Error importing rule '{title}': {e}")
                            return render(request, self.template_name, {'form': form})
                    return redirect('rule_list')
                else:
                    form.add_error(None, "Invalid YAML format: Expected a list of rules.")
            except yaml.YAMLError as e:
                form.add_error(None, f"Error parsing YAML: {e}")
        return render(request, self.template_name, {'form': form})


class AnalyzerViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows Analyzers to be viewed or edited.
    """
    queryset = Analyzer.objects.all()
    serializer_class = AnalyzerSerializer

class PlaybookViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows Playbooks to be viewed or edited.
    """
    queryset = Playbook.objects.all()
    serializer_class = PlaybookSerializer

class ConfigViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows Config to be viewed or edited.
    """
    queryset = Config.objects.all()
    serializer_class = ConfigSerializer

class DetectionRuleViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows Detections Rules to be viewed or edited.
    """
    queryset = Config.objects.all()
    serializer_class = DetectionRuleSerializer

class TaskViewSet(viewsets.ViewSet):
    """
    ViewSet for managing Celery tasks.
    """
    permission_classes = [permissions.IsAuthenticated]

    @csrf_exempt
    def create(self, request):
        """
        Initiates a new task.
        """
        raw_string = request.data.get('raw_string')
        playbook_id = request.data.get('playbook_id')

        if not raw_string or not playbook_id:
            return Response(
                {"error": "Both 'raw_string' and 'playbook_id' are required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            playbook = Playbook.objects.get(id=playbook_id)
        except Playbook.DoesNotExist:
            return Response(
                {"error": f"Playbook with ID {playbook_id} not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        observable_types = set(playbook.observable_types.all().values_list('name', flat=True))

        iocs = find_iocs(raw_string)  
        
        task_ids = []
        tasks_created = 0

        for observable_type, ioc_list in iocs.items():
            if observable_type not in observable_types:
                continue 

            for ioc in ioc_list:
                try:
                    task_id = create_task_analyzer.delay(
                        playbook_id=playbook.id,
                        raw_string=ioc,
                        observable_type=observable_type 
                    )
                    task_ids.append(task_id.id)
                    tasks_created += 1

                except Exception as e:
                    logger.error(f"Error creating task for IOC '{ioc}': {e}")
                    return Response(
                        {"error": f"Error creating task for IOC '{ioc}': {e}"},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )

        return Response(
            {"task_ids": ",".join(task_ids), "message": f"{tasks_created} tasks created"}, 
            status=status.HTTP_202_ACCEPTED
        )

    def retrieve(self, request, pk=None):
        """
        Gets the status and result of a single task.
        """
        task_id = pk  
        task = AsyncResult(task_id)
    
        try:
            result = {
                "task_id": task_id,
                "status": task.status,
                "result": task.result,  
            }
        except Exception as e:
            logger.error(f"Error retrieving task result for task_id '{task_id}': {e}")
            return Response(
                {"error": f"Error retrieving task result for task_id '{task_id}': {e}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response(result)

    @action(detail=False, methods=['POST'], url_path='retrieve-threat-data')
    def retrieve_threatdata(self, request):
        """
        Retrieves results of multiple tasks from the external database with optional custom query.
        """
        task_ids_str = request.data.get('task_ids')
        custom_query = request.data.get('custom_query', '').strip() 
        
        if not task_ids_str:
            return Response({"error": "task_ids field is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        task_ids_list = [task_id.strip() for task_id in task_ids_str.split(',') if task_id.strip()]        
        
        if not task_ids_list:
            return Response({"error": "No valid task IDs provided."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            now_utc = datetime.now(timezone.utc)
            timeframe = now_utc - timedelta(minutes=30)            
            start_time_str = timeframe.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            end_time_str = now_utc.strftime('%Y-%m-%dT%H:%M:%S.%fZ')           
            time_filter = f"meta.ts >= '{start_time_str}' and meta.ts <= '{end_time_str}'"             
            task_conditions = " or ".join([f"meta.taskId=='{task_id}'" for task_id in task_ids_list])
            base_query = f"from 'ThreatData' | {time_filter} | {task_conditions}"            

            if custom_query:
                final_query = f"{base_query} | {custom_query}"
            else:
                final_query = base_query

            superDB_client = HuntsmanSuperDB()
            data = superDB_client.execute_query(query=final_query)
            
            if not data:
                return Response({"error": "No results found for the provided task IDs."}, status=status.HTTP_404_NOT_FOUND)
            
            return Response({"results": data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['POST'], url_path='statuses')
    def statuses(self, request):
        """
        Retrieves the status of multiple tasks by their IDs.
        """
        task_ids = request.data.get('task_ids')
        
        if not task_ids:
            return Response({"error": "'task_ids' parameter is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        task_ids_list = task_ids.split(',')
        
        results = []
        for task_id in task_ids_list:
            try:
                task = AsyncResult(task_id)
                results.append({
                    "task_id": task_id,
                    "status": task.status,
                    "result": task.result if task.status == 'SUCCESS' else None
                })
            except Exception as e:
                logger.error(f"Error getting status for task_id '{task_id}': {e}")
                results.append({
                    "task_id": task_id,
                    "status": "ERROR",
                    "result": f"Error getting status: {e}"
                })

        return Response(results, status=status.HTTP_200_OK)

    @action(detail=False, methods=['POST'], url_path='retrieve-stix')
    def retrieve_stix(self, request):
        """
        Retrieves the full raw STIX format of the threat data asynchronously and returns only the STIX bundle.
        """
        stix_id = request.data.get('stix_id') 
        if not stix_id:
            return Response({"error": "STIX ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            task = AsyncResult(stix_id)
            if task.state == 'PENDING':
                return Response({"status": "Pending", "message": "The STIX task is still being processed."}, status=status.HTTP_202_ACCEPTED)
            elif task.state == 'SUCCESS':
                stix_data_str = task.result
                try:
                    stix_data_json = json.loads(stix_data_str)  
                    return Response(stix_data_json, status=status.HTTP_200_OK)
                except Exception as e:
                    return Response({"error": f"Error parsing raw STIX data: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            elif task.state == 'FAILURE':
                return Response({"error": "STIX task failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                return Response({"error": f"Unexpected task state: {task.state}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            logger.error(f"Error retrieving STIX: {e}")
            return Response({"error": f"Error retrieving STIX: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['POST'], url_path='create-stix')
    def create_stix(self, request):   
        task_ids = request.data.get('task_ids')
        
        if not task_ids:
            logger.error("Missing 'task_ids' parameter.")
            return Response({"error": "The 'task_ids' parameter is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        if isinstance(task_ids, list):
            task_ids = ",".join(task_ids)
        elif not isinstance(task_ids, str):
            logger.error("Invalid 'task_ids' format.")
            return Response({"error": "The 'task_ids' must be a string or a list of strings."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            stix_task = create_stix.delay(task_ids=task_ids)
            return Response({"stix_id": stix_task.id}, status=status.HTTP_202_ACCEPTED)
        except Exception as e:
            logger.error(f"Error creating STIX task: {e}")
            return Response({"error": "Error creating STIX task."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['POST'], url_path='create-ai')
    def create_ai(self, request):   
        task_ids = request.data.get('task_ids')
        
        if not task_ids:
            logger.error("Missing 'task_ids' parameter.")
            return Response({"error": "The 'task_ids' parameter is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        if isinstance(task_ids, list):
            task_ids = ",".join(task_ids)
        elif not isinstance(task_ids, str):
            logger.error("Invalid 'task_ids' format.")
            return Response({"error": "The 'task_ids' must be a string or a list of strings."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            task = get_ai_insights.delay(task_ids)
            return JsonResponse({'task_id': task.id})
        except Exception as e:
            logger.error(f"Error creating STIX task: {e}")
            return Response({"error": "Error creating STIX task."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['POST'], url_path='retrieve-ai')
    def retrieve_ai(self, request):          
        try:
            task_ids = request.data.get('task_ids')
            task = AsyncResult(task_ids)
            if task.state == 'PENDING':
                return Response({"status": "PENDING", "message": "The AI insights task is still being processed."}, status=status.HTTP_202_ACCEPTED)
            elif task.state == 'STARTED':
                return Response({"status": "STARTED", "message": "The AI insights task is still initiating."}, status=status.HTTP_202_ACCEPTED)
            elif task.state == 'SUCCESS':
                ai_data = task.result
                try:                    
                    return Response(ai_data, status=status.HTTP_200_OK)
                except Exception as e:
                    return Response({"error": f"Error parsing raw data: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            elif task.state == 'FAILURE':
                return Response({"error": "AI insights task failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                return Response({"error": f"Unexpected task state: {task.state}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            logger.error(f"Error retrieving AI data: {e}")
            return Response({"error": f"Error retrieving STIX: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['POST'], url_path='run-detections')
    def run_detections_api(self, request):
        """
        API endpoint to trigger the run_detections task.
        """
        task_ids_input = request.data.get('task_ids')

        if not task_ids_input:
            return Response({"error": "task_ids field is required."}, status=status.HTTP_400_BAD_REQUEST)

        if isinstance(task_ids_input, list):
            task_ids_list = [task_id.strip() for task_id in task_ids_input if task_id.strip()]
        elif isinstance(task_ids_input, str):
            task_ids_list = [task_id.strip() for task_id in task_ids_input.split(',') if task_id.strip()]
        else:
            return Response({"error": "Invalid format for task_ids."}, status=status.HTTP_400_BAD_REQUEST)

        if not task_ids_list:
            return Response({"error": "No valid task IDs provided."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            detection_task = run_detections.delay(task_ids_list)
            return Response(
                {"detection_id": detection_task.id, "message": "Detection task started."},
                status=status.HTTP_202_ACCEPTED
            )
        except Exception as e:
            return Response({"error": f"Task execution failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['POST'], url_path='retrieve-detections-result')
    def retrieve_detections_result(self, request):
        """
        API endpoint to get the result of a run_detections task.
        """
        task_id = request.data.get('detection_id')

        if not task_id:
            return Response({"error": "detection_id field is required."}, status=status.HTTP_400_BAD_REQUEST)

        task = AsyncResult(task_id)

        if task.state == 'PENDING':
            return Response({"status": "PENDING", "message": "The detection task is still being processed."},
                            status=status.HTTP_202_ACCEPTED)

        elif task.state == 'SUCCESS':
            result = task.result
            if isinstance(result, dict):
                if "error" in result:
                    return Response({"error": result["error"]}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                elif "message" in result:
                    return Response({"message": result["message"]}, status=status.HTTP_200_OK)
                else:
                    return Response(result, status=status.HTTP_200_OK)
            return Response({"message": "Detection task completed successfully.", "result": result},
                            status=status.HTTP_200_OK)

        elif task.state == 'FAILURE':
            return Response({"error": "Detection task failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"error": f"Unexpected task state: {task.state}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
