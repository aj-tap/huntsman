"""URL patterns for the Huntsman API."""
from django.urls import path
from .views import (
    AnalysisTriggerView,
    BulkAnalysisTriggerView,
    TaskStatusView,
    TaskListView,
    SuperDBQueryView,
    ServiceListView,
    HealthCheckView,
    BulkTaskStatusView,
    CorrelationEngineView,
    CreatePoolView,
    LoadDataToBranchView,
    STIXReportView,
    BulkSTIXReportView,
    PredefinedQueriesListView,
    AIAnalysisView
)

app_name = 'api'

urlpatterns = [
    path('services/', ServiceListView.as_view(), name='list-services'),
    path('health/', HealthCheckView.as_view(), name='health-check'),
    path('analyze/', AnalysisTriggerView.as_view(), name='trigger-analysis'),
    path('analyze/bulk/', BulkAnalysisTriggerView.as_view(), name='trigger-bulk-analysis'),
    path('tasks/', TaskListView.as_view(), name='list-tasks'),
    path('tasks/<uuid:id>/', TaskStatusView.as_view(), name='get-task-status'),
    path('tasks/bulk/', BulkTaskStatusView.as_view(), name='get-bulk-task-status'),
    path('query/', SuperDBQueryView.as_view(), name='superdb-query'),
    path('queries/predefined/', PredefinedQueriesListView.as_view(), name='list-predefined-queries'),
    path('pool/create/', CreatePoolView.as_view(), name='create-pool'),
    path('branch/load-data/', LoadDataToBranchView.as_view(), name='load-data-to-branch'),
    path('correlate/', CorrelationEngineView.as_view(), name='correlation-engine'),
    path('stix/reports/create/', STIXReportView.as_view(), name='stix-report-create'),
    path('stix/reports/create/bulk/', BulkSTIXReportView.as_view(), name='stix-report-create-bulk'),
    path('ai/analyze/', AIAnalysisView.as_view(), name='ai-analyze'),
]
