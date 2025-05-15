from django.contrib.auth import views as auth_views
from django.urls import path, include
from rest_framework import routers
from .views import AnalyzerViewSet, PlaybookViewSet, ConfigViewSet, TaskViewSet, IndexView, LoadingView, ResultView, RuleCreateView, RuleListView, RuleUpdateView, RuleDeleteView, RuleExportView, RuleImportView
from . import views


router = routers.DefaultRouter()
router.register(r'analyzers', AnalyzerViewSet)
router.register(r'playbooks', PlaybookViewSet)
router.register(r'configs', ConfigViewSet)
router.register(r'tasks', TaskViewSet, basename='task')
urlpatterns = [
    path('', IndexView.as_view(), name='index'),
    path('loading', LoadingView.as_view(), name='loading'),
    path('results', ResultView.as_view(), name='results'),
    path('api/', include(router.urls)),
    path('api/example-queries/', views.get_superdb_queries, name='get_superdb_queries'),
    path('accounts/login/', auth_views.LoginView.as_view(), name='login'),
    path('accounts/logout/', auth_views.LogoutView.as_view(), name='logout'),
    # Rule Management URLs
    path('rules/create/', RuleCreateView.as_view(), name='rule_create'),
    path('rules/', RuleListView.as_view(), name='rule_list'),
    path('rules/<int:pk>/update/', RuleUpdateView.as_view(), name='rule_update'),
    path('rules/<int:pk>/delete/', RuleDeleteView.as_view(), name='rule_delete'),
    path('rules/export/', RuleExportView.as_view(), name='rule_export'),  # New URL
    path('rules/import/', RuleImportView.as_view(), name='rule_import'),  # New URL

]