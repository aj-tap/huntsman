from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from api.views import DashboardView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', auth_views.LoginView.as_view(), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('api/', include('api.urls', namespace='api')),
    path('', DashboardView.as_view(), name='dashboard'),
]