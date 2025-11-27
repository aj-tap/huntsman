"""Configuration for the Django admin interface."""
from django.contrib import admin
from django.urls import path
from django.shortcuts import redirect
from django.contrib import messages
from django.utils.html import format_html
from django import forms
from typing import Dict, Any, Tuple
import yaml
from .models import AnalysisTask, ConfigFile, Rule
from .widgets import YamlEditorWidget
from .utils.rule_management import fetch_rules_from_github

class AnalysisTaskAdmin(admin.ModelAdmin):
    """Admin interface for the AnalysisTask model."""

    list_display = ('id', 'service_name', 'identifier', 'status', 'created_at')
    list_filter = ('status', 'service_name')
    search_fields = ('identifier', 'id', 'celery_task_id')
    readonly_fields = ('id', 'created_at', 'completed_at', 'result')

class ConfigFileForm(forms.ModelForm):
    """A form for editing ConfigFile objects with a YAML editor."""

    class Meta:
        """Meta options for the ConfigFileForm."""

        model = ConfigFile
        fields = '__all__'
        widgets = {
            'content': YamlEditorWidget(),
        }

    def clean_content(self) -> str:
        """
        Validate the YAML content of the form.

        Returns
        -------
        str
            The cleaned YAML content.

        Raises
        ------
        forms.ValidationError
            If the content is not valid YAML.
        """
        content = self.cleaned_data['content']
        try:
            yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise forms.ValidationError(f"Invalid YAML format: {e}")
        return content

class ConfigFileAdmin(admin.ModelAdmin):
    """Admin interface for the ConfigFile model."""

    form = ConfigFileForm
    list_display = ('name', 'path', 'updated_at')
    readonly_fields = ('path',)
    
    def get_readonly_fields(self, request: Any, obj: Any = None) -> Tuple[str, ...]:
        """
        Get the readonly fields for the admin interface.

        Parameters
        ----------
        request : Any
            The current request.
        obj : Any, optional
            The object being edited, by default None.

        Returns
        -------
        tuple
            A tuple of readonly fields.
        """
        if obj:
            return self.readonly_fields
        return ()

class RuleForm(forms.ModelForm):
    """A form for editing Rule objects with a YAML editor."""

    class Meta:
        """Meta options for the RuleForm."""

        model = Rule
        fields = '__all__'
        widgets = {
            'content': YamlEditorWidget(),
        }

    def clean_content(self) -> str:
        """
        Validate the YAML content of the form.

        Returns
        -------
        str
            The cleaned YAML content.

        Raises
        ------
        forms.ValidationError
            If the content is not valid YAML.
        """
        content = self.cleaned_data['content']
        try:
            yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise forms.ValidationError(f"Invalid YAML format: {e}")
        return content

@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    """Admin interface for the Rule model."""

    form = RuleForm
    list_display = ('title', 'name', 'author', 'updated_at')
    search_fields = ('title', 'name', 'description', 'content')
    readonly_fields = ('title', 'author', 'description', 'rule_id', 'id')
    
    fieldsets = (
        (None, {
            'fields': ('name', 'content')
        }),
        ('Generated Metadata', {
            'classes': ('collapse',),
            'fields': ('id', 'rule_id', 'title', 'author', 'description')
        }),
    )
    
    change_list_template = "admin/rule_changelist.html"

    def get_urls(self) -> list:
        """
        Get the URLs for the admin interface.

        Returns
        -------
        list
            A list of URLs.
        """
        urls = super().get_urls()
        custom_urls = [
            path('update-github/', self.admin_site.admin_view(self.update_from_github), name='rule-update-github'),
        ]
        return custom_urls + urls

    def update_from_github(self, request: Any) -> Any:
        """
        Update the rules from the GitHub repository.

        Parameters
        ----------
        request : Any
            The current request.

        Returns
        -------
        Any
            A redirect to the previous page.
        """
        try:
            stats = fetch_rules_from_github()
            msg = f"Successfully updated rules. Downloaded: {stats['downloaded']}, Skipped: {stats['skipped']}."
            if stats['errors']:
                msg += f" Errors: {len(stats['errors'])}."
            self.message_user(request, msg, messages.SUCCESS)
        except Exception as e:
            self.message_user(request, f"Failed to update rules: {str(e)}", messages.ERROR)
        return redirect('..')

admin.site.register(AnalysisTask, AnalysisTaskAdmin)
admin.site.register(ConfigFile, ConfigFileAdmin)
