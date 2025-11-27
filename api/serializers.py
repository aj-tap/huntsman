"""Serializers for the Huntsman API."""
from rest_framework import serializers
from django.core.cache import cache
from .models import AnalysisTask
from .db.superdb_client import SuperDBClient
from typing import Dict, Any, List

class AnalysisTaskSerializer(serializers.ModelSerializer):
    """
    Serializer for the AnalysisTask model.

    Serializes AnalysisTask objects, including a method to fetch the full
    results of a task, potentially from cache or by querying SuperDB.
    """

    full_result = serializers.SerializerMethodField()

    class Meta:
        """Meta options for the AnalysisTaskSerializer."""

        model = AnalysisTask
        fields = [
            'id', 'status', 'service_name', 'identifier',
            'identifier_type', 'full_result', 'created_at', 'completed_at'
        ]
        read_only_fields = fields

    def get_full_result(self, obj: AnalysisTask) -> Dict[str, Any]:
        """
        Get the full result for an AnalysisTask.

        If the task was successful and the result is stored in SuperDB, this
        method will query SuperDB for the full result. The result is cached
        for an hour to reduce redundant queries.

        Parameters
        ----------
        obj : AnalysisTask
            The AnalysisTask instance.

        Returns
        -------
        dict
            The full result of the task.
        """
        if obj.status != AnalysisTask.Status.SUCCESS:
            return obj.result

        if obj.service_name == 'superdb_query':
            return obj.result

        if obj.result and 'pool' in obj.result:
            cache_key = f"task_result_{obj.id}"
            cached_result = cache.get(cache_key)
            if cached_result:
                print(f"CACHE HIT for task {obj.id}")
                return cached_result
            
            print(f"CACHE MISS for task {obj.id}. Querying SuperDB...")
            try:
                pool_name = obj.result.get("pool")
                query = f"from '{pool_name}' | task_id == '{obj.id}'"
                client = SuperDBClient()
                query_result = client.execute_query(query=query, pool=pool_name)
                final_result = query_result if query_result is not None else []
                
                cache.set(cache_key, final_result, timeout=3600)
                return final_result
            except Exception as e:
                return {"error": "Failed to retrieve result from SuperDB.", "details": str(e)}

        return obj.result

class SuperDBQuerySerializer(serializers.Serializer):
    """
    Serializer for SuperDB queries.

    Validates and serializes the components of a SuperDB query, which can be
    either a raw query string or a structured query with a pool and commands.
    """

    query = serializers.CharField(required=False, help_text="Raw query string")
    from_pool = serializers.CharField(required=False, help_text="Pool name for structured queries")
    commands = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="List of commands for structured queries"
    )

class TaskSubmissionSerializer(serializers.Serializer):
    """
    Serializer for submitting a single analysis task.

    Validates and serializes the data required to submit a new analysis task.
    """

    service_name = serializers.CharField(max_length=100)
    identifier = serializers.CharField(max_length=255)
    identifier_type = serializers.CharField(max_length=50)

class BulkTaskSubmissionSerializer(serializers.Serializer):
    """Serializer for submitting multiple analysis tasks in a single request."""

    tasks = TaskSubmissionSerializer(many=True, required=True)

class BulkTaskStatusRequestSerializer(serializers.Serializer):
    """Serializer for requesting the status of multiple analysis tasks."""

    task_ids = serializers.ListField(
        child=serializers.UUIDField(),
        required=True,
        help_text="List of task IDs to check status for"
    )

class LoadDataToBranchSerializer(serializers.Serializer):
    """
    Serializer for loading data into a SuperDB branch.

    Validates and serializes the data required to load data into a specific
    branch of a SuperDB pool.
    """

    pool_id_or_name = serializers.CharField(max_length=255, help_text="ID or name of the pool")
    branch_name = serializers.CharField(max_length=255, help_text="Name of the branch to load data into")
    data = serializers.JSONField(help_text="Data to load into the branch")
    csv_delim = serializers.CharField(max_length=1, default=',', required=False, help_text="CSV delimiter (default: ',')")

    def validate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate the data for loading into a branch.

        Parameters
        ----------
        data : dict
            The data to be validated.

        Returns
        -------
        dict
            The validated data.

        Raises
        ------
        serializers.ValidationError
            If the 'data' field is not provided.
        """
        if not data.get('data'):
            raise serializers.ValidationError("Data must be provided.")
        return data

class CreatePoolSerializer(serializers.Serializer):
    """
    Serializer for creating a new SuperDB pool.

    Validates and serializes the data required to create a new SuperDB pool.
    """

    name = serializers.CharField(max_length=255, help_text="Name of the new SuperDB pool")
    layout_order = serializers.ChoiceField(
        choices=[('asc', 'Ascending'), ('desc', 'Descending')],
        default='asc',
        required=False,
        help_text="Order of the pool layout (asc or desc)"
    )
    layout_keys = serializers.ListField(
        child=serializers.ListField(child=serializers.CharField()),
        default=[['ts']],
        required=False,
        help_text="List of keys for the pool layout (e.g., [['ts']])"
    )
    thresh = serializers.IntegerField(
        required=False,
        allow_null=True,
        help_text="Optional threshold for the pool"
    )

class CorrelationEngineSerializer(serializers.Serializer):
    """
    Serializer for the Correlation Engine.

    Validates and serializes the parameters for running the correlation engine
    on a specific task.
    """

    task_id = serializers.UUIDField()
    rules = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Optional list of specific rule titles to run. If not provided, all rules will be executed."
    )
    tags_filter = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        help_text="Optional list of tags to filter rules by"
    )

class STIXReportSerializer(serializers.Serializer):
    """Serializer for generating a STIX report from a task."""

    task_id = serializers.UUIDField(required=True, help_text="The source task ID to generate the report from.")

class STIXReportItemSerializer(serializers.Serializer):
    """Serializer for a single item in a bulk STIX report request."""

    task_id = serializers.UUIDField(required=True)
    report_name = serializers.CharField(required=True, max_length=255)

class BulkSTIXReportSerializer(serializers.Serializer):
    """Serializer for generating multiple STIX reports in a single request."""

    reports = STIXReportItemSerializer(many=True, required=True)

class AIAnalysisSerializer(serializers.Serializer):
    """
    Serializer for AI analysis requests.

    Validates and serializes the data and prompts for an AI analysis request.
    """

    data = serializers.ListField(child=serializers.DictField(), required=True)
    prompt = serializers.CharField(required=True)
    system_prompt = serializers.CharField(required=False, default="You are an expert Security Operations Center (SOC) analyst. Analyze the provided data and provide insights.")
