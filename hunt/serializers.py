from rest_framework import serializers
from .models import Analyzer, Playbook, Config, DetectionRule

class AnalyzerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Analyzer
        fields = '__all__'  

class PlaybookSerializer(serializers.ModelSerializer):
    analyzers = AnalyzerSerializer(many=True, read_only=True)  

    class Meta:
        model = Playbook
        fields = '__all__'  

class ConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = Config
        fields = '__all__'  

class DetectionRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = DetectionRule
        fields = '__all__'  

class TaskResultSerializer(serializers.Serializer):
    task_id = serializers.CharField()
    status = serializers.CharField()
    result = serializers.DictField(required=False)  
