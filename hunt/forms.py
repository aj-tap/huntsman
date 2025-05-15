from django import forms
from .models import DetectionRule

class DetectionRuleForm(forms.ModelForm):
    class Meta:
        model = DetectionRule
        fields = ['title', 'description', 'syntax', 'tags']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'syntax': forms.Textarea(attrs={'rows': 5}),
            'tags': forms.TextInput(attrs={'placeholder': 'e.g., malware, phishing, network'}),
        }

class RuleImportForm(forms.Form):
    yaml_file = forms.FileField(
        label='Select a YAML file',
        help_text='Upload a YAML file containing detection rules.'
    )
    update_existing = forms.BooleanField(
        label='Update existing rules',
        required=False,
        initial=False,
        help_text='Check this box to update existing rules with the same title.'
    )
