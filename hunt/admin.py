from django.contrib import admin
from .models import Analyzer, Playbook, Config, ObservableType, QueriesTemplate, DetectionRule

class PlaybookAdmin(admin.ModelAdmin):
    list_display = ('name', 'observable_types_display', 'description')
    filter_horizontal = ('observable_types','analyzers')
    
    def observable_types_display(self, obj):
        return ", ".join([observable.get_name_display() for observable in obj.observable_types.all()])
    observable_types_display.short_description = "Observable Types"

admin.site.register(Analyzer)
admin.site.register(ObservableType)
admin.site.register(Config)
admin.site.register(DetectionRule)
admin.site.register(Playbook, PlaybookAdmin)
admin.site.register(QueriesTemplate)