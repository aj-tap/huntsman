"""Custom Django widgets for the Huntsman admin."""
from django import forms
from typing import Dict, Any, Optional
from django.utils.safestring import mark_safe

class YamlEditorWidget(forms.Textarea):
    """A Django widget that provides a YAML editor using Ace Editor."""

    def render(self, name: str, value: Any, attrs: Optional[Dict[str, Any]] = None, renderer: Optional[Any] = None) -> str:
        """
        Render the widget to an HTML string.

        Parameters
        ----------
        name : str
            The name of the field.
        value : Any
            The value of the field.
        attrs : dict, optional
            HTML attributes for the widget, by default None.
        renderer : Any, optional
            The renderer to use, by default None.

        Returns
        -------
        str
            The HTML representation of the widget.
        """
        if value is None:
            value = ""
        
        final_attrs = self.build_attrs(attrs, {'name': name})
        element_id = final_attrs.get('id', f'id_{name}')
        editor_id = f"editor_{element_id}"

        html = f"""
        <div id="{editor_id}" style="width: 100%; height: 800px; border: 1px solid #ccc; border-radius: 4px;">{value}</div>
        <textarea id="{element_id}" name="{name}" style="display: none;">{value}</textarea>
        
        <script>
            (function() {{
                var editor = ace.edit("{editor_id}");
                var textarea = document.getElementById("{element_id}");
                
                editor.setTheme("ace/theme/monokai");
                editor.session.setMode("ace/mode/yaml");
                editor.setShowPrintMargin(false);
                editor.setOptions({{
                    fontSize: "14px",
                    tabSize: 2,
                    useSoftTabs: true,
                    wrap: true
                }});
                
                editor.getSession().on('change', function() {{
                    textarea.value = editor.getSession().getValue();
                }});
            }})();
        </script>
        """
        return mark_safe(html)

    class Media:
        """Media resources for the widget."""

        js = (
            'https://cdnjs.cloudflare.com/ajax/libs/ace/1.9.6/ace.min.js',
            'https://cdnjs.cloudflare.com/ajax/libs/ace/1.9.6/mode-yaml.min.js',
            'https://cdnjs.cloudflare.com/ajax/libs/ace/1.9.6/theme-monokai.min.js',
        )
