import os
import sys
import django

# -- Path setup --------------------------------------------------------------
sys.path.insert(0, os.path.abspath('..'))

# -- Django Setup ------------------------------------------------------------
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'huntsman.settings')
django.setup()

# -- Project information -----------------------------------------------------
project = 'Huntsman'
copyright = '2024, ajtap'
author = 'ajtap'
release = '1.0.0'

# -- General configuration ---------------------------------------------------
extensions = [
    'sphinx.ext.autodoc',           # Core library for html generation from docstrings
    'sphinx.ext.napoleon',          # Support for NumPy and Google style docstrings
    'sphinx.ext.viewcode',          # Add links to highlighted source code
    'sphinx.ext.intersphinx',       # Link to other project's documentation
    'sphinx.ext.todo',              # Support for todo items
    'sphinx.ext.autodoc.typehints', # Automatically document type hints
]

templates_path = ['_templates']

# -- EXCLUSIONS --------------------------------------------------------------
# CRITICAL: We exclude 'api.rst' and 'modules.rst' because we are using 
# our own manual 'api_reference.rst'. This prevents "Duplicate Object" errors.
exclude_patterns = [
    '_build', 
    'Thumbs.db', 
    '.DS_Store', 
    '**/migrations/*', 
    '**/tests/*',
    'api.rst',      # Exclude old apidoc file
    'modules.rst',  # Exclude old apidoc file
    'huntsman.rst'  # Exclude old apidoc file
]

# -- Options for HTML output -------------------------------------------------
try:
    import sphinx_rtd_theme
    html_theme = 'sphinx_rtd_theme'
except ImportError:
    import warnings
    warnings.warn("sphinx_rtd_theme not found, falling back to default theme.")
    html_theme = 'alabaster'

html_theme_options = {
    'navigation_depth': 4,
    'collapse_navigation': False,
    'sticky_navigation': True,
    'prev_next_buttons_location': 'bottom',
}

html_static_path = ['_static']

# -- Extension configuration -------------------------------------------------
intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
    'django': ('https://docs.djangoproject.com/en/stable/', None),
}

autoclass_content = 'both'
autodoc_member_order = 'bysource'
autodoc_typehints = 'description'
todo_include_todos = True