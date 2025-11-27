from pathlib import Path
import os
import dj_database_url
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv("SECRET_KEY", "django-insecure-change-me-in-production")

DEBUG = os.getenv("DEBUG", "False") == "True"

ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "*").split(",")

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'api.apps.ApiConfig',
    'corsheaders',
    'django_celery_beat',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'huntsman.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'huntsman.wsgi.application'

if not os.getenv("DATABASE_URL"):
    if DEBUG:
        os.environ["DATABASE_URL"] = f"sqlite:///{BASE_DIR / 'db.sqlite3'}"
    if not os.getenv("DATABASE_URL"):
        DB_USER = os.getenv("POSTGRES_USER", "postgres")
        DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "postgres")
        DB_HOST = os.getenv("POSTGRES_HOST", "db")
        DB_PORT = os.getenv("POSTGRES_PORT", "5432")
        DB_NAME = os.getenv("POSTGRES_DB", "huntsman_db")        
        if not os.getenv("POSTGRES_HOST"):
            os.environ["DATABASE_URL"] = f"sqlite:///{BASE_DIR / 'db.sqlite3'}"
        else:
            os.environ["DATABASE_URL"] = f"postgres://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

DATABASES = {
    'default': dj_database_url.config(conn_max_age=600, ssl_require=False)
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ],
    'EXCEPTION_HANDLER': 'api.utils.custom_exception_handler.custom_exception_handler',
}

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'

SUPERDB_HOST = os.getenv("SUPERDB_HOST", "localhost")
SUPERDB_BASE_URL = f"http://{SUPERDB_HOST}:9867"

CORS_ALLOW_ALL_ORIGINS = os.getenv("CORS_ALLOW_ALL_ORIGINS", "True") == "True"

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": os.getenv("CACHE_URL", "redis://127.0.0.1:6379/1"),
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        }
    }
}

API_RECIPES_PATH = os.path.join(BASE_DIR, 'huntsman/config/api_recipes.yaml')
SCRAPING_RECIPES_PATH = os.path.join(BASE_DIR, 'huntsman/config/scraping_recipes.yaml')
INTERNAL_SERVICES_RECIPES_PATH = os.path.join(BASE_DIR, 'huntsman/config/internal_services_recipe.yaml')
RSS_RECIPES_PATH = os.path.join(BASE_DIR, 'huntsman/config/rss_recipes.yaml')
IOC_PATTERNS_PATH = os.path.join(BASE_DIR, 'huntsman/config/ioc_patterns.yaml')
PREDEFINED_QUERIES_PATH = os.path.join(BASE_DIR, 'huntsman/config/queries.yaml')
CORRELATION_RULES_PATH = os.path.join(BASE_DIR, 'huntsman/config/rules/')
MAX_IOC_SUBMISSION_LIMIT = int(os.getenv("MAX_IOC_SUBMISSION_LIMIT", 20))

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'dashboard'
LOGOUT_REDIRECT_URL = 'login'
