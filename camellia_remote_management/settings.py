import ipaddress
import base64
import binascii
import hashlib
import os
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

import django
from django.core.exceptions import ImproperlyConfigured
from django.utils.csp import CSP

BASE_DIR = Path(__file__).resolve().parent.parent
DJANGO_FORMS_TEMPLATES = Path(django.__file__).resolve().parent / "forms" / "templates"


def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on", "y")


def env_csv(name, default=None):
    value = os.environ.get(name, "").strip()
    if not value:
        return list(default or [])
    return [item.strip() for item in value.replace(";", ",").split(",") if item.strip()]


def env_int(name, default, min_value=None, max_value=None):
    try:
        value = int(os.environ.get(name, str(default)).strip())
    except ValueError:
        value = default
    if min_value is not None and value < min_value:
        return default
    if max_value is not None and value > max_value:
        return default
    return value


def valid_https_url(value, *, allow_query=True):
    if not isinstance(value, str) or not value or len(value) > 2048:
        return False
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
        and (allow_query or not parsed.query)
    )


DEBUG = env_bool("CAMELLIA_REMOTE_DEBUG", False)
SECRET_KEY = os.environ.get("CAMELLIA_REMOTE_SECRET_KEY", "").strip()
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = "dev-only-insecure-secret-key"
    else:
        raise ImproperlyConfigured("CAMELLIA_REMOTE_SECRET_KEY must be set when CAMELLIA_REMOTE_DEBUG is false")
if not DEBUG and (len(SECRET_KEY) < 50 or SECRET_KEY.startswith("dev-only-") or "replace-with" in SECRET_KEY.lower()):
    raise ImproperlyConfigured("CAMELLIA_REMOTE_SECRET_KEY must be an unpredictable value of at least 50 characters")

_data_encryption_key = os.environ.get("CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY", "").strip()
if _data_encryption_key:
    try:
        DATA_ENCRYPTION_KEY_BYTES = base64.b64decode(
            _data_encryption_key,
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ImproperlyConfigured("CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY must be canonical Base64") from exc
    if (
        len(DATA_ENCRYPTION_KEY_BYTES) != 32
        or base64.b64encode(DATA_ENCRYPTION_KEY_BYTES).decode("ascii") != _data_encryption_key
    ):
        raise ImproperlyConfigured("CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY must encode exactly 32 bytes")
elif DEBUG:
    DATA_ENCRYPTION_KEY_BYTES = hashlib.sha256(f"development-data-key:{SECRET_KEY}".encode()).digest()
else:
    raise ImproperlyConfigured("CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY is required when CAMELLIA_REMOTE_DEBUG is false")

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
ALLOWED_HOSTS = env_csv("CAMELLIA_REMOTE_ALLOWED_HOSTS", ["127.0.0.1", "localhost"])
CSRF_TRUSTED_ORIGINS = env_csv("CAMELLIA_REMOTE_CSRF_TRUSTED_ORIGINS", ["http://127.0.0.1:21114"])
# The OIDC client polls server-side state and deliberately clears popup.opener,
# so every response can retain full cross-origin opener isolation.
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"

# Only enable behind a reverse proxy that overwrites X-Forwarded-For / X-Real-IP;
# otherwise clients can choose the address the login lockout is keyed on.
TRUST_PROXY_HEADERS = env_bool("CAMELLIA_REMOTE_TRUST_PROXY_HEADERS", False)
TRUSTED_PROXY_CIDRS = env_csv("CAMELLIA_REMOTE_TRUSTED_PROXY_CIDRS")
try:
    TRUSTED_PROXY_NETWORKS = tuple(ipaddress.ip_network(value, strict=False) for value in TRUSTED_PROXY_CIDRS)
except ValueError as exc:
    raise ImproperlyConfigured("CAMELLIA_REMOTE_TRUSTED_PROXY_CIDRS contains an invalid network") from exc
if TRUST_PROXY_HEADERS and not TRUSTED_PROXY_NETWORKS:
    raise ImproperlyConfigured(
        "CAMELLIA_REMOTE_TRUSTED_PROXY_CIDRS is required when CAMELLIA_REMOTE_TRUST_PROXY_HEADERS is enabled"
    )

# TLS-terminating deployments should set CAMELLIA_REMOTE_SECURE_TLS=true.
_secure_tls = env_bool("CAMELLIA_REMOTE_SECURE_TLS", False)
SESSION_COOKIE_SECURE = _secure_tls
CSRF_COOKIE_SECURE = _secure_tls
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https") if _secure_tls else None
SECURE_SSL_REDIRECT = _secure_tls
SECURE_HSTS_SECONDS = env_int(
    "CAMELLIA_REMOTE_SECURE_HSTS_SECONDS",
    31536000 if _secure_tls else 0,
    0,
    63072000,
)
# Neither option is safe to infer merely from the API endpoint using TLS:
# sibling hostnames may still serve HTTP, and preload is a long-lived external
# commitment. Operators must opt in after reviewing the entire DNS namespace.
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool("CAMELLIA_REMOTE_SECURE_HSTS_INCLUDE_SUBDOMAINS", False)
SECURE_HSTS_PRELOAD = env_bool("CAMELLIA_REMOTE_SECURE_HSTS_PRELOAD", False)
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = env_int("CAMELLIA_REMOTE_SESSION_COOKIE_AGE_SECONDS", 8 * 60 * 60, 300, 7 * 24 * 60 * 60)
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
AUTH_USER_MODEL = "api.UserProfile"

ID_SERVER = os.environ.get("CAMELLIA_REMOTE_ID_SERVER", "").strip()
API_SERVER = os.environ.get("CAMELLIA_REMOTE_API_SERVER", "").strip()
RS_PUB_KEY = os.environ.get("CAMELLIA_REMOTE_RS_PUB_KEY", "").strip()
RELAY_SERVER = os.environ.get("CAMELLIA_REMOTE_RELAY_SERVER", "").strip()
DEFAULT_ID_PORT = env_int("CAMELLIA_REMOTE_DEFAULT_ID_PORT", 21116, 1, 65535)
PLUGIN_SIGNING_KEY = os.environ.get("CAMELLIA_REMOTE_PLUGIN_SIGNING_KEY", "").strip()
DEVICE_VERIFICATION_TOKEN = os.environ.get("CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN", "").strip()
if DEVICE_VERIFICATION_TOKEN and (
    not 32 <= len(DEVICE_VERIFICATION_TOKEN) <= 512
    or any(character.isspace() for character in DEVICE_VERIFICATION_TOKEN)
):
    raise ImproperlyConfigured(
        "CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN must contain 32-512 non-whitespace characters"
    )
if not DEBUG and not DEVICE_VERIFICATION_TOKEN:
    raise ImproperlyConfigured(
        "CAMELLIA_REMOTE_DEVICE_VERIFICATION_TOKEN is required when CAMELLIA_REMOTE_DEBUG is false"
    )

OIDC_PROVIDERS = {}
OIDC_HTTP_TIMEOUT_SECONDS = env_int("CAMELLIA_REMOTE_OIDC_HTTP_TIMEOUT_SECONDS", 10, 2, 60)
_oidc_name = os.environ.get("CAMELLIA_REMOTE_OIDC_NAME", "").strip()
_oidc_issuer = os.environ.get("CAMELLIA_REMOTE_OIDC_ISSUER", "").strip()
_oidc_client_id = os.environ.get("CAMELLIA_REMOTE_OIDC_CLIENT_ID", "").strip()
_oidc_client_secret = os.environ.get("CAMELLIA_REMOTE_OIDC_CLIENT_SECRET", "").strip()
_oidc_redirect_uri = os.environ.get("CAMELLIA_REMOTE_OIDC_REDIRECT_URI", "").strip()
_oidc_values = (
    _oidc_name,
    _oidc_issuer,
    _oidc_client_id,
    _oidc_client_secret,
    _oidc_redirect_uri,
)
if any(_oidc_values) and not all(_oidc_values):
    raise ImproperlyConfigured(
        "CAMELLIA_REMOTE_OIDC_NAME, CAMELLIA_REMOTE_OIDC_ISSUER, CAMELLIA_REMOTE_OIDC_CLIENT_ID, "
        "CAMELLIA_REMOTE_OIDC_CLIENT_SECRET and CAMELLIA_REMOTE_OIDC_REDIRECT_URI must be configured together"
    )
if all(_oidc_values):
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", _oidc_name):
        raise ImproperlyConfigured("CAMELLIA_REMOTE_OIDC_NAME contains unsupported characters")
    if not valid_https_url(_oidc_issuer, allow_query=False):
        raise ImproperlyConfigured("CAMELLIA_REMOTE_OIDC_ISSUER must be a canonical HTTPS URL")
    if not valid_https_url(_oidc_redirect_uri):
        raise ImproperlyConfigured("CAMELLIA_REMOTE_OIDC_REDIRECT_URI must be an HTTPS URL")
    _oidc_issuer_host = (urlsplit(_oidc_issuer).hostname or "").lower()
    _oidc_allowed_hosts = env_csv(
        "CAMELLIA_REMOTE_OIDC_ALLOWED_HOSTS",
        [_oidc_issuer_host],
    )
    if any(
        not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host) or host.startswith(".") or host.endswith(".")
        for host in _oidc_allowed_hosts
    ):
        raise ImproperlyConfigured("CAMELLIA_REMOTE_OIDC_ALLOWED_HOSTS must contain exact DNS hostnames")
    _oidc_allowed_hosts = tuple(dict.fromkeys(host.lower() for host in _oidc_allowed_hosts))
    if _oidc_issuer_host not in _oidc_allowed_hosts:
        raise ImproperlyConfigured("CAMELLIA_REMOTE_OIDC_ALLOWED_HOSTS must include the issuer hostname")
    _oidc_scope = os.environ.get("CAMELLIA_REMOTE_OIDC_SCOPE", "openid email profile").strip()
    if "openid" not in _oidc_scope.split():
        raise ImproperlyConfigured("CAMELLIA_REMOTE_OIDC_SCOPE must include openid")
    OIDC_PROVIDERS[_oidc_name] = {
        "issuer": _oidc_issuer,
        "client_id": _oidc_client_id,
        "client_secret": _oidc_client_secret,
        "redirect_uri": _oidc_redirect_uri,
        "scope": _oidc_scope,
        "allowed_hosts": _oidc_allowed_hosts,
    }

ALLOW_REGISTRATION = env_bool("CAMELLIA_REMOTE_ALLOW_REGISTRATION", False)
MAX_PASSWORD_LENGTH = 128

# Recording uploads contain highly sensitive session data. Keep each request
# bounded before Django materializes request.body, and cap the resulting file so
# a valid but compromised device session cannot exhaust the server volume.
RECORD_UPLOAD_MAX_CHUNK_BYTES = env_int(
    "CAMELLIA_REMOTE_RECORD_UPLOAD_MAX_CHUNK_BYTES",
    4 * 1024 * 1024,
    64 * 1024,
    64 * 1024 * 1024,
)
RECORD_UPLOAD_MAX_FILE_BYTES = env_int(
    "CAMELLIA_REMOTE_RECORD_UPLOAD_MAX_FILE_BYTES",
    10 * 1024 * 1024 * 1024,
    RECORD_UPLOAD_MAX_CHUNK_BYTES,
    1024 * 1024 * 1024 * 1024,
)
RECORD_UPLOAD_ROOT = Path(os.environ.get("CAMELLIA_REMOTE_RECORD_UPLOAD_ROOT", BASE_DIR / "records"))
DATA_UPLOAD_MAX_MEMORY_SIZE = RECORD_UPLOAD_MAX_CHUNK_BYTES
DATA_UPLOAD_MAX_NUMBER_FIELDS = env_int("CAMELLIA_REMOTE_DATA_UPLOAD_MAX_NUMBER_FIELDS", 1000, 100, 10000)
DATA_UPLOAD_MAX_NUMBER_FILES = 0
FILE_UPLOAD_PERMISSIONS = 0o600


DATABASE_URL = os.environ.get("CAMELLIA_REMOTE_DATABASE_URL", "").strip()
SQLITE_DB_PATH = os.environ.get("CAMELLIA_REMOTE_SQLITE_DB_PATH", "").strip()

LANGUAGE_CODE = os.environ.get("CAMELLIA_REMOTE_LANGUAGE_CODE", "zh-hans")

# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "api.apps.ApiConfig",
    "webui2.apps.Webui2Config",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.csp.ContentSecurityPolicyMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "camellia_remote_management.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates", DJANGO_FORMS_TEMPLATES],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.template.context_processors.csp",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "api.util.settings",
            ],
        },
    },
]
FORM_RENDERER = "django.forms.renderers.TemplatesSetting"

WSGI_APPLICATION = "camellia_remote_management.wsgi.application"


if not DATABASE_URL:
    if not DEBUG:
        raise ImproperlyConfigured("CAMELLIA_REMOTE_DATABASE_URL is required when CAMELLIA_REMOTE_DEBUG is false")
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": SQLITE_DB_PATH or (BASE_DIR / ".local/db.sqlite3"),
            "OPTIONS": {
                "timeout": env_int("CAMELLIA_REMOTE_SQLITE_BUSY_TIMEOUT_SECONDS", 20, 1, 300),
                "transaction_mode": "IMMEDIATE",
                "init_command": ("PRAGMA journal_mode=WAL;PRAGMA synchronous=NORMAL;PRAGMA busy_timeout=20000"),
            },
        }
    }
else:
    _database = urlsplit(DATABASE_URL)
    if (
        _database.scheme not in ("postgres", "postgresql")
        or not _database.hostname
        or not _database.username
        or _database.password is None
        or not _database.path.lstrip("/")
        or _database.query
        or _database.fragment
    ):
        raise ImproperlyConfigured(
            "CAMELLIA_REMOTE_DATABASE_URL must be a PostgreSQL URL with credentials and database name; "
            "configure TLS through CAMELLIA_REMOTE_DATABASE_SSLMODE"
        )
    _database_sslmode = os.environ.get("CAMELLIA_REMOTE_DATABASE_SSLMODE", "prefer" if DEBUG else "require").strip()
    if _database_sslmode not in (
        "disable",
        "allow",
        "prefer",
        "require",
        "verify-ca",
        "verify-full",
    ):
        raise ImproperlyConfigured("CAMELLIA_REMOTE_DATABASE_SSLMODE is invalid")
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": unquote(_database.path.lstrip("/")),
            "HOST": _database.hostname,
            "USER": unquote(_database.username),
            "PASSWORD": unquote(_database.password),
            "PORT": _database.port or 5432,
            "CONN_MAX_AGE": env_int("CAMELLIA_REMOTE_DATABASE_CONN_MAX_AGE", 60, 0, 3600),
            "CONN_HEALTH_CHECKS": True,
            "OPTIONS": {
                "connect_timeout": env_int("CAMELLIA_REMOTE_DATABASE_CONNECT_TIMEOUT", 10, 1, 60),
                "sslmode": _database_sslmode,
            },
        }
    }

# Password validation
# https://docs.djangoproject.com/en/3.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/3.1/topics/i18n/

# LANGUAGE_CODE = 'zh-hans'

TIME_ZONE = os.environ.get("CAMELLIA_REMOTE_TIME_ZONE", "Asia/Shanghai")

USE_I18N = True

USE_TZ = True

# ==========日志配置 开始=====================
LOG_LEVEL = os.environ.get("CAMELLIA_REMOTE_LOG_LEVEL", "INFO").upper()
LOG_LEVEL = LOG_LEVEL if LOG_LEVEL in ("CAMELLIA_REMOTE_DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL") else "INFO"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "[{asctime}] {levelname} {name}: {message}",
            "style": "{",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "level": LOG_LEVEL,
        },
    },
    "root": {
        "handlers": ["console"],
        "level": LOG_LEVEL,
    },
    "loggers": {
        "django": {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
        "api": {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
    },
}
# ==========日志配置 结束=====================


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.1/howto/static-files/

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "static_root"
STATICFILES_DIRS = [BASE_DIR / "static"]
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

SECURE_CSP = {
    "default-src": [CSP.SELF],
    "base-uri": [CSP.SELF],
    "connect-src": [CSP.SELF, "https:", "wss:"],
    "font-src": [CSP.SELF, "data:"],
    "form-action": [CSP.SELF],
    "frame-ancestors": [CSP.NONE],
    "img-src": [CSP.SELF, "data:", "blob:"],
    "object-src": [CSP.NONE],
    "script-src": [CSP.SELF, CSP.NONCE, CSP.WASM_UNSAFE_EVAL],
    # Flutter and Django form widgets create style declarations at runtime.
    # Script execution remains nonce-bound, and user-controlled color values
    # are normalized before rendering.
    "style-src": [CSP.SELF, CSP.UNSAFE_INLINE],
    "worker-src": [CSP.SELF, "blob:"],
}
SECURE_CSP_REPORT_ONLY = {}
X_FRAME_OPTIONS = "DENY"

MEDIA_ROOT = BASE_DIR / "records"
MEDIA_URL = "/records/"

LANGUAGES = (
    ("zh-hans", "中文简体"),
    ("en", "English"),
)

LOCALE_PATHS = (os.path.join(BASE_DIR, "locale"),)
