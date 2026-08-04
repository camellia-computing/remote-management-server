import base64
import binascii
import hashlib
import ipaddress
import os
import re
from pathlib import Path
from types import MappingProxyType
from urllib.parse import unquote, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import django
from django.core.exceptions import ImproperlyConfigured
from django.utils.csp import CSP

BASE_DIR = Path(__file__).resolve().parent.parent
DJANGO_FORMS_TEMPLATES = Path(django.__file__).resolve().parent / "forms" / "templates"


def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False
    raise ImproperlyConfigured(f"{name} must be true or false")


def env_csv(name, default=None):
    value = os.environ.get(name, "").strip()
    if not value:
        return list(default or [])
    return [item.strip() for item in value.replace(";", ",").split(",") if item.strip()]


def env_int(name, default, min_value=None, max_value=None):
    raw_value = os.environ.get(name)
    if raw_value is None:
        value = default
    else:
        try:
            value = int(raw_value.strip())
        except ValueError as exc:
            raise ImproperlyConfigured(f"{name} must be an integer") from exc
    if min_value is not None and value < min_value:
        raise ImproperlyConfigured(f"{name} must be at least {min_value}")
    if max_value is not None and value > max_value:
        raise ImproperlyConfigured(f"{name} must be at most {max_value}")
    return value


def env_choice(name, default, choices):
    value = os.environ.get(name, default).strip().upper()
    if value not in choices:
        allowed = ", ".join(sorted(choices))
        raise ImproperlyConfigured(f"{name} must be one of: {allowed}")
    return value


def canonical_base64_bytes(value, expected_size):
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(decoded) != expected_size or base64.b64encode(decoded).decode("ascii") != value:
        return None
    return decoded


DATA_ENCRYPTION_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
MAX_DATA_ENCRYPTION_KEYS = 8


def data_encryption_key_id(value, setting_name):
    normalized = value.strip().lower()
    if value != normalized or not DATA_ENCRYPTION_KEY_ID_RE.fullmatch(normalized):
        raise ImproperlyConfigured(
            f"{setting_name} must be a lowercase key ID containing 1-32 letters, digits, '.', '_' or '-'"
        )
    return normalized


def data_encryption_legacy_keys(value):
    keys = {}
    if not value.strip():
        return keys
    for entry in value.split(","):
        key_id_raw, separator, encoded_key = entry.strip().partition(":")
        if not separator:
            raise ImproperlyConfigured(
                "CAMELLIA_REMOTE_DATA_ENCRYPTION_LEGACY_KEYS entries must use key-id:canonical-base64"
            )
        key_id = data_encryption_key_id(
            key_id_raw,
            "CAMELLIA_REMOTE_DATA_ENCRYPTION_LEGACY_KEYS key ID",
        )
        key = canonical_base64_bytes(encoded_key, 32)
        if key is None:
            raise ImproperlyConfigured(
                "CAMELLIA_REMOTE_DATA_ENCRYPTION_LEGACY_KEYS values must encode exactly 32 bytes"
            )
        if key_id in keys:
            raise ImproperlyConfigured("CAMELLIA_REMOTE_DATA_ENCRYPTION_LEGACY_KEYS contains a duplicate key ID")
        if key in keys.values():
            raise ImproperlyConfigured("CAMELLIA_REMOTE_DATA_ENCRYPTION_LEGACY_KEYS aliases one key under multiple IDs")
        keys[key_id] = key
    if len(keys) >= MAX_DATA_ENCRYPTION_KEYS:
        raise ImproperlyConfigured(
            f"CAMELLIA_REMOTE_DATA_ENCRYPTION_LEGACY_KEYS supports at most {MAX_DATA_ENCRYPTION_KEYS - 1} keys"
        )
    return keys


def valid_https_url(value, *, allow_query=True):
    if not isinstance(value, str) or not value or len(value) > 2048:
        return False
    try:
        parsed = urlsplit(value)
        _port = parsed.port
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


def valid_https_origin(value):
    if not valid_https_url(value, allow_query=False):
        return False
    parsed = urlsplit(value)
    return parsed.path in ("", "/") and value == f"{parsed.scheme}://{parsed.netloc}"


DEBUG = env_bool("CAMELLIA_REMOTE_DEBUG", False)
SECRET_KEY = os.environ.get("CAMELLIA_REMOTE_SECRET_KEY", "").strip()
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = "dev-only-insecure-secret-key"  # noqa: S105 - isolated debug default
    else:
        raise ImproperlyConfigured("CAMELLIA_REMOTE_SECRET_KEY must be set when CAMELLIA_REMOTE_DEBUG is false")
if not DEBUG and (len(SECRET_KEY) < 50 or SECRET_KEY.startswith("dev-only-") or "replace-with" in SECRET_KEY.lower()):
    raise ImproperlyConfigured("CAMELLIA_REMOTE_SECRET_KEY must be an unpredictable value of at least 50 characters")

_data_encryption_key = os.environ.get("CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY", "").strip()
if _data_encryption_key:
    DATA_ENCRYPTION_KEY_BYTES = canonical_base64_bytes(_data_encryption_key, 32)
    if DATA_ENCRYPTION_KEY_BYTES is None:
        raise ImproperlyConfigured("CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY must encode exactly 32 bytes")
elif DEBUG:
    DATA_ENCRYPTION_KEY_BYTES = hashlib.sha256(f"development-data-key:{SECRET_KEY}".encode()).digest()
else:
    raise ImproperlyConfigured("CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY is required when CAMELLIA_REMOTE_DEBUG is false")

_data_encryption_key_id = os.environ.get("CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY_ID", "").strip()
if not _data_encryption_key_id:
    if DEBUG:
        _data_encryption_key_id = "debug-primary"
    else:
        raise ImproperlyConfigured(
            "CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY_ID is required when CAMELLIA_REMOTE_DEBUG is false"
        )
DATA_ENCRYPTION_PRIMARY_KEY_ID = data_encryption_key_id(
    _data_encryption_key_id,
    "CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY_ID",
)
_data_encryption_keys = data_encryption_legacy_keys(
    os.environ.get("CAMELLIA_REMOTE_DATA_ENCRYPTION_LEGACY_KEYS", "")
)
if DATA_ENCRYPTION_PRIMARY_KEY_ID in _data_encryption_keys:
    raise ImproperlyConfigured("The primary data-encryption key ID must not also be a legacy key ID")
if DATA_ENCRYPTION_KEY_BYTES in _data_encryption_keys.values():
    raise ImproperlyConfigured("The primary data-encryption key must not be aliased as a legacy key")
_data_encryption_keys[DATA_ENCRYPTION_PRIMARY_KEY_ID] = DATA_ENCRYPTION_KEY_BYTES
DATA_ENCRYPTION_KEYS = MappingProxyType(_data_encryption_keys)
DATA_ENCRYPTION_V1_KEY_ID = data_encryption_key_id(
    os.environ.get(
        "CAMELLIA_REMOTE_DATA_ENCRYPTION_V1_KEY_ID",
        DATA_ENCRYPTION_PRIMARY_KEY_ID,
    ),
    "CAMELLIA_REMOTE_DATA_ENCRYPTION_V1_KEY_ID",
)
if DATA_ENCRYPTION_V1_KEY_ID not in DATA_ENCRYPTION_KEYS:
    raise ImproperlyConfigured("CAMELLIA_REMOTE_DATA_ENCRYPTION_V1_KEY_ID must identify a configured key")

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
ALLOWED_HOSTS = env_csv("CAMELLIA_REMOTE_ALLOWED_HOSTS", ["127.0.0.1", "localhost"])
CSRF_TRUSTED_ORIGINS = env_csv("CAMELLIA_REMOTE_CSRF_TRUSTED_ORIGINS", ["http://127.0.0.1:21114"])
if not DEBUG:
    if "CAMELLIA_REMOTE_ALLOWED_HOSTS" not in os.environ or not ALLOWED_HOSTS:
        raise ImproperlyConfigured("CAMELLIA_REMOTE_ALLOWED_HOSTS is required in production")
    if "*" in ALLOWED_HOSTS:
        raise ImproperlyConfigured("CAMELLIA_REMOTE_ALLOWED_HOSTS must not contain a wildcard in production")
    if "CAMELLIA_REMOTE_CSRF_TRUSTED_ORIGINS" not in os.environ or not CSRF_TRUSTED_ORIGINS:
        raise ImproperlyConfigured("CAMELLIA_REMOTE_CSRF_TRUSTED_ORIGINS is required in production")
    if any(not valid_https_origin(origin) for origin in CSRF_TRUSTED_ORIGINS):
        raise ImproperlyConfigured("CAMELLIA_REMOTE_CSRF_TRUSTED_ORIGINS must contain only HTTPS origins")
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
if not DEBUG and not _secure_tls:
    raise ImproperlyConfigured("CAMELLIA_REMOTE_SECURE_TLS must be true in production")
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
if not DEBUG:
    if not valid_https_url(API_SERVER):
        raise ImproperlyConfigured("CAMELLIA_REMOTE_API_SERVER must be an HTTPS URL in production")
    _api_origin = urlsplit(API_SERVER)
    _api_origin = f"{_api_origin.scheme}://{_api_origin.netloc}"
    if _api_origin not in CSRF_TRUSTED_ORIGINS:
        raise ImproperlyConfigured(
            "CAMELLIA_REMOTE_CSRF_TRUSTED_ORIGINS must include the CAMELLIA_REMOTE_API_SERVER origin"
        )
    _id_server_endpoints = [endpoint for endpoint in re.split(r"[,;\s]+", ID_SERVER) if endpoint]
    _relay_server_endpoints = [endpoint for endpoint in re.split(r"[,;\s]+", RELAY_SERVER) if endpoint]
    if not _id_server_endpoints:
        raise ImproperlyConfigured("CAMELLIA_REMOTE_ID_SERVER is required in production")
    for endpoint in (*_id_server_endpoints, *_relay_server_endpoints):
        try:
            parsed_endpoint = urlsplit(endpoint)
            endpoint_port = parsed_endpoint.port
        except ValueError as exc:
            raise ImproperlyConfigured("Remote server endpoints must be valid WSS URLs") from exc
        if (
            parsed_endpoint.scheme != "wss"
            or not parsed_endpoint.hostname
            or parsed_endpoint.username is not None
            or parsed_endpoint.password is not None
            or parsed_endpoint.fragment
            or endpoint_port is None
        ):
            raise ImproperlyConfigured(
                "CAMELLIA_REMOTE_ID_SERVER and CAMELLIA_REMOTE_RELAY_SERVER must contain WSS URLs with explicit ports"
            )
    if canonical_base64_bytes(RS_PUB_KEY, 32) is None:
        raise ImproperlyConfigured("CAMELLIA_REMOTE_RS_PUB_KEY must encode exactly 32 bytes")
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
LOGIN_ATTEMPT_RETENTION_MINUTES = env_int(
    "CAMELLIA_REMOTE_LOGIN_ATTEMPT_RETENTION_MINUTES",
    15,
    5,
    24 * 60,
)
OIDC_PENDING_RETENTION_MINUTES = env_int(
    "CAMELLIA_REMOTE_OIDC_PENDING_RETENTION_MINUTES",
    5,
    2,
    60,
)
SHARE_LINK_RETENTION_DAYS = env_int(
    "CAMELLIA_REMOTE_SHARE_LINK_RETENTION_DAYS",
    30,
    1,
    365,
)

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
if not RECORD_UPLOAD_ROOT.is_absolute():
    raise ImproperlyConfigured("CAMELLIA_REMOTE_RECORD_UPLOAD_ROOT must be an absolute path")
DATA_UPLOAD_MAX_MEMORY_SIZE = RECORD_UPLOAD_MAX_CHUNK_BYTES
DATA_UPLOAD_MAX_NUMBER_FIELDS = env_int("CAMELLIA_REMOTE_DATA_UPLOAD_MAX_NUMBER_FIELDS", 1000, 100, 10000)
DATA_UPLOAD_MAX_NUMBER_FILES = 0
FILE_UPLOAD_PERMISSIONS = 0o600


DATABASE_URL = os.environ.get("CAMELLIA_REMOTE_DATABASE_URL", "").strip()
DATABASE_HOST = os.environ.get("CAMELLIA_REMOTE_DATABASE_HOST", "").strip()
DATABASE_NAME = os.environ.get("CAMELLIA_REMOTE_DATABASE_NAME", "").strip()
DATABASE_USER = os.environ.get("CAMELLIA_REMOTE_DATABASE_USER", "").strip()
DATABASE_PASSWORD = os.environ.get("CAMELLIA_REMOTE_DATABASE_PASSWORD", "")
SQLITE_DB_PATH = os.environ.get("CAMELLIA_REMOTE_SQLITE_DB_PATH", "").strip()
if SQLITE_DB_PATH and not Path(SQLITE_DB_PATH).is_absolute():
    raise ImproperlyConfigured("CAMELLIA_REMOTE_SQLITE_DB_PATH must be an absolute path")

LANGUAGE_CODE = os.environ.get("CAMELLIA_REMOTE_LANGUAGE_CODE", "zh-hans")

# Application definition

INSTALLED_APPS = [
    "api.admin_config.CamelliaAdminConfig",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "api.apps.ApiConfig",
    "webui2.apps.Webui2Config",
]

MIDDLEWARE = [
    "api.middleware.SafeAccessLogMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.csp.ContentSecurityPolicyMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "api.middleware.ApiExceptionMiddleware",
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


_discrete_database_names = (
    "CAMELLIA_REMOTE_DATABASE_HOST",
    "CAMELLIA_REMOTE_DATABASE_NAME",
    "CAMELLIA_REMOTE_DATABASE_USER",
    "CAMELLIA_REMOTE_DATABASE_PASSWORD",
)
_has_discrete_database_settings = any(name in os.environ for name in _discrete_database_names)
if DATABASE_URL and _has_discrete_database_settings:
    raise ImproperlyConfigured(
        "CAMELLIA_REMOTE_DATABASE_URL cannot be combined with discrete database connection settings"
    )


def _database_text(value, name, max_bytes):
    if not value or "\x00" in value or len(value.encode("utf-8")) > max_bytes:
        raise ImproperlyConfigured(f"{name} must be a non-empty value of at most {max_bytes} UTF-8 bytes")
    return value


def _database_host(value):
    if not value or len(value) > 253 or any(character.isspace() for character in value):
        raise ImproperlyConfigured("CAMELLIA_REMOTE_DATABASE_HOST is invalid")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if not re.fullmatch(
        r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
        r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
        value,
    ):
        raise ImproperlyConfigured("CAMELLIA_REMOTE_DATABASE_HOST is invalid")
    return value


def _database_tls_options(database_host):
    sslmode = os.environ.get(
        "CAMELLIA_REMOTE_DATABASE_SSLMODE",
        "prefer" if DEBUG else "verify-full",
    ).strip()
    if sslmode not in (
        "disable",
        "allow",
        "prefer",
        "require",
        "verify-ca",
        "verify-full",
    ):
        raise ImproperlyConfigured("CAMELLIA_REMOTE_DATABASE_SSLMODE is invalid")
    local_hosts = {"127.0.0.1", "::1", "localhost", "postgres"}
    if not DEBUG and database_host not in local_hosts and sslmode != "verify-full":
        raise ImproperlyConfigured(
            "external production databases must use CAMELLIA_REMOTE_DATABASE_SSLMODE=verify-full"
        )

    options = {
        "connect_timeout": env_int("CAMELLIA_REMOTE_DATABASE_CONNECT_TIMEOUT", 10, 1, 60),
        "sslmode": sslmode,
    }
    certificate_options = {
        "CAMELLIA_REMOTE_DATABASE_SSLROOTCERT": "sslrootcert",
        "CAMELLIA_REMOTE_DATABASE_SSLCERT": "sslcert",
        "CAMELLIA_REMOTE_DATABASE_SSLKEY": "sslkey",
    }
    configured_certificates = {}
    for environment_name, option_name in certificate_options.items():
        value = os.environ.get(environment_name, "").strip()
        if value:
            if not Path(value).is_absolute():
                raise ImproperlyConfigured(f"{environment_name} must be an absolute path")
            options[option_name] = value
            configured_certificates[option_name] = value
    if ("sslcert" in configured_certificates) != ("sslkey" in configured_certificates):
        raise ImproperlyConfigured(
            "CAMELLIA_REMOTE_DATABASE_SSLCERT and CAMELLIA_REMOTE_DATABASE_SSLKEY must be configured together"
        )
    return options


if not DATABASE_URL and not _has_discrete_database_settings:
    if not DEBUG:
        raise ImproperlyConfigured(
            "a PostgreSQL connection is required through CAMELLIA_REMOTE_DATABASE_URL "
            "or the discrete database settings when CAMELLIA_REMOTE_DEBUG is false"
        )
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": SQLITE_DB_PATH or (BASE_DIR / "db.sqlite3"),
            "OPTIONS": {
                "timeout": env_int("CAMELLIA_REMOTE_SQLITE_BUSY_TIMEOUT_SECONDS", 20, 1, 300),
                "transaction_mode": "IMMEDIATE",
                "init_command": ("PRAGMA journal_mode=WAL;PRAGMA synchronous=NORMAL;PRAGMA busy_timeout=20000"),
            },
        }
    }
elif _has_discrete_database_settings:
    missing_database_settings = [
        name
        for name, value in (
            ("CAMELLIA_REMOTE_DATABASE_HOST", DATABASE_HOST),
            ("CAMELLIA_REMOTE_DATABASE_NAME", DATABASE_NAME),
            ("CAMELLIA_REMOTE_DATABASE_USER", DATABASE_USER),
            ("CAMELLIA_REMOTE_DATABASE_PASSWORD", DATABASE_PASSWORD),
        )
        if not value
    ]
    if missing_database_settings:
        raise ImproperlyConfigured(
            "discrete database settings must be configured together; missing " + ", ".join(missing_database_settings)
        )
    database_host = _database_host(DATABASE_HOST)
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": _database_text(DATABASE_NAME, "CAMELLIA_REMOTE_DATABASE_NAME", 63),
            "HOST": database_host,
            "USER": _database_text(DATABASE_USER, "CAMELLIA_REMOTE_DATABASE_USER", 63),
            "PASSWORD": _database_text(DATABASE_PASSWORD, "CAMELLIA_REMOTE_DATABASE_PASSWORD", 1024),
            "PORT": env_int("CAMELLIA_REMOTE_DATABASE_PORT", 5432, 1, 65535),
            "CONN_MAX_AGE": env_int("CAMELLIA_REMOTE_DATABASE_CONN_MAX_AGE", 60, 0, 3600),
            "CONN_HEALTH_CHECKS": True,
            "OPTIONS": _database_tls_options(database_host),
        }
    }
else:
    try:
        _database = urlsplit(DATABASE_URL)
        _database_port = _database.port
    except ValueError as exc:
        raise ImproperlyConfigured("CAMELLIA_REMOTE_DATABASE_URL is invalid") from exc
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
    database_host = _database.hostname
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": _database_text(
                unquote(_database.path.lstrip("/")),
                "CAMELLIA_REMOTE_DATABASE_URL database name",
                63,
            ),
            "HOST": _database.hostname,
            "USER": _database_text(
                unquote(_database.username),
                "CAMELLIA_REMOTE_DATABASE_URL username",
                63,
            ),
            "PASSWORD": _database_text(
                unquote(_database.password),
                "CAMELLIA_REMOTE_DATABASE_URL password",
                1024,
            ),
            "PORT": _database_port or 5432,
            "CONN_MAX_AGE": env_int("CAMELLIA_REMOTE_DATABASE_CONN_MAX_AGE", 60, 0, 3600),
            "CONN_HEALTH_CHECKS": True,
            "OPTIONS": _database_tls_options(database_host),
        }
    }

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


TIME_ZONE = os.environ.get("CAMELLIA_REMOTE_TIME_ZONE", "UTC").strip()
try:
    ZoneInfo(TIME_ZONE)
except (ValueError, ZoneInfoNotFoundError) as exc:
    raise ImproperlyConfigured("CAMELLIA_REMOTE_TIME_ZONE must be a valid IANA time zone") from exc

USE_I18N = True

USE_TZ = True

LOG_LEVEL = env_choice(
    "CAMELLIA_REMOTE_LOG_LEVEL",
    "INFO",
    {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"},
).upper()

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
    "filters": {
        "safe_django_request": {
            "()": "camellia_remote_management.access_logging.SafeDjangoRequestFilter",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "filters": ["safe_django_request"],
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
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "static_root"
STATICFILES_DIRS = [BASE_DIR / "static"]
# pytest-django temporarily overrides DEBUG after settings are loaded. Keep the
# intended development mode explicit so tests do not scan an uncollected root.
WHITENOISE_AUTOREFRESH = DEBUG
WHITENOISE_USE_FINDERS = DEBUG
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

MEDIA_ROOT = RECORD_UPLOAD_ROOT
MEDIA_URL = "/records/"

LANGUAGES = (
    ("zh-hans", "中文简体"),
    ("en", "English"),
)

LOCALE_PATHS = (os.path.join(BASE_DIR, "locale"),)
