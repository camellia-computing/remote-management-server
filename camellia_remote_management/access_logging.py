import re
from logging import Filter

from gunicorn.glogging import Logger

ACCESS_ROUTE_ENV = "camellia.access_route"
REQUEST_ID_ENV = "camellia.request_id"
TRACE_ID_ENV = "camellia.trace_id"
SPAN_ID_ENV = "camellia.span_id"
EVENT_ID_ENV = "camellia.event_id"
REQUEST_ID_HEADER = "X-Request-ID"
SAFE_ACCESS_LOG_FORMAT = (
    "method=%(m)s route=%(route)s status=%(s)s bytes=%(B)s duration_us=%(D)s "
    "request_id=%(request_id)s trace_id=%(trace_id)s span_id=%(span_id)s event_id=%(event_id)s"
)

_METHOD_RE = re.compile(r"[A-Z]{1,16}\Z", re.ASCII)
_REQUEST_ID_RE = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_TRACE_ID_RE = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_SPAN_ID_RE = re.compile(r"[0-9a-f]{16}\Z", re.ASCII)
_EVENT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z",
    re.ASCII,
)
_ROUTE_RE = re.compile(r"[!-~]{1,256}\Z", re.ASCII)
_STATUS_RE = re.compile(r"[1-5][0-9]{2}\Z", re.ASCII)


def normalized_route(resolver_match):
    """Return a bounded label derived only from the configured URL pattern."""
    route = getattr(resolver_match, "route", None)
    if not isinstance(route, str):
        return "<unmatched>"
    route = route.removeprefix("^").removesuffix("$")
    route = f"/{route}" if route else "/"
    if not _ROUTE_RE.fullmatch(route):
        return "<invalid-route>"
    return route


def _safe_method(environ):
    method = environ.get("REQUEST_METHOD")
    if isinstance(method, str) and _METHOD_RE.fullmatch(method):
        return method
    return "INVALID"


def _safe_route(environ):
    route = environ.get(ACCESS_ROUTE_ENV)
    if isinstance(route, str) and (route in {"<unmatched>", "<invalid-route>"} or _ROUTE_RE.fullmatch(route)):
        return route
    return "<unmatched>"


def safe_request_id(environ):
    request_id = environ.get(REQUEST_ID_ENV)
    if isinstance(request_id, str) and _REQUEST_ID_RE.fullmatch(request_id):
        return request_id
    return "<missing>"


def _safe_correlation(environ, key, pattern, *, allow_missing=False):
    value = environ.get(key)
    if isinstance(value, str) and pattern.fullmatch(value) and value.strip("0"):
        return value
    return "-" if allow_missing else "<missing>"


def _safe_status(resp):
    status = str(getattr(resp, "status", "")).split(None, 1)[0]
    return status if _STATUS_RE.fullmatch(status) else "000"


def _safe_bytes(resp):
    sent = getattr(resp, "sent", None)
    return sent if isinstance(sent, int) and sent >= 0 else 0


def _duration_microseconds(request_time):
    try:
        duration = (request_time.days * 86_400 + request_time.seconds) * 1_000_000 + request_time.microseconds
    except (AttributeError, TypeError):
        return 0
    return max(duration, 0)


class SafeAccessLogger(Logger):
    """Expose only fixed-cardinality, non-secret atoms to Gunicorn access logs."""

    def atoms(self, resp, req, environ, request_time):
        # Do not call Logger.atoms(): it materializes the raw target, query,
        # Referer, user agent, request headers and WSGI environment. Keeping
        # those atoms unavailable makes an accidental default format fail safe.
        return {
            "m": _safe_method(environ),
            "route": _safe_route(environ),
            "s": _safe_status(resp),
            "B": _safe_bytes(resp),
            "D": _duration_microseconds(request_time),
            "request_id": safe_request_id(environ),
            "trace_id": _safe_correlation(environ, TRACE_ID_ENV, _TRACE_ID_RE),
            "span_id": _safe_correlation(environ, SPAN_ID_ENV, _SPAN_ID_RE),
            "event_id": _safe_correlation(environ, EVENT_ID_ENV, _EVENT_ID_RE, allow_missing=True),
        }


class SafeDjangoRequestFilter(Filter):
    """Replace Django's raw request-path error message with bounded context."""

    def filter(self, record):
        request = getattr(record, "request", None)
        if request is None:
            return True
        status = str(getattr(record, "status_code", ""))
        if not _STATUS_RE.fullmatch(status):
            status = "000"
        environ = getattr(request, "META", {})
        record.msg = "request status=%s route=%s request_id=%s trace_id=%s span_id=%s event_id=%s"
        record.args = (
            status,
            normalized_route(getattr(request, "resolver_match", None)),
            safe_request_id(environ),
            _safe_correlation(environ, TRACE_ID_ENV, _TRACE_ID_RE),
            _safe_correlation(environ, SPAN_ID_ENV, _SPAN_ID_RE),
            _safe_correlation(environ, EVENT_ID_ENV, _EVENT_ID_RE, allow_missing=True),
        )
        return True
