import logging
import time

from django.conf import settings
from django.db import connection
from django.urls import Resolver404, resolve

from api.address_book_errors import AuthorizationGenerationExhausted
from api.database_deadlines import (
    DatabaseOperationDeadlineExceeded,
    current_database_timeout_kind,
    database_operation_budget,
    database_timeout_kind,
)
from api.identifiers import InvalidIdentifier
from api.rate_limits import (
    RateLimitBackendUnavailable,
    RateLimitRejected,
    rate_limit_backend_response,
    rate_limit_response,
)
from api.request_utils import (
    STRICT_SHARE_JSON_ATTRIBUTE,
    InvalidJsonPayload,
    JsonPayloadTooLarge,
    UnsupportedJsonMediaType,
    load_json_form_field,
)
from api.response_contract import RESPONSE_MODE_JSON, apply_response_contract, json_error, response_mode
from api.response_security import SENSITIVE_RESPONSE_MARKER, protect_sensitive_response
from camellia_remote_management.access_logging import REQUEST_ID_HEADER
from camellia_remote_management.observability import (
    EVENT_ID_HEADER,
    TRACEPARENT_HEADER,
    begin_request_context,
    finish_request_context,
    log_structured_event,
    reset_request_context,
)

logger = logging.getLogger(__name__)


def json_envelope_error_response(exception):
    if isinstance(exception, JsonPayloadTooLarge):
        return json_error("json_payload_too_large", "JSON payload too large", status=413)
    if isinstance(exception, UnsupportedJsonMediaType):
        return json_error("unsupported_json_media_type", "Unsupported JSON media type", status=415)
    return json_error("invalid_json_payload", "Invalid JSON payload", status=400)


def _is_sensitive_response_route(request):
    resolver_match = getattr(request, "resolver_match", None)
    if resolver_match is None:
        try:
            resolver_match = resolve(request.path_info)
        except Resolver404:
            return False
    return bool(getattr(resolver_match.func, SENSITIVE_RESPONSE_MARKER, False))


class SafeAccessLogMiddleware:
    """Attach server-generated request correlation and a route-pattern label."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        context, token = begin_request_context(request)
        started_ns = time.monotonic_ns()
        try:
            response = self.get_response(request)
        except Exception as exc:
            finish_request_context(request, context)
            log_structured_event(
                logger,
                request,
                "http_request_failed",
                level="error",
                duration_us=max((time.monotonic_ns() - started_ns) // 1_000, 0),
                error_class=type(exc).__name__,
            )
            raise
        else:
            context = finish_request_context(request, context)
            apply_response_contract(request, response)
            if _is_sensitive_response_route(request):
                protect_sensitive_response(response)
            response[REQUEST_ID_HEADER] = context.request_id
            response[TRACEPARENT_HEADER] = context.traceparent
            if context.event_id:
                response[EVENT_ID_HEADER] = context.event_id
            log_structured_event(
                logger,
                request,
                "http_request_completed",
                status=getattr(response, "status_code", 0),
                duration_us=max((time.monotonic_ns() - started_ns) // 1_000, 0),
            )
            return response
        finally:
            reset_request_context(token)


class DatabaseDeadlineMiddleware:
    """Bound all request database work by the active monotonic profile."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        with database_operation_budget():
            response = self.get_response(request)
            # Django converts exceptions raised by inner middleware into an
            # HTTP response before outer middleware can catch them.  The SQL
            # execution wrapper therefore records the timeout in the active
            # operation context so session/rate-limit failures retain the same
            # fail-closed response contract as view failures.
            timeout_kind = current_database_timeout_kind()
            if timeout_kind and not getattr(response, "_camellia_database_timeout", False):
                return database_timeout_response(request, timeout_kind)
            return response


class StrictShareJsonPreflightMiddleware:
    """Bound and parse the only CSRF-protected embedded-JSON form before CSRF reads it."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method == "POST" and request.path_info == "/api/share":
            try:
                payload = load_json_form_field(
                    request,
                    "data",
                    max_bytes=settings.JSON_SHARE_EMBEDDED_MAX_BYTES,
                    max_form_bytes=settings.JSON_SHARE_FORM_MAX_BODY_BYTES,
                )
            except InvalidJsonPayload as exc:
                return json_envelope_error_response(exc)
            setattr(request, STRICT_SHARE_JSON_ATTRIBUTE, payload)
        return self.get_response(request)


class ApiExceptionMiddleware:
    """Translate bounded API parsing failures into stable client errors."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        timeout_kind = database_timeout_kind(exception)
        if isinstance(exception, DatabaseOperationDeadlineExceeded) or timeout_kind:
            return database_timeout_response(request, timeout_kind or "operation_deadline")
        if isinstance(exception, InvalidJsonPayload):
            return json_envelope_error_response(exception)
        if isinstance(exception, InvalidIdentifier):
            return json_error("invalid_identifier", "Invalid identifier", status=400)
        if isinstance(exception, AuthorizationGenerationExhausted):
            return json_error(
                "authorization_generation_exhausted",
                "Address-book authorization generation exhausted",
                status=409,
            )
        if isinstance(exception, RateLimitRejected):
            return rate_limit_response(exception.admission)
        if isinstance(exception, RateLimitBackendUnavailable):
            return rate_limit_backend_response()
        if response_mode(request) == RESPONSE_MODE_JSON:
            log_structured_event(
                logger,
                request,
                "http_request_exception",
                level="error",
                error_class=type(exception).__name__,
            )
            return json_error("internal_server_error", "Internal server error", status=500)
        return None


def database_timeout_response(request, timeout_kind):
    """Return the single fail-closed response for every request phase."""

    # PostgreSQL may have cancelled a statement or terminated an idle
    # transaction. Never return that connection to persistent reuse.
    connection.close()
    log_structured_event(
        logger,
        request,
        "database_operation_timeout",
        level="warning",
        timeout_kind=timeout_kind,
    )
    response = json_error(
        "database_operation_timeout",
        "Database operation deadline exceeded",
        status=503,
        retryable=False,
        result="unknown",
    )
    response["Retry-After"] = "1"
    response._camellia_database_timeout = True
    return response
