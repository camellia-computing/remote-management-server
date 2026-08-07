import logging
import time

from django.http import JsonResponse
from django.urls import Resolver404, resolve

from api.address_book_errors import AuthorizationGenerationExhausted
from api.rate_limits import (
    RateLimitBackendUnavailable,
    RateLimitRejected,
    rate_limit_backend_response,
    rate_limit_response,
)
from api.request_utils import InvalidJsonPayload
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


class ApiExceptionMiddleware:
    """Translate bounded API parsing failures into stable client errors."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        if isinstance(exception, InvalidJsonPayload):
            return JsonResponse({"error": "Invalid JSON payload"}, status=400)
        if isinstance(exception, AuthorizationGenerationExhausted):
            return JsonResponse(
                {"error": "Address-book authorization generation exhausted"},
                status=409,
            )
        if isinstance(exception, RateLimitRejected):
            return rate_limit_response(exception.admission)
        if isinstance(exception, RateLimitBackendUnavailable):
            return rate_limit_backend_response()
        return None
