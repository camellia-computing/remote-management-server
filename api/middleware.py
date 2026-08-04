import secrets

from django.http import JsonResponse

from api.request_utils import InvalidJsonPayload
from camellia_remote_management.access_logging import (
    ACCESS_ROUTE_ENV,
    REQUEST_ID_ENV,
    REQUEST_ID_HEADER,
    normalized_route,
)


class SafeAccessLogMiddleware:
    """Attach server-generated request correlation and a route-pattern label."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_id = secrets.token_hex(16)
        request.META[REQUEST_ID_ENV] = request_id
        request.META[ACCESS_ROUTE_ENV] = "<unmatched>"
        try:
            response = self.get_response(request)
        finally:
            request.META[ACCESS_ROUTE_ENV] = normalized_route(getattr(request, "resolver_match", None))
        response[REQUEST_ID_HEADER] = request_id
        return response


class ApiExceptionMiddleware:
    """Translate bounded API parsing failures into stable client errors."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        if isinstance(exception, InvalidJsonPayload):
            return JsonResponse({"error": "Invalid JSON payload"}, status=400)
        return None
