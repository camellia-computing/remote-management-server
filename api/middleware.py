from django.http import JsonResponse

from api.request_utils import InvalidJsonPayload


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
