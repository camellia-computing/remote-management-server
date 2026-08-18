"""Versioned, bounded Management HTTP response contracts."""

import json
import math
import re

from django.http import HttpResponse, HttpResponseBase, JsonResponse
from django.urls import Resolver404, resolve

RESPONSE_SCHEMA_VERSION = 1
RESPONSE_SCHEMA_HEADER = "X-Camellia-Response-Schema"
RESPONSE_KIND_HEADER = "X-Camellia-Response-Kind"
RESPONSE_MODE_MARKER = "camellia_response_mode"
RESPONSE_MODE_JSON = "json"
RESPONSE_MODE_BROWSER = "browser"
RESPONSE_MODE_BROWSER_JSON_POST = "browser_json_post"
MAX_RESPONSE_MESSAGE_CHARS = 256
MAX_ERROR_BODY_BYTES = 16 * 1024
_MACHINE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_SENSITIVE_DETAIL_KEY = re.compile(
    r"(?:secret|token|password|credential|private|authorization|cookie|proof|nonce|verifier|key_material)",
    re.IGNORECASE,
)
_RETRYABLE_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
_NO_BODY_STATUSES = frozenset({204, 304})


def _route_template(request):
    match = getattr(request, "resolver_match", None)
    route = getattr(match, "route", "") if match is not None else ""
    route = re.sub(r"[^A-Za-z0-9]+", "_", route).strip("_").lower()
    return route[:48] or "route"


def _error_code(request, response):
    return f"http_{response.status_code}_{_route_template(request)}"[:64]


def _bounded_message(value):
    if not isinstance(value, str) or not value:
        return "Request failed"
    return value[:MAX_RESPONSE_MESSAGE_CHARS]


def _safe_error_details(value, *, depth=0):
    """Keep error details bounded and exclude credential-shaped fields."""
    if depth >= 4:
        return None
    if isinstance(value, dict):
        result = {}
        for key, item in list(value.items())[:32]:
            if not isinstance(key, str) or _SENSITIVE_DETAIL_KEY.search(key):
                continue
            safe = _safe_error_details(item, depth=depth + 1)
            if safe is not None:
                result[key[:64]] = safe
        return result
    if isinstance(value, list):
        return [safe for item in value[:32] if (safe := _safe_error_details(item, depth=depth + 1)) is not None]
    if isinstance(value, str):
        return value[:MAX_RESPONSE_MESSAGE_CHARS]
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if -(1 << 63) <= value <= (1 << 63) - 1 else None
    if isinstance(value, float) and math.isfinite(value):
        return value
    return None


def _bounded_error_payload(payload):
    """Return a safe error body, dropping oversized optional details."""
    safe = _safe_error_details(payload)
    if not isinstance(safe, dict):
        return {}
    if len(_json_bytes(safe)) <= MAX_ERROR_BODY_BYTES:
        return safe
    return {
        key: safe[key] for key in ("response_schema_version", "code", "message", "retryable", "pending") if key in safe
    } | {"details_truncated": True}


def _response_mode(request):
    match = getattr(request, "resolver_match", None)
    if match is None:
        try:
            match = resolve(request.path_info)
        except Resolver404:
            match = None
    mode = getattr(getattr(match, "func", None), RESPONSE_MODE_MARKER, None)
    if mode == RESPONSE_MODE_BROWSER_JSON_POST:
        return RESPONSE_MODE_JSON if request.method == "POST" else RESPONSE_MODE_BROWSER
    if mode in {RESPONSE_MODE_JSON, RESPONSE_MODE_BROWSER}:
        return mode
    if request.path_info in {"/health/live", "/health/ready"}:
        return RESPONSE_MODE_JSON
    # An unmatched route below /api is an API typo, not a browser page.
    return RESPONSE_MODE_JSON if request.path_info.startswith("/api/") else None


def response_mode(request):
    """Return the declared response mode for middleware exception boundaries."""

    return _response_mode(request)


def _json_bytes(payload):
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _set_content(response, payload):
    response.content = _json_bytes(payload)
    response["Content-Type"] = "application/json"
    response["Content-Length"] = str(len(response.content))


def json_error(code, message, *, status, retryable=None, **details):
    """Build a canonical API error without a human-text compatibility alias."""

    if _MACHINE_CODE.fullmatch(code) is None:
        raise ValueError("Invalid response machine code")
    payload = _bounded_error_payload(
        {
            **details,
            "response_schema_version": RESPONSE_SCHEMA_VERSION,
            "code": code,
            "message": _bounded_message(message),
            "retryable": status in _RETRYABLE_STATUSES if retryable is None else bool(retryable),
        }
    )
    response = JsonResponse(payload, status=status)
    response[RESPONSE_KIND_HEADER] = "error"
    return response


def json_pending(code, message, *, retry_after=1, **details):
    """Build an explicit, retryable HTTP 202 state response."""

    if not 1 <= retry_after <= 60:
        raise ValueError("Invalid pending retry interval")
    response = json_error(
        code,
        message,
        status=202,
        retryable=True,
        pending=True,
        **details,
    )
    response[RESPONSE_KIND_HEADER] = "pending"
    response["Retry-After"] = str(retry_after)
    response["Cache-Control"] = "no-store"
    return response


def empty_success():
    """Return the only valid no-body mutation success shape."""

    response = HttpResponse(status=204)
    response["Content-Type"] = "application/json"
    response[RESPONSE_KIND_HEADER] = "empty"
    return response


def _normalized_error_payload(request, response, payload):
    if isinstance(payload, dict):
        result = dict(payload)
        raw_code = result.pop("code", None)
        raw_message = result.pop("message", None)
        if raw_message is None:
            raw_message = result.pop("error", None)
        else:
            result.pop("error", None)
        if raw_message is None:
            raw_message = result.pop("msg", None)
        else:
            result.pop("msg", None)
    else:
        result = {}
        raw_code = None
        raw_message = payload
    code = (
        raw_code if isinstance(raw_code, str) and _MACHINE_CODE.fullmatch(raw_code) else _error_code(request, response)
    )
    result = _safe_error_details(result) or {}
    result.update(
        {
            "response_schema_version": RESPONSE_SCHEMA_VERSION,
            "code": code,
            "message": _bounded_message(raw_message),
            "retryable": response.status_code in _RETRYABLE_STATUSES,
        }
    )
    return _bounded_error_payload(result)


def apply_response_contract(request, response):
    """Attach and enforce Management response contract v1.

    Endpoint-specific successful data remains endpoint-specific. JSON objects
    carry the version in-body; lists, downloads and browser HTML carry it in
    the transport header. Every machine API error is a canonical JSON object.
    """

    if not isinstance(response, HttpResponseBase):
        return response
    mode = _response_mode(request)
    if mode is None:
        return response

    response[RESPONSE_SCHEMA_HEADER] = str(RESPONSE_SCHEMA_VERSION)
    status = int(getattr(response, "status_code", 0) or 0)
    streaming = bool(getattr(response, "streaming", False))
    content_type = str(response.get("Content-Type", "")).lower()
    payload = None
    if not streaming and "application/json" in content_type and status not in _NO_BODY_STATUSES:
        try:
            payload = json.loads(response.content.decode("utf-8"))
        except (UnicodeDecodeError, TypeError, ValueError):
            payload = None

    if (
        status >= 400
        and (mode == RESPONSE_MODE_JSON or payload is not None)
        and request.method != "HEAD"
        and not streaming
    ):
        payload = _normalized_error_payload(request, response, payload)
        _set_content(response, payload)
        response["Cache-Control"] = "no-store"
    elif isinstance(payload, dict):
        payload["response_schema_version"] = RESPONSE_SCHEMA_VERSION
        _set_content(response, payload)

    if status >= 400:
        kind = "error"
    elif status == 202 and isinstance(payload, dict) and payload.get("pending") is True:
        kind = "pending"
    elif status == 202:
        kind = "accepted"
    elif status in _NO_BODY_STATUSES:
        kind = "empty"
    elif response.get("Location"):
        kind = "redirect"
    elif streaming:
        kind = "download" if response.get("Content-Disposition") else "stream"
    else:
        kind = "success"
    response[RESPONSE_KIND_HEADER] = kind
    return response
