import ipaddress
import json
import math
import re
import unicodedata

from django.conf import settings
from django.core.exceptions import RequestDataTooBig, TooManyFieldsSent, TooManyFilesSent
from django.http import UnreadablePostError
from django.http.multipartparser import MultiPartParserError

MAX_JSON_DEPTH = 64
MAX_JSON_CONTAINER_ITEMS = 10_000
MAX_JSON_TOTAL_NODES = 250_000
MAX_JSON_KEY_BYTES = 256
MAX_JSON_STRING_BYTES = 64 * 1024
MAX_JSON_NUMBER_CHARACTERS = 128
STRICT_SHARE_JSON_ATTRIBUTE = "_camellia_strict_share_json"
_MULTIPART_BOUNDARY = re.compile(r"[0-9A-Za-z'()+_,./:=?-]{1,70}\Z")


class InvalidJsonPayload(ValueError):
    """Raised when an endpoint receives an ambiguous or malformed JSON envelope."""


class JsonPayloadTooLarge(InvalidJsonPayload):
    """Raised before parsing when a route-specific byte budget is exceeded."""


class UnsupportedJsonMediaType(InvalidJsonPayload):
    """Raised when JSON arrives outside an explicitly supported media container."""


def _parse_media_type(raw_value):
    if not isinstance(raw_value, str) or not raw_value or len(raw_value) > 255:
        raise UnsupportedJsonMediaType("A bounded Content-Type is required")
    if any(ord(character) < 32 or ord(character) == 127 for character in raw_value):
        raise UnsupportedJsonMediaType("Content-Type contains control characters")

    parts = raw_value.split(";")
    media_type = parts[0].strip().lower()
    if not media_type:
        raise UnsupportedJsonMediaType("Content-Type is missing a media type")
    parameters = {}
    for raw_parameter in parts[1:]:
        if not raw_parameter.strip() or "=" not in raw_parameter:
            raise UnsupportedJsonMediaType("Content-Type parameters are malformed")
        raw_name, raw_parameter_value = raw_parameter.split("=", 1)
        name = raw_name.strip().lower()
        value = raw_parameter_value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        elif value.startswith('"') or value.endswith('"'):
            raise UnsupportedJsonMediaType("Content-Type parameter quoting is malformed")
        if not name or not value or name in parameters or "\\" in value or '"' in value:
            raise UnsupportedJsonMediaType("Content-Type parameters are ambiguous")
        parameters[name] = value
    return media_type, parameters


def _require_json_media_type(request):
    if request.META.get("HTTP_CONTENT_ENCODING") or request.META.get("CONTENT_ENCODING"):
        raise UnsupportedJsonMediaType("Encoded JSON bodies are not accepted")
    media_type, parameters = _parse_media_type(request.META.get("CONTENT_TYPE", ""))
    if media_type != "application/json":
        raise UnsupportedJsonMediaType("Content-Type must be application/json")
    if set(parameters) - {"charset"}:
        raise UnsupportedJsonMediaType("JSON Content-Type has unsupported parameters")
    if parameters.get("charset", "utf-8").lower() != "utf-8":
        raise UnsupportedJsonMediaType("JSON charset must be UTF-8")


def _require_form_media_type(request):
    if request.META.get("HTTP_CONTENT_ENCODING") or request.META.get("CONTENT_ENCODING"):
        raise UnsupportedJsonMediaType("Encoded form bodies are not accepted")
    media_type, parameters = _parse_media_type(request.META.get("CONTENT_TYPE", ""))
    if media_type == "application/x-www-form-urlencoded":
        if set(parameters) - {"charset"}:
            raise UnsupportedJsonMediaType("Form Content-Type has unsupported parameters")
        if parameters.get("charset", "utf-8").lower() != "utf-8":
            raise UnsupportedJsonMediaType("Form charset must be UTF-8")
        return
    if media_type == "multipart/form-data":
        if set(parameters) != {"boundary"} or not _MULTIPART_BOUNDARY.fullmatch(parameters["boundary"]):
            raise UnsupportedJsonMediaType("Multipart boundary is missing or invalid")
        return
    raise UnsupportedJsonMediaType("Embedded JSON requires a supported form media type")


def _content_length(request):
    transfer_encoding = request.META.get("HTTP_TRANSFER_ENCODING") or request.META.get("TRANSFER_ENCODING")
    if transfer_encoding:
        raise InvalidJsonPayload("Transfer-Encoding is not accepted for bounded JSON envelopes")
    raw_length = request.META.get("CONTENT_LENGTH")
    if not isinstance(raw_length, str) or not raw_length or len(raw_length) > 20 or not raw_length.isascii():
        raise InvalidJsonPayload("A canonical Content-Length is required")
    if not raw_length.isdecimal() or (len(raw_length) > 1 and raw_length.startswith("0")):
        raise InvalidJsonPayload("Content-Length must be canonical decimal")
    return int(raw_length)


def _bounded_request_body(request, max_bytes):
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    declared_length = _content_length(request)
    if declared_length > max_bytes:
        raise JsonPayloadTooLarge("Payload exceeds the route byte budget")
    try:
        body = request.body
    except RequestDataTooBig as exc:
        raise JsonPayloadTooLarge("Payload exceeds the server materialization budget") from exc
    except (AssertionError, UnreadablePostError) as exc:
        # WSGI servers normally reject an early EOF before Django. The test
        # server exposes it as AssertionError, while real input streams use
        # UnreadablePostError; both are malformed client framing here.
        raise InvalidJsonPayload("Request body does not match Content-Length") from exc
    if len(body) != declared_length:
        raise InvalidJsonPayload("Request body does not match Content-Length")
    if len(body) > max_bytes:
        raise JsonPayloadTooLarge("Payload exceeds the route byte budget")
    if not body:
        raise InvalidJsonPayload("JSON payload must not be empty")
    return body


def _json_integer(raw_value):
    digits = raw_value[1:] if raw_value.startswith("-") else raw_value
    if len(raw_value) > MAX_JSON_NUMBER_CHARACTERS or len(digits) > MAX_JSON_NUMBER_CHARACTERS:
        raise InvalidJsonPayload("JSON integer token is too long")
    return int(raw_value)


def _json_float(raw_value):
    if len(raw_value) > MAX_JSON_NUMBER_CHARACTERS:
        raise InvalidJsonPayload("JSON number token is too long")
    value = float(raw_value)
    if not math.isfinite(value):
        raise InvalidJsonPayload("JSON numbers must be finite")
    return value


def _reject_json_constant(_raw_value):
    raise InvalidJsonPayload("Non-finite JSON constants are not accepted")


def _strict_object(pairs):
    if len(pairs) > MAX_JSON_CONTAINER_ITEMS:
        raise InvalidJsonPayload("JSON object has too many members")
    result = {}
    normalized_keys = set()
    for key, value in pairs:
        normalized = unicodedata.normalize("NFC", key)
        if normalized in normalized_keys:
            raise InvalidJsonPayload("JSON object keys must be unique")
        normalized_keys.add(normalized)
        result[key] = value
    return result


def _utf8_size(value, kind):
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise InvalidJsonPayload(f"JSON {kind} is not valid Unicode") from exc


def _validate_json_shape(payload):
    total_nodes = 1
    stack = [(payload, 1)]
    while stack:
        value, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise InvalidJsonPayload("JSON nesting is too deep")
        if isinstance(value, dict):
            if len(value) > MAX_JSON_CONTAINER_ITEMS:
                raise InvalidJsonPayload("JSON object has too many members")
            total_nodes += len(value) * 2
            if total_nodes > MAX_JSON_TOTAL_NODES:
                raise InvalidJsonPayload("JSON payload has too many nodes")
            for key, item in value.items():
                if _utf8_size(key, "key") > MAX_JSON_KEY_BYTES:
                    raise InvalidJsonPayload("JSON object key is too long")
                stack.append((item, depth + 1))
        elif isinstance(value, list):
            if len(value) > MAX_JSON_CONTAINER_ITEMS:
                raise InvalidJsonPayload("JSON array has too many items")
            total_nodes += len(value)
            if total_nodes > MAX_JSON_TOTAL_NODES:
                raise InvalidJsonPayload("JSON payload has too many nodes")
            stack.extend((item, depth + 1) for item in value)
        elif isinstance(value, str) and _utf8_size(value, "string") > MAX_JSON_STRING_BYTES:
            raise InvalidJsonPayload("JSON string is too long")


def load_json_text(raw_text, *, max_bytes):
    if not isinstance(raw_text, str):
        raise InvalidJsonPayload("Embedded JSON must be text")
    if _utf8_size(raw_text, "document") > max_bytes:
        raise JsonPayloadTooLarge("Embedded JSON exceeds the route byte budget")
    if not raw_text or raw_text.startswith("\ufeff"):
        raise InvalidJsonPayload("JSON text must be non-empty UTF-8 without a BOM")
    try:
        payload = json.loads(
            raw_text,
            object_pairs_hook=_strict_object,
            parse_int=_json_integer,
            parse_float=_json_float,
            parse_constant=_reject_json_constant,
        )
    except InvalidJsonPayload:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise InvalidJsonPayload("JSON syntax is invalid") from exc
    _validate_json_shape(payload)
    return payload


def load_json_body(request, *, max_bytes=None):
    _require_json_media_type(request)
    maximum = settings.JSON_CONTROL_MAX_BODY_BYTES if max_bytes is None else max_bytes
    body = _bounded_request_body(request, maximum)
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidJsonPayload("Request body is not valid UTF-8") from exc
    return load_json_text(text, max_bytes=maximum)


def load_json_object(request, *, max_bytes=None):
    payload = load_json_body(request, max_bytes=max_bytes)
    if not isinstance(payload, dict):
        raise InvalidJsonPayload("Request body must be a JSON object")
    return payload


def load_json_form_field(request, field_name, *, max_bytes, max_form_bytes):
    _require_form_media_type(request)
    _bounded_request_body(request, max_form_bytes)
    try:
        values = request.POST.getlist(field_name)
    except (MultiPartParserError, RequestDataTooBig, TooManyFieldsSent, TooManyFilesSent) as exc:
        raise InvalidJsonPayload("Form envelope is malformed") from exc
    if len(values) != 1:
        raise InvalidJsonPayload("Embedded JSON form field must occur exactly once")
    return load_json_text(values[0], max_bytes=max_bytes)


def _canonical_ip(value):
    value = str(value or "").strip()
    if not value:
        return ""
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        return ""


def client_ip(request):
    """Return a bounded, canonical address for auditing and rate limiting.

    Forwarded headers are accepted only from an explicitly trusted proxy
    network. Enabling header support alone must never let an Internet client
    choose its own rate-limit bucket.
    """

    remote = _canonical_ip(request.META.get("REMOTE_ADDR"))
    if getattr(settings, "TRUST_PROXY_HEADERS", False) and remote:
        remote_address = ipaddress.ip_address(remote)
        trusted_networks = getattr(settings, "TRUSTED_PROXY_NETWORKS", ())
        if any(remote_address in network for network in trusted_networks):
            forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
            forwarded_first = _canonical_ip(forwarded.split(",", 1)[0])
            if forwarded_first:
                return forwarded_first
            real_ip = _canonical_ip(request.META.get("HTTP_X_REAL_IP"))
            if real_ip:
                return real_ip
    # Keep audit/rate-limit keys valid and fail closed when the server did not
    # receive a usable transport address.
    return remote or "0.0.0.0"  # noqa: S104 - non-routable audit sentinel, not a bind address
