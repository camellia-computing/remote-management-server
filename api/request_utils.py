import ipaddress
import json

from django.conf import settings


class InvalidJsonPayload(ValueError):
    """Raised when an endpoint receives a non-decodable JSON body."""


def load_json_body(request):
    if not request.body:
        return {}
    try:
        return json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidJsonPayload("Request body is not valid UTF-8 JSON") from exc


def load_json_object(request):
    payload = load_json_body(request)
    if not isinstance(payload, dict):
        raise InvalidJsonPayload("Request body must be a JSON object")
    return payload


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
