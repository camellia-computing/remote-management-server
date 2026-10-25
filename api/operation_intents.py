"""Versioned public intent and encrypted, per-operation private binding.

No password-derived verifier or binding key may leave the encrypted receipt.
The random per-operation key travels inside the existing context-bound field,
so normal encryption-key rewrapping does not invalidate idempotent replay.
"""

import base64
import binascii
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass

SENSITIVE_INTENT_FIELDS = frozenset({"password", "default_password", "address_book_password", "hash", "rhash", "token"})
_BINDING_DOMAIN = b"camellia-management-operation-private-intent-v2\0"
# HTTP JSON permits depth 64. Metadata and explicit secret wrappers add frames;
# this internal budget must not reject otherwise valid bounded JSON as a 500.
_MAX_INTENT_DEPTH = 256
_KEY_BYTES = 32


@dataclass(frozen=True, repr=False)
class SecretIntent:
    """Explicit secret marking for non-JSON/form surfaces; never log its value."""

    value: object


def canonical_document(value):
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode(
            "utf-8"
        )
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("Management operation document is not canonical JSON") from None


def _secret_action(value):
    if value is None:
        return "keep"
    if value == "":
        return "clear"
    return "set"


def partition_intent(value, *, _depth=0):
    """Return public proof input and full, memory-only private proof input.

    Both projections preserve names and non-secret values. Public secret markers
    deliberately reveal neither the value nor its length or a derived hash.
    Field names form a cross-language v2 contract, not a logging heuristic.
    """
    if _depth > _MAX_INTENT_DEPTH:
        raise ValueError("Management operation intent is too deeply nested")
    if isinstance(value, SecretIntent):
        _unused, private = partition_intent(value.value, _depth=_depth + 1)
        return {"$secret_intent": _secret_action(private)}, private
    if isinstance(value, dict):
        public, private = {}, {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("Management operation intent keys must be strings")
            if key in SENSITIVE_INTENT_FIELDS and not isinstance(child, SecretIntent):
                child = SecretIntent(child)
            public[key], private[key] = partition_intent(child, _depth=_depth + 1)
        return public, private
    if isinstance(value, (list, tuple)):
        children = [partition_intent(child, _depth=_depth + 1) for child in value]
        return [child[0] for child in children], [child[1] for child in children]
    return value, value


def public_intent_digest(value):
    public, _private = partition_intent(value)
    return hashlib.sha256(canonical_document(public)).hexdigest()


def _private_mac(key, value, *, actor_id, operation_id, operation):
    _public, private = partition_intent(value)
    material = canonical_document(
        {"actor_id": str(actor_id), "operation_id": str(operation_id), "operation": operation, "intent": private}
    )
    return hmac.new(key, _BINDING_DOMAIN + material, hashlib.sha256).hexdigest()


def new_private_binding(value, *, actor_id, operation_id, operation):
    key = secrets.token_bytes(_KEY_BYTES)
    return {
        "version": 1,
        "key": base64.b64encode(key).decode("ascii"),
        "mac": _private_mac(key, value, actor_id=actor_id, operation_id=operation_id, operation=operation),
    }


def _binding_key(binding):
    if (
        not isinstance(binding, dict)
        or set(binding) != {"version", "key", "mac"}
        or type(binding["version"]) is not int
        or binding["version"] != 1
        or not isinstance(binding["key"], str)
        or len(binding["key"]) != 44
        or not isinstance(binding["mac"], str)
        or len(binding["mac"]) != 64
        or any(character not in "0123456789abcdef" for character in binding["mac"])
    ):
        raise ValueError("Stored private operation binding is invalid")
    try:
        key = base64.b64decode(binding["key"], validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("Stored private operation binding is invalid") from None
    if len(key) != _KEY_BYTES or base64.b64encode(key).decode("ascii") != binding["key"]:
        raise ValueError("Stored private operation binding is invalid")
    return key


def validate_private_binding(binding):
    _binding_key(binding)


def private_binding_matches(binding, value, *, actor_id, operation_id, operation):
    key = _binding_key(binding)
    expected = _private_mac(key, value, actor_id=actor_id, operation_id=operation_id, operation=operation)
    return secrets.compare_digest(binding["mac"], expected)
