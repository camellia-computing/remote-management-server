import uuid

from django.core.exceptions import ValidationError

_AUTO_FIELD_MAX = {
    "SmallAutoField": (1 << 15) - 1,
    "AutoField": (1 << 31) - 1,
    "BigAutoField": (1 << 63) - 1,
}


class InvalidIdentifier(ValidationError):
    """Raised before an untrusted identifier reaches an ORM lookup."""


def parse_model_pk(value, model):
    """Parse one positive, text-form primary key using the model field type.

    AutoField ranges are derived from the declared model field rather than the
    active database backend. SQLite accepts wider integers than PostgreSQL, so
    backend-derived limits would preserve the production-only overflow.
    """

    field_type = model._meta.pk.get_internal_type()
    try:
        maximum = _AUTO_FIELD_MAX[field_type]
    except KeyError as exc:
        raise TypeError(f"Unsupported primary-key field: {field_type}") from exc
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdigit():
        raise InvalidIdentifier("A primary key must be ASCII decimal text")
    maximum_text = str(maximum)
    if len(value) > len(maximum_text) or (len(value) == len(maximum_text) and value > maximum_text):
        raise InvalidIdentifier("Primary key is outside the model field range")
    parsed = int(value)
    if parsed < 1 or str(parsed) != value:
        raise InvalidIdentifier("Primary key is outside the model field range")
    return parsed


def parse_uuid(value):
    """Parse canonical hyphenated UUID text while accepting ASCII hex case."""

    if not isinstance(value, str) or len(value) != 36 or not value.isascii():
        raise InvalidIdentifier("A UUID must use canonical hyphenated text")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError) as exc:
        raise InvalidIdentifier("Invalid UUID") from exc
    if str(parsed) != value.lower():
        raise InvalidIdentifier("A UUID must use canonical hyphenated text")
    return parsed


def _parse_list(value, parser, *, max_items):
    if not isinstance(value, list) or len(value) > max_items:
        raise InvalidIdentifier("Invalid identifier list")
    result = []
    seen = set()
    for item in value:
        parsed = parser(item)
        if parsed in seen:
            raise InvalidIdentifier("Duplicate identifiers are not allowed")
        seen.add(parsed)
        result.append(parsed)
    return result


def parse_model_pk_list(value, model, *, max_items):
    return _parse_list(
        value,
        lambda item: parse_model_pk(item, model),
        max_items=max_items,
    )


def parse_uuid_list(value, *, max_items):
    return _parse_list(value, parse_uuid, max_items=max_items)
