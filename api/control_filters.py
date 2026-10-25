"""Bounded, index-aware filters used by the management control lists.

The control-plane list endpoints historically treated any value containing ``%``
as an unbounded ``icontains`` query.  That made a short or empty substring an
unavoidable table scan.  Keep the public syntax deliberately small and make the
query shape explicit so the caller can choose an exact, prefix, or substring
lookup without asking the database to interpret arbitrary wildcard syntax.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.db.models import QuerySet

CONTROL_FILTER_CONTRACT_VERSION = 1
CONTROL_FILTER_MAX_BYTES = 256
CONTROL_FILTER_MAX_CHARACTERS = 128
CONTROL_FILTER_MIN_SUBSTRING_CHARACTERS = 3


@dataclass(frozen=True)
class ControlFilter:
    mode: str
    value: str


class ControlFilterError(ValueError):
    """A filter cannot be represented by the bounded control-list contract."""

    def __init__(self, field: str, reason: str):
        self.field = field
        self.reason = reason
        super().__init__(f"invalid {field} filter: {reason}")


def parse_control_filter(field: str, value: object) -> ControlFilter | None:
    """Parse one control-list value into a typed, bounded filter.

    The only wildcard forms accepted are ``term%`` (case-insensitive prefix)
    and ``%term%`` (case-insensitive substring).  A value without ``%`` remains
    an exact match.  Wildcards are intentionally not escaped or interpreted as
    SQL patterns; malformed placement is rejected before a QuerySet is built.
    """

    if value is None:
        return None
    if not isinstance(value, str):
        raise ControlFilterError(field, "not_text")
    value = value.strip()
    if not value:
        return None
    if len(value) > CONTROL_FILTER_MAX_CHARACTERS or len(value.encode("utf-8")) > CONTROL_FILTER_MAX_BYTES:
        raise ControlFilterError(field, "too_long")

    wildcard_count = value.count("%")
    if wildcard_count == 0:
        return ControlFilter("exact", value)
    if wildcard_count == 1 and value.endswith("%") and not value.startswith("%"):
        term = value[:-1]
        if not term:
            raise ControlFilterError(field, "empty_prefix")
        return ControlFilter("prefix", term)
    if wildcard_count == 2 and value.startswith("%") and value.endswith("%"):
        term = value[1:-1]
        if len(term) < CONTROL_FILTER_MIN_SUBSTRING_CHARACTERS:
            raise ControlFilterError(field, "substring_too_short")
        return ControlFilter("substring", term)
    raise ControlFilterError(field, "wildcard_syntax")


def apply_control_filter(
    qs: QuerySet,
    field: str,
    value: object,
    *,
    parameter: str | None = None,
    allowed_modes: frozenset[str] | None = None,
) -> QuerySet:
    """Apply a parsed filter without evaluating the supplied QuerySet."""

    parsed = parse_control_filter(parameter or field, value)
    if parsed is None:
        return qs
    if allowed_modes is not None and parsed.mode not in allowed_modes:
        raise ControlFilterError(parameter or field, "unsupported_mode")
    if parsed.mode == "exact":
        return qs.filter(**{field: parsed.value})
    if parsed.mode == "prefix":
        return qs.filter(**{f"{field}__istartswith": parsed.value})
    if parsed.mode == "substring":
        return qs.filter(**{f"{field}__icontains": parsed.value})
    raise ControlFilterError(field, "unknown_mode")
