import json
import logging
import re
import secrets
import uuid
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from camellia_remote_management.access_logging import (
    ACCESS_ROUTE_ENV,
    EVENT_ID_ENV,
    REQUEST_ID_ENV,
    SPAN_ID_ENV,
    TRACE_ID_ENV,
    normalized_route,
)

SERVICE_NAME = "remote-management"
SERVICE_VERSION = "1.0.0"
TRACEPARENT_HEADER = "traceparent"
EVENT_ID_HEADER = "X-Camellia-Event-ID"

_TRACEPARENT_RE = re.compile(
    r"00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})\Z",
    re.ASCII,
)
_EVENT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z",
    re.ASCII,
)
_METHOD_RE = re.compile(r"[A-Z]{1,16}\Z", re.ASCII)
_LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}
_STRUCTURED_REQUIRED_FIELDS = {
    "schema_version",
    "timestamp",
    "level",
    "service",
    "service_version",
    "event",
    "request_id",
    "trace_id",
    "span_id",
    "route",
    "method",
    "attributes",
}


@dataclass(frozen=True, slots=True)
class RequestContext:
    request_id: str
    trace_id: str
    span_id: str
    trace_flags: str
    event_id: str | None
    route: str = "<unmatched>"
    method: str = "INVALID"

    @property
    def traceparent(self):
        return f"00-{self.trace_id}-{self.span_id}-{self.trace_flags}"


_request_context: ContextVar[RequestContext | None] = ContextVar(
    "camellia_remote_request_context",
    default=None,
)


def _nonzero_hex(byte_count):
    value = secrets.token_hex(byte_count)
    while not value.strip("0"):
        value = secrets.token_hex(byte_count)
    return value


def _incoming_trace(header):
    if not isinstance(header, str):
        return None
    match = _TRACEPARENT_RE.fullmatch(header)
    if not match:
        return None
    trace_id, parent_id, flags = match.groups()
    if not trace_id.strip("0") or not parent_id.strip("0"):
        return None
    return trace_id, flags


def canonical_event_id(header):
    if not isinstance(header, str) or not _EVENT_ID_RE.fullmatch(header):
        return None
    try:
        parsed = uuid.UUID(header)
    except ValueError:
        return None
    if parsed.version != 4 or parsed.variant != uuid.RFC_4122 or str(parsed) != header:
        return None
    return header


def begin_request_context(request):
    incoming = _incoming_trace(request.headers.get(TRACEPARENT_HEADER))
    trace_id, trace_flags = incoming if incoming else (_nonzero_hex(16), "01")
    method = request.method if isinstance(request.method, str) and _METHOD_RE.fullmatch(request.method) else "INVALID"
    context = RequestContext(
        request_id=secrets.token_hex(16),
        trace_id=trace_id,
        span_id=_nonzero_hex(8),
        trace_flags=trace_flags,
        event_id=canonical_event_id(request.headers.get(EVENT_ID_HEADER)),
        method=method,
    )
    request.META[REQUEST_ID_ENV] = context.request_id
    request.META[TRACE_ID_ENV] = context.trace_id
    request.META[SPAN_ID_ENV] = context.span_id
    request.META[EVENT_ID_ENV] = context.event_id or ""
    request.META[ACCESS_ROUTE_ENV] = context.route
    return context, _request_context.set(context)


def finish_request_context(request, context):
    route = normalized_route(getattr(request, "resolver_match", None))
    request.META[ACCESS_ROUTE_ENV] = route
    finished = replace(context, route=route)
    _request_context.set(finished)
    return finished


def reset_request_context(token: Token):
    _request_context.reset(token)


def current_request_context():
    return _request_context.get()


@contextmanager
def background_operation(operation):
    event_id = uuid.uuid4()
    context = RequestContext(
        request_id=secrets.token_hex(16),
        trace_id=event_id.hex,
        span_id=_nonzero_hex(8),
        trace_flags="01",
        event_id=str(event_id),
        route=f"<command:{operation}>",
        method="BACKGROUND",
    )
    token = _request_context.set(context)
    try:
        yield context
    finally:
        _request_context.reset(token)


class StructuredEventFormatter(logging.Formatter):
    """Keep typed events as JSON and wrap remaining application records."""

    def format(self, record):
        message = record.getMessage()
        try:
            parsed = json.loads(message)
        except (json.JSONDecodeError, TypeError):
            parsed = None
        if (
            isinstance(parsed, dict)
            and _STRUCTURED_REQUIRED_FIELDS <= parsed.keys()
            and parsed.get("schema_version") == 1
            and parsed.get("service") == SERVICE_NAME
        ):
            return json.dumps(parsed, ensure_ascii=False, default=str, separators=(",", ":"), sort_keys=True)

        context = current_request_context()
        payload = {
            "schema_version": 1,
            "timestamp": datetime.fromtimestamp(record.created, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "service": SERVICE_NAME,
            "service_version": SERVICE_VERSION,
            "event": "application_log",
            "request_id": context.request_id if context else None,
            "trace_id": context.trace_id if context else None,
            "span_id": context.span_id if context else None,
            "route": context.route if context else "<background>",
            "method": context.method if context else "BACKGROUND",
            "attributes": {
                "logger": record.name,
                "message": message,
            },
        }
        if context and context.event_id:
            payload["event_id"] = context.event_id
        if record.exc_info and record.exc_info[0]:
            payload["error_class"] = record.exc_info[0].__name__
            frames = []
            traceback = record.exc_info[2]
            while traceback is not None and len(frames) < 32:
                frame = traceback.tb_frame
                frames.append(
                    {
                        "module": frame.f_globals.get("__name__", "<unknown>"),
                        "function": frame.f_code.co_name,
                        "line": traceback.tb_lineno,
                    }
                )
                traceback = traceback.tb_next
            payload["attributes"]["stack_frames"] = frames
        return json.dumps(payload, ensure_ascii=False, default=str, separators=(",", ":"), sort_keys=True)


def _context_for_request(request):
    context = current_request_context()
    if context is not None:
        return replace(
            context,
            route=normalized_route(getattr(request, "resolver_match", None)),
            method=getattr(request, "method", context.method),
        )
    meta = getattr(request, "META", {})
    return RequestContext(
        request_id=meta.get(REQUEST_ID_ENV, ""),
        trace_id=meta.get(TRACE_ID_ENV, ""),
        span_id=meta.get(SPAN_ID_ENV, ""),
        trace_flags="01",
        event_id=meta.get(EVENT_ID_ENV) or None,
        route=normalized_route(getattr(request, "resolver_match", None)),
        method=getattr(request, "method", "INVALID"),
    )


def log_structured_event(logger, request, event, *, level="info", attributes=None, **fields):
    context = _context_for_request(request)
    level_number = _LOG_LEVELS.get(level, logging.INFO)
    payload = {
        "schema_version": 1,
        "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "level": logging.getLevelName(level_number),
        "service": SERVICE_NAME,
        "service_version": SERVICE_VERSION,
        "event": event,
        "request_id": context.request_id,
        "trace_id": context.trace_id,
        "span_id": context.span_id,
        "route": context.route,
        "method": context.method,
        "attributes": attributes or {},
    }
    if context.event_id:
        payload["event_id"] = context.event_id
    payload.update({key: value for key, value in fields.items() if value is not None})
    log_fn = getattr(logger, level if level in _LOG_LEVELS else "info")
    log_fn(json.dumps(payload, ensure_ascii=False, default=str, separators=(",", ":"), sort_keys=True))
