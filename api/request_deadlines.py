"""Monotonic HTTP request budgets shared by every synchronous boundary.

Gunicorn's gthread heartbeat only proves that the worker is alive; it cannot
interrupt a request thread blocked in a database, filesystem, or HTTP call.
This module therefore provides a cooperative, fail-closed deadline.  Downstream
operations must consume the remaining value and call :func:`check_request_deadline`
around potentially blocking work.
"""

from __future__ import annotations

import math
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass


class RequestDeadlineExceeded(TimeoutError):
    """The current HTTP request budget is exhausted."""


@dataclass(frozen=True, slots=True)
class RequestBudget:
    deadline: float
    configured_seconds: float


_current_budget: ContextVar[RequestBudget | None] = ContextVar(
    "camellia_remote_request_budget",
    default=None,
)


def current_request_budget() -> RequestBudget | None:
    return _current_budget.get()


def remaining_request_seconds() -> float | None:
    budget = current_request_budget()
    if budget is None:
        return None
    return max(budget.deadline - time.monotonic(), 0.0)


def remaining_request_milliseconds() -> int | None:
    remaining = remaining_request_seconds()
    if remaining is None:
        return None
    return max(math.floor(remaining * 1000), 0)


def check_request_deadline(*, margin_seconds: float = 0.0) -> float | None:
    """Return remaining seconds or raise before a blocking operation.

    ``margin_seconds`` reserves time for a caller's cleanup/response path. It
    never extends the request deadline and is useful before multi-step commits.
    """

    remaining = remaining_request_seconds()
    if remaining is None:
        return None
    if remaining <= max(float(margin_seconds), 0.0):
        raise RequestDeadlineExceeded("request deadline exhausted")
    return remaining


def bounded_timeout(configured: float | int, *, margin_seconds: float = 0.0) -> float:
    """Bound a downstream timeout by the remaining request budget.

    With no request context (for example a management command or a unit test),
    the configured timeout is preserved. A tiny positive floor avoids passing
    zero to clients which interpret it as "wait forever".
    """

    configured_value = float(configured)
    if configured_value <= 0:
        raise ValueError("configured timeout must be positive")
    remaining = check_request_deadline(margin_seconds=margin_seconds)
    if remaining is None:
        return configured_value
    bounded = min(configured_value, remaining - max(float(margin_seconds), 0.0))
    if bounded <= 0:
        raise RequestDeadlineExceeded("request deadline exhausted")
    return bounded


@contextmanager
def request_operation_budget(configured: float | int, *, margin_seconds: float = 0.0):
    """Temporarily expose the smaller of the active and operation deadlines."""

    configured_value = float(configured)
    if configured_value <= 0:
        raise ValueError("configured operation budget must be positive")
    active = current_request_budget()
    operation_deadline = time.monotonic() + configured_value
    if active is None:
        deadline = operation_deadline
    else:
        deadline = min(active.deadline, operation_deadline)
    token = _current_budget.set(RequestBudget(deadline, configured_value))
    try:
        check_request_deadline(margin_seconds=margin_seconds)
        yield current_request_budget()
    finally:
        _current_budget.reset(token)


def install_request_budget(configured: float | int) -> tuple[RequestBudget, object]:
    """Install a request budget and return its ContextVar token."""

    configured_value = float(configured)
    if configured_value <= 0:
        raise ValueError("request deadline must be positive")
    budget = RequestBudget(time.monotonic() + configured_value, configured_value)
    return budget, _current_budget.set(budget)


def reset_request_budget(token: object) -> None:
    _current_budget.reset(token)


class DeadlineInputStream:
    """Proxy Django's request stream and check before/after each read."""

    def __init__(self, stream):
        self._stream = stream

    def read(self, *args, **kwargs):
        check_request_deadline()
        value = self._stream.read(*args, **kwargs)
        check_request_deadline()
        return value

    def readline(self, *args, **kwargs):
        check_request_deadline()
        value = self._stream.readline(*args, **kwargs)
        check_request_deadline()
        return value

    def readinto(self, buffer, *args, **kwargs):
        check_request_deadline()
        value = self._stream.readinto(buffer, *args, **kwargs)
        check_request_deadline()
        return value

    def __iter__(self):
        while True:
            check_request_deadline()
            chunk = next(self._stream)
            check_request_deadline()
            yield chunk

    def __getattr__(self, name):
        return getattr(self._stream, name)


class DeadlineStreamingIterator:
    """Check each response chunk without retaining request ContextVar state."""

    def __init__(self, iterator, budget: RequestBudget):
        self._iterator = iter(iterator)
        self._budget = budget

    def __iter__(self):
        return self

    def __next__(self):
        if time.monotonic() >= self._budget.deadline:
            raise RequestDeadlineExceeded("request deadline exhausted while streaming")
        chunk = next(self._iterator)
        if time.monotonic() >= self._budget.deadline:
            raise RequestDeadlineExceeded("request deadline exhausted while streaming")
        return chunk

    def close(self):
        close = getattr(self._iterator, "close", None)
        if close is not None:
            close()
