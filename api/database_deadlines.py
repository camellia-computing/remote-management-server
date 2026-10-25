import math
import time
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

from django.conf import settings
from django.db import connections

from api.request_deadlines import current_request_budget

_TIMEOUT_SQLSTATES = {
    "25P03": "idle_in_transaction_timeout",
    "55P03": "lock_timeout",
    "57014": "statement_timeout",
}


class DatabaseOperationDeadlineExceeded(TimeoutError):
    """The operation exhausted its monotonic database budget before a query."""


@dataclass(frozen=True, slots=True)
class DatabaseBudget:
    deadline: float
    idle_transaction_timeout_ms: int
    lock_timeout_ms: int
    operation_timeout_ms: int
    profile: str
    statement_timeout_ms: int


@dataclass(slots=True)
class _ExecutionState:
    applied_session_timeouts: tuple[int, int, int] | None = None
    close_connection: bool = False


@dataclass(slots=True)
class _OperationState:
    timeout_kind: str | None = None


_current_budget: ContextVar[DatabaseBudget | None] = ContextVar(
    "camellia_remote_database_budget",
    default=None,
)
_current_operation_state: ContextVar[_OperationState | None] = ContextVar(
    "camellia_remote_database_operation_state",
    default=None,
)


def database_timeout_kind(exception):
    """Return a stable PostgreSQL timeout kind without matching error text."""

    seen = set()
    current = exception
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, DatabaseOperationDeadlineExceeded):
            return "operation_deadline"
        sqlstate = getattr(current, "sqlstate", None) or getattr(current, "pgcode", None)
        if sqlstate in _TIMEOUT_SQLSTATES:
            return _TIMEOUT_SQLSTATES[sqlstate]
        current = current.__cause__ or current.__context__
    return None


def current_database_budget():
    return _current_budget.get()


def current_database_timeout_kind():
    state = _current_operation_state.get()
    return state.timeout_kind if state is not None else None


def remaining_database_milliseconds():
    budget = current_database_budget()
    if budget is None:
        return None
    return max(math.floor((budget.deadline - time.monotonic()) * 1000), 0)


def _bounded_timeouts(budget):
    remaining_ms = max(math.floor((budget.deadline - time.monotonic()) * 1000), 0)
    if remaining_ms <= 0:
        raise DatabaseOperationDeadlineExceeded(f"{budget.profile.lower()} database operation deadline exhausted")
    # Whole-second flooring avoids a SET round trip for every query while
    # never extending the monotonic deadline. Sub-second operations retain
    # their exact remaining budget.
    bounded_remaining_ms = remaining_ms if remaining_ms < 1000 else max((remaining_ms // 1000) * 1000, 1)
    statement_ms = min(budget.statement_timeout_ms, bounded_remaining_ms)
    lock_ms = min(budget.lock_timeout_ms, statement_ms)
    idle_ms = min(budget.idle_transaction_timeout_ms, bounded_remaining_ms)
    return statement_ms, lock_ms, idle_ms


def _set_postgresql_timeouts(cursor, *, statement_ms, lock_ms, idle_ms, local):
    raw_cursor = getattr(cursor, "cursor", None)
    if raw_cursor is None:
        raise RuntimeError("database deadline enforcement requires the native PostgreSQL cursor")
    raw_cursor.execute(
        """
        SELECT pg_catalog.set_config('statement_timeout', %s, %s),
               pg_catalog.set_config('lock_timeout', %s, %s),
               pg_catalog.set_config('idle_in_transaction_session_timeout', %s, %s)
        """,
        (
            f"{statement_ms}ms",
            local,
            f"{lock_ms}ms",
            local,
            f"{idle_ms}ms",
            local,
        ),
    )


class _DeadlineExecutor:
    def __init__(self, budget, state, operation_state=None):
        self.budget = budget
        self.state = state
        self.operation_state = operation_state or _current_operation_state.get()

    def _record_timeout(self, kind):
        if self.operation_state is not None and self.operation_state.timeout_kind is None:
            self.operation_state.timeout_kind = kind

    def __call__(self, execute, sql, params, many, context):
        connection = context["connection"]
        if connection.vendor != "postgresql":
            return execute(sql, params, many, context)

        try:
            target = _bounded_timeouts(self.budget)
        except DatabaseOperationDeadlineExceeded:
            self._record_timeout("operation_deadline")
            raise
        configured = (
            self.budget.statement_timeout_ms,
            self.budget.lock_timeout_ms,
            self.budget.idle_transaction_timeout_ms,
        )
        local = bool(connection.in_atomic_block)
        # The libpq connection starts with the configured profile. Only issue
        # SET when elapsed non-database work has reduced the remaining budget,
        # or when a previous reduced session value must be tightened again.
        needs_update = target != configured and (local or target != self.state.applied_session_timeouts)
        if needs_update:
            try:
                _set_postgresql_timeouts(
                    context["cursor"],
                    statement_ms=target[0],
                    lock_ms=target[1],
                    idle_ms=target[2],
                    local=local,
                )
            except Exception as exc:
                self.state.close_connection = True
                if timeout_kind := database_timeout_kind(exc):
                    self._record_timeout(timeout_kind)
                raise
            if not local:
                self.state.applied_session_timeouts = target
                self.state.close_connection = True
        try:
            return execute(sql, params, many, context)
        except Exception as exc:
            if timeout_kind := database_timeout_kind(exc):
                self.state.close_connection = True
                self._record_timeout(timeout_kind)
            raise


def configured_database_budget():
    configured_deadline = time.monotonic() + (settings.DATABASE_OPERATION_DEADLINE_MS / 1000)
    request_budget = current_request_budget()
    if request_budget is not None:
        configured_deadline = min(configured_deadline, request_budget.deadline)
    return DatabaseBudget(
        deadline=configured_deadline,
        idle_transaction_timeout_ms=settings.DATABASE_IDLE_TRANSACTION_TIMEOUT_MS,
        lock_timeout_ms=settings.DATABASE_LOCK_TIMEOUT_MS,
        operation_timeout_ms=settings.DATABASE_OPERATION_DEADLINE_MS,
        profile=settings.DATABASE_OPERATION_PROFILE,
        statement_timeout_ms=settings.DATABASE_STATEMENT_TIMEOUT_MS,
    )


@contextmanager
def database_operation_budget(*, aliases=("default",)):
    """Apply the active profile and a monotonic total budget to ORM queries."""

    budget = configured_database_budget()
    token = _current_budget.set(budget)
    operation_state = _OperationState()
    operation_token = _current_operation_state.set(operation_state)
    states = {}
    try:
        with ExitStack() as stack:
            for alias in aliases:
                state = _ExecutionState()
                states[alias] = state
                stack.enter_context(
                    connections[alias].execute_wrapper(_DeadlineExecutor(budget, state, operation_state))
                )
            yield budget
    finally:
        _current_operation_state.reset(operation_token)
        _current_budget.reset(token)
        # A reduced session setting must never leak into the next persistent
        # request, and a cancelled connection must never return to reuse.
        for alias, state in states.items():
            if state.close_connection:
                connections[alias].close()
