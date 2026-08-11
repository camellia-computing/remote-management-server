import json
import time
import unittest
from unittest import mock

from django.db import DatabaseError, connection, transaction
from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase, TransactionTestCase, override_settings

from api.database_deadlines import (
    DatabaseBudget,
    DatabaseOperationDeadlineExceeded,
    _current_budget,
    _DeadlineExecutor,
    _ExecutionState,
    database_operation_budget,
    database_timeout_kind,
)
from api.middleware import ApiExceptionMiddleware, DatabaseDeadlineMiddleware


class _SqlstateError(DatabaseError):
    def __init__(self, sqlstate):
        super().__init__(sqlstate)
        self.sqlstate = sqlstate


class _RawCursor:
    def __init__(self):
        self.calls = []

    def execute(self, sql, params):
        self.calls.append((sql, params))


class _CursorWrapper:
    def __init__(self):
        self.cursor = _RawCursor()


class _PostgresqlConnection:
    vendor = "postgresql"
    in_atomic_block = False


class DatabaseDeadlineUnitTests(SimpleTestCase):
    def test_timeout_classification_uses_sqlstate_not_localized_message(self):
        for sqlstate, expected in (
            ("57014", "statement_timeout"),
            ("55P03", "lock_timeout"),
            ("25P03", "idle_in_transaction_timeout"),
        ):
            with self.subTest(sqlstate=sqlstate):
                wrapped = RuntimeError("translated database failure")
                wrapped.__cause__ = _SqlstateError(sqlstate)
                self.assertEqual(database_timeout_kind(wrapped), expected)
        self.assertIsNone(database_timeout_kind(DatabaseError("statement timeout text is not authority")))

    def test_expired_monotonic_budget_rejects_before_sql(self):
        budget = DatabaseBudget(
            deadline=time.monotonic() - 1,
            idle_transaction_timeout_ms=1000,
            lock_timeout_ms=500,
            operation_timeout_ms=2000,
            profile="RUNTIME",
            statement_timeout_ms=1000,
        )
        state = _ExecutionState()
        cursor = _CursorWrapper()
        token = _current_budget.set(budget)
        try:
            executor = _DeadlineExecutor(budget, state)
            with self.assertRaises(DatabaseOperationDeadlineExceeded):
                executor(mock.Mock(), "SELECT 1", (), False, {"connection": _PostgresqlConnection(), "cursor": cursor})
        finally:
            _current_budget.reset(token)
        self.assertEqual(cursor.cursor.calls, [])

    def test_elapsed_work_tightens_session_without_extending_deadline(self):
        budget = DatabaseBudget(
            deadline=time.monotonic() + 0.4,
            idle_transaction_timeout_ms=1000,
            lock_timeout_ms=500,
            operation_timeout_ms=2000,
            profile="RUNTIME",
            statement_timeout_ms=1000,
        )
        state = _ExecutionState()
        cursor = _CursorWrapper()
        token = _current_budget.set(budget)
        try:
            executor = _DeadlineExecutor(budget, state)
            execute = mock.Mock(return_value="ok")
            self.assertEqual(
                executor(execute, "SELECT 1", (), False, {"connection": _PostgresqlConnection(), "cursor": cursor}),
                "ok",
            )
        finally:
            _current_budget.reset(token)
        self.assertEqual(len(cursor.cursor.calls), 1)
        configured = cursor.cursor.calls[0][1]
        statement_ms = int(configured[0].removesuffix("ms"))
        lock_ms = int(configured[2].removesuffix("ms"))
        idle_ms = int(configured[4].removesuffix("ms"))
        self.assertGreater(statement_ms, 0)
        self.assertLessEqual(statement_ms, 400)
        self.assertLessEqual(lock_ms, statement_ms)
        self.assertLessEqual(idle_ms, 400)
        self.assertTrue(state.close_connection)

    def test_short_operation_uses_handshake_profile_without_extra_set_query(self):
        budget = DatabaseBudget(
            deadline=time.monotonic() + 50,
            idle_transaction_timeout_ms=15_000,
            lock_timeout_ms=5_000,
            operation_timeout_ms=50_000,
            profile="RUNTIME",
            statement_timeout_ms=45_000,
        )
        state = _ExecutionState()
        cursor = _CursorWrapper()
        executor = _DeadlineExecutor(budget, state)
        execute = mock.Mock(return_value="ok")
        self.assertEqual(
            executor(execute, "SELECT 1", (), False, {"connection": _PostgresqlConnection(), "cursor": cursor}),
            "ok",
        )
        self.assertEqual(cursor.cursor.calls, [])
        self.assertFalse(state.close_connection)

    def test_api_timeout_is_fail_closed_and_marks_commit_result_unknown(self):
        request = RequestFactory().post("/api/test")
        middleware = ApiExceptionMiddleware(lambda _request: None)
        with mock.patch("api.middleware.connection.close") as close:
            response = middleware.process_exception(request, DatabaseOperationDeadlineExceeded("expired"))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response["Retry-After"], "1")
        payload = json.loads(response.content)
        self.assertEqual(payload["code"], "database_operation_timeout")
        self.assertFalse(payload["retryable"])
        self.assertEqual(payload["result"], "unknown")
        close.assert_called_once_with()

    def test_timeout_converted_by_inner_middleware_keeps_unknown_result_contract(self):
        request = RequestFactory().post("/api/test")

        def converted_inner_response(_request):
            budget = DatabaseBudget(
                deadline=time.monotonic() + 1,
                idle_transaction_timeout_ms=1000,
                lock_timeout_ms=500,
                operation_timeout_ms=2000,
                profile="RUNTIME",
                statement_timeout_ms=1000,
            )
            executor = _DeadlineExecutor(budget, _ExecutionState())
            with self.assertRaises(DatabaseError):
                executor(
                    mock.Mock(side_effect=_SqlstateError("55P03")),
                    "SELECT 1",
                    (),
                    False,
                    {"connection": _PostgresqlConnection(), "cursor": _CursorWrapper()},
                )
            # This models Django's convert_exception_to_response boundary for
            # database work in session/rate-limit middleware.
            return HttpResponse(status=500)

        middleware = DatabaseDeadlineMiddleware(converted_inner_response)
        with mock.patch("api.middleware.connection.close") as close:
            response = middleware(request)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response["Retry-After"], "1")
        payload = json.loads(response.content)
        self.assertEqual(payload["code"], "database_operation_timeout")
        self.assertFalse(payload["retryable"])
        self.assertEqual(payload["result"], "unknown")
        close.assert_called_once_with()


@unittest.skipUnless(connection.vendor == "postgresql", "PostgreSQL deadline semantics require PostgreSQL")
class PostgreSQLDatabaseDeadlineTests(TransactionTestCase):
    databases = {"default"}

    def test_connection_profile_has_three_nonzero_timeouts(self):
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT current_setting('statement_timeout'), "
                "current_setting('lock_timeout'), "
                "current_setting('idle_in_transaction_session_timeout')"
            )
            values = cursor.fetchone()
        self.assertNotIn("0", values)
        parameters = connection.get_connection_params()
        self.assertGreater(parameters["connect_timeout"], 0)
        self.assertGreater(parameters["keepalives_idle"], 0)
        self.assertGreater(parameters["keepalives_interval"], 0)
        self.assertGreater(parameters["keepalives_count"], 0)
        self.assertGreater(parameters["tcp_user_timeout"], 0)

    @override_settings(
        DATABASE_OPERATION_PROFILE="RUNTIME",
        DATABASE_OPERATION_DEADLINE_MS=350,
        DATABASE_STATEMENT_TIMEOUT_MS=1000,
        DATABASE_LOCK_TIMEOUT_MS=500,
        DATABASE_IDLE_TRANSACTION_TIMEOUT_MS=1000,
    )
    def test_monotonic_budget_cancels_slow_statement_and_discards_connection(self):
        started = time.monotonic()
        with self.assertRaises(DatabaseError) as raised:
            with database_operation_budget(), connection.cursor() as cursor:
                cursor.execute("SELECT pg_catalog.pg_sleep(2)")
        self.assertEqual(database_timeout_kind(raised.exception), "statement_timeout")
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertIsNone(connection.connection)
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            self.assertEqual(cursor.fetchone(), (1,))

    @override_settings(
        DATABASE_OPERATION_PROFILE="RUNTIME",
        DATABASE_OPERATION_DEADLINE_MS=1200,
        DATABASE_STATEMENT_TIMEOUT_MS=1000,
        DATABASE_LOCK_TIMEOUT_MS=100,
        DATABASE_IDLE_TRANSACTION_TIMEOUT_MS=1000,
    )
    def test_elapsed_budget_bounds_row_lock_wait_and_rolls_back(self):
        holder = connection.Database.connect(**connection.get_connection_params())
        try:
            with holder.cursor() as cursor:
                cursor.execute("SELECT id FROM django_migrations ORDER BY id LIMIT 1 FOR UPDATE")
                locked_id = cursor.fetchone()[0]

            started = time.monotonic()
            with self.assertRaises(DatabaseError) as raised:
                with database_operation_budget():
                    time.sleep(0.8)
                    with transaction.atomic(), connection.cursor() as cursor:
                        cursor.execute("SELECT id FROM django_migrations WHERE id = %s FOR UPDATE", [locked_id])
            self.assertEqual(database_timeout_kind(raised.exception), "lock_timeout")
            self.assertLess(time.monotonic() - started, 1.8)
            self.assertIsNone(connection.connection)
        finally:
            holder.rollback()
            holder.close()

    def test_idle_transaction_timeout_terminates_backend_and_releases_session(self):
        idle = connection.Database.connect(**connection.get_connection_params())
        try:
            idle.autocommit = True
            with idle.cursor() as cursor:
                cursor.execute("SET idle_in_transaction_session_timeout = '200ms'")
                cursor.execute("SELECT pg_backend_pid()")
                backend_pid = cursor.fetchone()[0]
            idle.autocommit = False
            with idle.cursor() as cursor:
                cursor.execute("SELECT 1")
            time.sleep(0.5)
            with self.assertRaises(connection.Database.Error):
                with idle.cursor() as cursor:
                    cursor.execute("SELECT 1")
        finally:
            idle.close()

        with connection.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM pg_stat_activity WHERE pid = %s", [backend_pid])
            self.assertEqual(cursor.fetchone(), (0,))
