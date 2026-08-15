import json
import time
from unittest import mock

from django.http import HttpResponse, StreamingHttpResponse
from django.test import RequestFactory, SimpleTestCase, override_settings

from api.database_deadlines import configured_database_budget
from api.middleware import RequestDeadlineMiddleware, SafeAccessLogMiddleware
from api.request_deadlines import (
    DeadlineInputStream,
    DeadlineStreamingIterator,
    RequestDeadlineExceeded,
    bounded_timeout,
    current_request_budget,
    install_request_budget,
    remaining_request_milliseconds,
    reset_request_budget,
)


class RequestDeadlineTests(SimpleTestCase):
    def test_budget_is_monotonic_and_downstream_timeout_is_bounded(self):
        budget, token = install_request_budget(1)
        try:
            self.assertGreater(budget.deadline, time.monotonic())
            self.assertLessEqual(bounded_timeout(30), 1)
            self.assertGreater(remaining_request_milliseconds(), 0)
        finally:
            reset_request_budget(token)
        self.assertIsNone(current_request_budget())

    def test_database_budget_never_extends_request_budget(self):
        budget, token = install_request_budget(0.2)
        try:
            with override_settings(
                DATABASE_OPERATION_DEADLINE_MS=50_000,
                DATABASE_STATEMENT_TIMEOUT_MS=45_000,
                DATABASE_LOCK_TIMEOUT_MS=5_000,
                DATABASE_IDLE_TRANSACTION_TIMEOUT_MS=15_000,
                DATABASE_OPERATION_PROFILE="RUNTIME",
            ):
                database_budget = configured_database_budget()
            self.assertLessEqual(database_budget.deadline, budget.deadline)
        finally:
            reset_request_budget(token)

    def test_expired_view_returns_typed_unknown_result(self):
        request = RequestFactory().get("/api/slow")

        def slow_view(_request):
            time.sleep(0.03)
            return HttpResponse("late")

        with override_settings(REQUEST_DEADLINE_SECONDS=0.01):
            response = RequestDeadlineMiddleware(slow_view)(request)
        self.assertEqual(response.status_code, 504)
        self.assertEqual(response["Retry-After"], "1")
        payload = json.loads(response.content)
        self.assertEqual(payload["code"], "request_deadline_exceeded")
        self.assertEqual(payload["result"], "unknown")

    def test_expired_view_keeps_access_correlation_headers(self):
        request = RequestFactory().get("/api/slow")

        def slow_view(_request):
            time.sleep(0.03)
            return HttpResponse("late")

        with override_settings(REQUEST_DEADLINE_SECONDS=0.01):
            response = RequestDeadlineMiddleware(SafeAccessLogMiddleware(slow_view))(request)
        self.assertRegex(response["X-Request-ID"], r"\A[0-9a-f]{32}\Z")
        self.assertIn("traceparent", response)

    def test_request_body_stream_checks_before_and_after_read(self):
        stream = mock.Mock()
        stream.read.return_value = b"body"
        _budget, token = install_request_budget(1)
        try:
            self.assertEqual(DeadlineInputStream(stream).read(), b"body")
            stream.read.assert_called_once_with()
        finally:
            reset_request_budget(token)

    def test_streaming_iterator_fails_closed_after_deadline(self):
        budget, token = install_request_budget(0.01)
        try:
            iterator = DeadlineStreamingIterator(iter([b"chunk"]), budget)
            time.sleep(0.02)
            with self.assertRaises(RequestDeadlineExceeded):
                next(iterator)
        finally:
            reset_request_budget(token)

    def test_streaming_response_is_wrapped_without_consuming_it(self):
        request = RequestFactory().get("/api/stream")
        response = StreamingHttpResponse(iter([b"chunk"]))
        with override_settings(REQUEST_DEADLINE_SECONDS=1):
            wrapped = RequestDeadlineMiddleware(lambda _request: response)(request)
        self.assertTrue(wrapped.streaming)
        self.assertEqual(b"".join(wrapped.streaming_content), b"chunk")
