import json
import logging
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

from django.conf import settings
from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase
from django.urls import resolve

from api import views_api, views_front
from api.middleware import SafeAccessLogMiddleware
from camellia_remote_management.observability import (
    StructuredEventFormatter,
    background_operation,
    current_request_context,
)


class RequestObservabilityTests(SimpleTestCase):
    def _response(self, request):
        request.resolver_match = resolve("/api/login-options")
        return HttpResponse("ok")

    def test_valid_traceparent_is_propagated_but_request_id_is_server_owned(self):
        incoming_trace_id = "0123456789abcdef0123456789abcdef"
        incoming_parent_id = "0123456789abcdef"
        request = RequestFactory().get(
            "/api/login-options",
            HTTP_TRACEPARENT=f"00-{incoming_trace_id}-{incoming_parent_id}-01",
            HTTP_X_REQUEST_ID="attacker-selected-request-id",
            HTTP_X_CAMELLIA_EVENT_ID="11111111-1111-4111-8111-111111111111",
        )

        response = SafeAccessLogMiddleware(self._response)(request)

        self.assertRegex(response["X-Request-ID"], r"\A[0-9a-f]{32}\Z")
        self.assertNotEqual(response["X-Request-ID"], "attacker-selected-request-id")
        self.assertRegex(
            response["traceparent"],
            rf"\A00-{incoming_trace_id}-[0-9a-f]{{16}}-01\Z",
        )
        self.assertEqual(
            response["X-Camellia-Event-ID"],
            "11111111-1111-4111-8111-111111111111",
        )

    def test_invalid_or_ambiguous_trace_and_event_headers_are_not_echoed(self):
        request = RequestFactory().get(
            "/api/login-options",
            HTTP_TRACEPARENT="00-00000000000000000000000000000000-0000000000000000-01,duplicate",
            HTTP_X_CAMELLIA_EVENT_ID="not-a-canonical-event-id",
        )

        response = SafeAccessLogMiddleware(self._response)(request)

        self.assertRegex(
            response["traceparent"],
            r"\A00-(?!0{32})[0-9a-f]{32}-(?!0{16})[0-9a-f]{16}-01\Z",
        )
        self.assertNotIn("X-Camellia-Event-ID", response)

    def test_traceparent_and_event_header_parsers_fail_closed(self):
        invalid_traceparents = [
            "",
            "ff-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
            "00-00000000000000000000000000000000-0123456789abcdef-01",
            "00-0123456789abcdef0123456789abcdef-0000000000000000-01",
            "00-0123456789abcdef0123456789abcdef-0123456789abcdef-0",
            "00-0123456789ABCDEF0123456789ABCDEF-0123456789ABCDEF-01",
            "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01,duplicate",
            "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\ninjected",
        ]
        invalid_event_ids = [
            "11111111-1111-4111-1111-111111111111",
            "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
            "11111111-1111-4111-8111-111111111111,duplicate",
            "11111111-1111-4111-8111-111111111111\r\ninjected",
        ]

        for index, traceparent in enumerate(invalid_traceparents):
            with self.subTest(traceparent=traceparent):
                request = RequestFactory().get(
                    "/api/login-options",
                    HTTP_TRACEPARENT=traceparent,
                    HTTP_X_REQUEST_ID=f"external-{index}",
                    HTTP_X_CAMELLIA_EVENT_ID=invalid_event_ids[index % len(invalid_event_ids)],
                )
                response = SafeAccessLogMiddleware(self._response)(request)
                self.assertRegex(
                    response["traceparent"],
                    r"\A00-(?!0{32})[0-9a-f]{32}-(?!0{16})[0-9a-f]{16}-01\Z",
                )
                self.assertNotEqual(response["X-Request-ID"], f"external-{index}")
                self.assertNotIn("X-Camellia-Event-ID", response)

    def test_application_events_are_single_structured_json_objects(self):
        request = RequestFactory().get(
            "/api/login-options",
            HTTP_TRACEPARENT="00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
        )
        request.resolver_match = resolve(request.path_info)
        request.user = SimpleNamespace(is_authenticated=False)

        def view_response(bound_request):
            bound_request.resolver_match = request.resolver_match
            bound_request.user = request.user
            for module in (views_api, views_front):
                module._log_event(bound_request, "log011_structured_canary", attempt=2)
            return HttpResponse("ok")

        with (
            patch.object(views_api.logger, "info") as api_log,
            patch.object(views_front.logger, "info") as front_log,
        ):
            response = SafeAccessLogMiddleware(view_response)(request)

        for log_call in (api_log.call_args, front_log.call_args):
            with self.subTest(log_call=log_call):
                self.assertEqual(len(log_call.args), 1)
                payload = json.loads(log_call.args[0])
                self.assertEqual(payload["schema_version"], 1)
                self.assertEqual(payload["service"], "remote-management")
                self.assertEqual(payload["event"], "log011_structured_canary")
                self.assertEqual(payload["level"], "INFO")
                self.assertEqual(payload["request_id"], response["X-Request-ID"])
                self.assertEqual(payload["trace_id"], "0123456789abcdef0123456789abcdef")
                self.assertRegex(payload["span_id"], r"\A(?!0{16})[0-9a-f]{16}\Z")
                self.assertEqual(payload["route"], "/api/login-options")
                self.assertEqual(payload["method"], "GET")
                self.assertEqual(payload["attributes"]["attempt"], 2)
                self.assertTrue(re.fullmatch(r"\d{4}-\d{2}-\d{2}T.*Z", payload["timestamp"]))
                uuid.UUID(payload["request_id"])

    def test_concurrent_requests_do_not_share_context(self):
        trace_ids = [
            "11111111111141118111111111111111",
            "22222222222242228222222222222222",
        ]

        def invoke(trace_id):
            captured = {}

            def response(request):
                request.resolver_match = resolve("/api/login-options")
                captured["context"] = current_request_context()
                return HttpResponse("ok")

            request = RequestFactory().get(
                "/api/login-options",
                HTTP_TRACEPARENT=f"00-{trace_id}-0123456789abcdef-01",
            )
            result = SafeAccessLogMiddleware(response)(request)
            self.assertIsNone(current_request_context())
            return captured["context"], result

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(invoke, trace_ids))

        request_ids = set()
        for expected_trace, (context, response) in zip(trace_ids, results, strict=True):
            self.assertEqual(context.trace_id, expected_trace)
            self.assertEqual(response["X-Request-ID"], context.request_id)
            self.assertIn(expected_trace, response["traceparent"])
            request_ids.add(context.request_id)
        self.assertEqual(len(request_ids), 2)

    def test_middleware_exception_resets_context_and_emits_typed_failure(self):
        request = RequestFactory().get("/api/login-options")

        def fail(bound_request):
            bound_request.resolver_match = resolve(bound_request.path_info)
            raise RuntimeError("LOG011_SECRET_EXCEPTION_TEXT")

        with patch("api.middleware.logger.error") as error_log:
            with self.assertRaisesRegex(RuntimeError, "LOG011_SECRET_EXCEPTION_TEXT"):
                SafeAccessLogMiddleware(fail)(request)

        self.assertIsNone(current_request_context())
        self.assertEqual(len(error_log.call_args.args), 1)
        payload = json.loads(error_log.call_args.args[0])
        self.assertEqual(payload["event"], "http_request_failed")
        self.assertEqual(payload["error_class"], "RuntimeError")
        self.assertGreaterEqual(payload["duration_us"], 0)
        self.assertNotIn("LOG011_SECRET_EXCEPTION_TEXT", error_log.call_args.args[0])

    def test_application_formatter_wraps_background_and_request_logs_as_json(self):
        formatter = StructuredEventFormatter()
        background = logging.LogRecord(
            "api.cleanup",
            logging.WARNING,
            __file__,
            1,
            "cleanup deferred",
            (),
            None,
        )
        background_payload = json.loads(formatter.format(background))
        self.assertEqual(background_payload["event"], "application_log")
        self.assertEqual(background_payload["route"], "<background>")
        self.assertIsNone(background_payload["request_id"])

        captured = {}

        def response(request):
            request.resolver_match = resolve(request.path_info)
            record = logging.LogRecord(
                "api.worker",
                logging.INFO,
                __file__,
                1,
                "request worker checkpoint",
                (),
                None,
            )
            captured["payload"] = json.loads(formatter.format(record))
            return HttpResponse("ok")

        result = SafeAccessLogMiddleware(response)(RequestFactory().get("/api/login-options"))
        self.assertEqual(captured["payload"]["request_id"], result["X-Request-ID"])
        self.assertEqual(captured["payload"]["trace_id"], result["traceparent"].split("-")[1])
        self.assertEqual(settings.LOGGING["handlers"]["structured_console"]["formatter"], "structured_event")
        self.assertEqual(settings.LOGGING["loggers"]["api"]["handlers"], ["structured_console"])

    def test_background_operation_has_stable_typed_correlation_and_resets(self):
        formatter = StructuredEventFormatter()
        with background_operation("purge_expired_state") as context:
            first = json.loads(
                formatter.format(logging.LogRecord("api.cleanup", logging.INFO, __file__, 1, "first", (), None))
            )
            second = json.loads(
                formatter.format(logging.LogRecord("api.cleanup", logging.WARNING, __file__, 1, "second", (), None))
            )

        self.assertIsNone(current_request_context())
        self.assertEqual(first["request_id"], context.request_id)
        self.assertEqual(first["trace_id"], second["trace_id"])
        self.assertEqual(first["span_id"], second["span_id"])
        self.assertEqual(first["event_id"], second["event_id"])
        self.assertEqual(first["route"], "<command:purge_expired_state>")
        self.assertEqual(first["method"], "BACKGROUND")
