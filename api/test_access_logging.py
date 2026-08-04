import logging
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase
from django.urls import Resolver404, resolve
from gunicorn.glogging import SafeAtoms

from api import views_api, views_front
from api.middleware import SafeAccessLogMiddleware
from camellia_remote_management.access_logging import (
    ACCESS_ROUTE_ENV,
    REQUEST_ID_ENV,
    REQUEST_ID_HEADER,
    SAFE_ACCESS_LOG_FORMAT,
    SafeAccessLogger,
    SafeDjangoRequestFilter,
)


class SafeAccessLoggingTests(SimpleTestCase):
    maxDiff = None

    @staticmethod
    def _response():
        return SimpleNamespace(status="200 OK", sent=123, headers=[])

    def _access_line(self, request):
        middleware = SafeAccessLogMiddleware(self._resolve_response)
        response = middleware(request)
        atoms = SafeAccessLogger.atoms(
            object.__new__(SafeAccessLogger),
            self._response(),
            {},
            request.META,
            timedelta(microseconds=2500),
        )
        return response, atoms, SAFE_ACCESS_LOG_FORMAT % SafeAtoms(atoms)

    @staticmethod
    def _resolve_response(request):
        try:
            request.resolver_match = resolve(request.path_info)
        except Resolver404:
            request.resolver_match = None
        return HttpResponse("ok")

    def test_sensitive_targets_queries_and_referer_are_not_access_atoms(self):
        cases = [
            (
                "/api/oidc/auth-query?code=LOG008_POLL_CODE_CANARY",
                "/api/oidc/auth-query",
            ),
            (
                "/api/oidc/callback?code=LOG008_PROVIDER_CODE_CANARY&state=LOG008_STATE_CANARY",
                "/api/oidc/callback",
            ),
            (
                f"/api/share/{'LOG008_SHARE_TOKEN_CANARY_' + 'A' * 32}",
                "/api/share/(?P<share_token>[A-Za-z0-9_-]{32,128})",
            ),
            (
                "/api/audit/conn/active?id=LOG008_DEVICE_CANARY&session_id=LOG008_SESSION_CANARY",
                "/api/audit/(?P<typ>conn/active|conn|file|alarm)",
            ),
            (
                "/api/record?type=0&file=incoming_LOG008_RECORD_FILENAME_CANARY&offset=4096",
                "/api/record",
            ),
            (
                "/does/not/exist/LOG008_UNKNOWN_PATH_CANARY?value=LOG008_UNKNOWN_QUERY_CANARY",
                "<unmatched>",
            ),
        ]
        referer = "https://idp.example/callback?code=LOG008_REFERER_CODE_CANARY&state=LOG008_REFERER_STATE_CANARY"

        for target, expected_route in cases:
            with self.subTest(target=target):
                request = RequestFactory().get(target, HTTP_REFERER=referer)
                response, atoms, line = self._access_line(request)
                self.assertEqual(
                    set(atoms),
                    {"m", "route", "s", "B", "D", "request_id"},
                )
                self.assertEqual(atoms["route"], expected_route)
                self.assertRegex(atoms["request_id"], r"\A[0-9a-f]{32}\Z")
                self.assertEqual(response[REQUEST_ID_HEADER], atoms["request_id"])
                self.assertIn(f"route={expected_route}", line)
                self.assertIn("duration_us=2500", line)
                self.assertNotIn("LOG008_", line)
                self.assertNotIn("idp.example", line)
                self.assertNotIn("198.51.100", line)

    def test_invalid_internal_context_fails_closed(self):
        environ = {
            "REQUEST_METHOD": "GET\nINJECTED",
            ACCESS_ROUTE_ENV: "/safe\r\nINJECTED",
            REQUEST_ID_ENV: "not-a-server-request-id\nINJECTED",
            "RAW_URI": "/LOG008_RAW_URI_CANARY?secret=LOG008_QUERY_CANARY",
            "QUERY_STRING": "secret=LOG008_QUERY_CANARY",
            "HTTP_REFERER": "https://example.test/LOG008_REFERER_CANARY",
        }
        atoms = SafeAccessLogger.atoms(
            object.__new__(SafeAccessLogger),
            SimpleNamespace(status="not-a-status", sent=-1, headers=[]),
            {},
            environ,
            object(),
        )
        line = SAFE_ACCESS_LOG_FORMAT % SafeAtoms(atoms)
        self.assertEqual(atoms["m"], "INVALID")
        self.assertEqual(atoms["route"], "<unmatched>")
        self.assertEqual(atoms["request_id"], "<missing>")
        self.assertEqual(atoms["s"], "000")
        self.assertEqual(atoms["B"], 0)
        self.assertEqual(atoms["D"], 0)
        self.assertNotIn("LOG008_", line)
        self.assertNotIn("INJECTED", line)

    def test_django_request_errors_use_route_context_not_raw_path(self):
        token = "LOG008_SHARE_TOKEN_CANARY_" + "A" * 32
        request = RequestFactory().get(
            f"/api/share/{token}?code=LOG008_QUERY_CANARY",
            HTTP_REFERER="https://example.test/LOG008_REFERER_CANARY",
        )
        request.resolver_match = resolve(request.path_info)
        request.META[REQUEST_ID_ENV] = "a" * 32
        record = logging.LogRecord(
            "django.request",
            logging.WARNING,
            __file__,
            1,
            "Not Found: %s",
            (request.path,),
            None,
        )
        record.request = request
        record.status_code = 404

        self.assertTrue(SafeDjangoRequestFilter().filter(record))
        rendered = record.getMessage()
        self.assertEqual(
            rendered,
            f"request status=404 route=/api/share/(?P<share_token>[A-Za-z0-9_-]{{32,128}}) request_id={'a' * 32}",
        )
        self.assertNotIn("LOG008_", rendered)

    def test_application_events_use_route_context_not_raw_path(self):
        token = "LOG008_SHARE_TOKEN_CANARY_" + "A" * 32
        request = RequestFactory().get(f"/api/share/{token}?code=LOG008_QUERY_CANARY")
        request.resolver_match = resolve(request.path_info)
        request.user = SimpleNamespace(is_authenticated=False)

        for module in (views_api, views_front):
            with self.subTest(module=module.__name__), patch.object(module.logger, "info") as log_info:
                module._log_event(request, "log008_canary_event")
                args = log_info.call_args.args
                rendered = args[0] % args[1:]
                self.assertIn('"route": "/api/share/(?P<share_token>[A-Za-z0-9_-]{32,128})"', rendered)
                self.assertNotIn("LOG008_", rendered)

    def test_production_entrypoint_selects_safe_logger_and_format(self):
        run_script = (Path(__file__).resolve().parents[1] / "run.sh").read_text()
        self.assertIn(
            "--logger-class camellia_remote_management.access_logging.SafeAccessLogger",
            run_script,
        )
        self.assertIn('--access-logformat "$ACCESS_LOG_FORMAT"', run_script)
        self.assertIn(SAFE_ACCESS_LOG_FORMAT, run_script)
        for forbidden_atom in ("%(r)s", "%(U)s", "%(q)s", "%(f)s", "%(a)s", "%(h)s"):
            self.assertNotIn(forbidden_atom, run_script)
