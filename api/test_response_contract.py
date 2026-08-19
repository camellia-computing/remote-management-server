import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.http import FileResponse, HttpResponse, JsonResponse
from django.test import Client, RequestFactory, SimpleTestCase, TestCase, override_settings
from django.urls import resolve

from api.models import OidcPendingAuth
from api.response_contract import (
    RESPONSE_KIND_HEADER,
    RESPONSE_SCHEMA_HEADER,
    RESPONSE_SCHEMA_VERSION,
    apply_response_contract,
    empty_success,
    json_error,
)


class ResponseContractUnitTests(SimpleTestCase):
    def request(self, path="/api/example", *, resolve_route=False, method="GET"):
        request = RequestFactory().generic(method, path)
        if resolve_route:
            request.resolver_match = resolve(path)
        return request

    def test_success_object_gets_version_without_data_shape_change(self):
        response = JsonResponse({"name": "example"})
        apply_response_contract(self.request(), response)
        self.assertEqual(json.loads(response.content), {"name": "example", "response_schema_version": 1})
        self.assertEqual(response[RESPONSE_SCHEMA_HEADER], str(RESPONSE_SCHEMA_VERSION))
        self.assertEqual(response[RESPONSE_KIND_HEADER], "success")
        self.assertEqual(int(response["Content-Length"]), len(response.content))

    def test_error_object_is_canonical_bounded_and_drops_human_aliases(self):
        response = JsonResponse({"error": "Provider unavailable", "secret": "safe-detail"}, status=503)
        apply_response_contract(self.request("/api/oidc/auth"), response)
        body = json.loads(response.content)
        self.assertEqual(body["response_schema_version"], 1)
        self.assertRegex(body["code"], r"^http_503_[a-z0-9_]+$")
        self.assertEqual(body["message"], "Provider unavailable")
        self.assertTrue(body["retryable"])
        self.assertNotIn("error", body)
        self.assertNotIn("msg", body)
        self.assertNotIn("secret", body)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(response[RESPONSE_KIND_HEADER], "error")

    def test_scalar_and_html_machine_errors_are_normalized(self):
        scalar = JsonResponse("unauthorized", safe=False, status=401)
        apply_response_contract(self.request("/api/audit/active"), scalar)
        scalar_body = json.loads(scalar.content)
        self.assertEqual(scalar_body["message"], "unauthorized")
        self.assertEqual(scalar_body["response_schema_version"], 1)

        html = HttpResponse("<html>upstream error</html>", status=502, content_type="text/html")
        apply_response_contract(self.request("/api/example"), html)
        self.assertEqual(html["Content-Type"], "application/json")
        self.assertEqual(json.loads(html.content)["message"], "Request failed")
        self.assertNotIn("upstream error", html.content.decode())

    def test_invalid_json_encoding_is_replaced_by_a_bounded_machine_error(self):
        response = HttpResponse(b"\xff", status=400, content_type="application/json")

        apply_response_contract(self.request("/api/example"), response)

        body = json.loads(response.content)
        self.assertEqual(body["code"], "http_400_route")
        self.assertEqual(body["message"], "Request failed")
        self.assertFalse(body["retryable"])
        self.assertNotIn("\ufffd", response.content.decode())

    def test_error_details_are_bounded_and_non_credential_fields_only(self):
        response = JsonResponse(
            {
                "error": "bad",
                "nested": {"safe": "x" * 100_000, "access_token": "do-not-return"},
                "items": list(range(20_000)),
            },
            status=400,
        )
        apply_response_contract(self.request("/api/example"), response)
        self.assertLessEqual(len(response.content), 16 * 1024)
        body = json.loads(response.content)
        self.assertLessEqual(len(body["items"]), 32)
        self.assertLessEqual(len(body["nested"]["safe"]), 256)
        self.assertNotIn("access_token", response.content.decode())

    def test_error_builder_reserves_core_fields_and_drops_unbounded_integers(self):
        response = json_error(
            "stable_code",
            "stable message",
            status=400,
            response_schema_version=0,
            huge_integer=10**5000,
        )
        body = json.loads(response.content)
        self.assertEqual(body["code"], "stable_code")
        self.assertEqual(body["message"], "stable message")
        self.assertFalse(body["retryable"])
        self.assertEqual(body["response_schema_version"], 1)
        self.assertNotIn("huge_integer", body)

    def test_browser_html_list_empty_and_download_shapes_are_not_rewritten(self):
        listing = JsonResponse(["item"], safe=False)
        apply_response_contract(self.request("/api/example"), listing)
        self.assertEqual(json.loads(listing.content), ["item"])
        self.assertEqual(listing[RESPONSE_SCHEMA_HEADER], "1")

        html = HttpResponse("<html>ok</html>", content_type="text/html")
        apply_response_contract(self.request("/api/home", resolve_route=True), html)
        self.assertEqual(html.content, b"<html>ok</html>")
        self.assertEqual(html[RESPONSE_SCHEMA_HEADER], "1")

        empty = empty_success()
        apply_response_contract(self.request("/api/ab/peer/example", method="DELETE"), empty)
        self.assertEqual(empty.status_code, 204)
        self.assertEqual(empty.content, b"")
        self.assertEqual(empty[RESPONSE_KIND_HEADER], "empty")

        with Path(__file__).open("rb") as stream:
            download = FileResponse(stream, as_attachment=True, filename="fixture.txt")
            apply_response_contract(self.request("/api/download"), download)
            self.assertTrue(download.streaming)
            self.assertEqual(download[RESPONSE_KIND_HEADER], "download")

    def test_public_schema_artifact_matches_runtime_contract(self):
        schema_path = Path(__file__).resolve().parent.parent / "docs" / "management-api-response-v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(schema["$defs"]["versionedObject"]["properties"]["response_schema_version"]["const"], 1)
        self.assertEqual(schema["$defs"]["error"]["properties"]["message"]["maxLength"], 256)
        self.assertEqual(schema["$defs"]["machineCode"]["pattern"], "^[a-z][a-z0-9_]{0,63}$")


class EndpointResponseContractTests(TestCase):
    @override_settings(OIDC_PROVIDERS={"example": {}})
    def test_login_options_uses_a_versioned_object(self):
        response = Client().get("/api/login-options")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"options": ["oidc/example"], "response_schema_version": 1})
        self.assertEqual(response[RESPONSE_SCHEMA_HEADER], "1")

    def test_sysinfo_version_is_typed_json(self):
        user = SimpleNamespace(username="response-contract-user")
        with patch("api.views_api._get_token_user", return_value=(object(), user)):
            response = Client().post("/api/sysinfo_ver", data="{}", content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"sysinfo_schema_version": 1, "response_schema_version": 1},
        )
        self.assertEqual(response["Content-Type"], "application/json")

    def test_front_post_csrf_failure_uses_machine_contract_but_get_stays_html(self):
        client = Client(enforce_csrf_checks=True)
        rejected = client.post("/api/user_action?action=login", {"account": "user", "password": "secret"})
        self.assertEqual(rejected.status_code, 403)
        self.assertEqual(rejected[RESPONSE_KIND_HEADER], "error")
        self.assertEqual(rejected["Content-Type"], "application/json")
        self.assertEqual(rejected.json()["response_schema_version"], 1)

        with patch(
            "api.views_front.render",
            return_value=HttpResponse("<html>login</html>", content_type="text/html"),
        ):
            browser = client.get("/api/user_action?action=login")
        self.assertEqual(browser.status_code, 200)
        self.assertTrue(browser["Content-Type"].startswith("text/html"))


class OidcPollingResponseContractTests(TestCase):
    def setUp(self):
        self.client = Client(raise_request_exception=False)
        self.poll_code = "poll-contract-code"
        OidcPendingAuth.objects.create(
            state="poll-contract-state",
            poll_code_hash=hashlib.sha256(self.poll_code.encode()).hexdigest(),
            provider="example",
            rid="123456789",
            device_uuid="ZGV2aWNlLXV1aWQ=",
            nonce="nonce",
            code_verifier="code-verifier",
            status=OidcPendingAuth.STATUS_PENDING,
        )

    def post_poll(self, code):
        return self.client.post(
            "/api/oidc/auth-query",
            data=json.dumps({"code": code, "id": "123456789", "uuid": "ZGV2aWNlLXV1aWQ="}),
            content_type="application/json",
        )

    def test_pending_is_202_typed_and_retryable(self):
        response = self.post_poll(self.poll_code)
        self.assertEqual(response.status_code, 202, response.content)
        body = response.json()
        self.assertEqual(body["code"], "oidc_pending")
        self.assertTrue(body["pending"])
        self.assertTrue(body["retryable"])
        self.assertNotIn("error", body)
        self.assertEqual(body["response_schema_version"], 1)
        self.assertEqual(response["Retry-After"], "1")
        self.assertEqual(response[RESPONSE_KIND_HEADER], "pending")
        self.assertEqual(response[RESPONSE_SCHEMA_HEADER], "1")

    def test_unknown_poll_code_is_a_non_pending_typed_client_error(self):
        response = self.post_poll("unknown-poll-code")
        self.assertEqual(response.status_code, 400, response.content)
        body = response.json()
        self.assertEqual(body["code"], "oidc_poll_invalid")
        self.assertFalse(body["pending"])
        self.assertFalse(body["retryable"])
        self.assertNotIn("error", body)
