import json
import uuid
from unittest.mock import patch

from django.test import Client, TestCase, override_settings
from django.utils import translation
from django.utils.html import escapejs

from api.models import AddressBookProfile, RemotePeer, ShareLink, UserProfile


@override_settings(
    STORAGES={
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }
)
class BrowserHttpContractTests(TestCase):
    def setUp(self):
        self.admin = UserProfile.objects.create_superuser("browser-http-admin", "isolated-browser-http-password")
        self.client.force_login(self.admin)
        self.peer = self.make_peer(self.admin, "browser-http-admin-book", "840006001")

    def make_peer(self, owner, name, rid):
        profile = AddressBookProfile.objects.create(guid=name, name=name, owner=owner, rule=3)
        return RemotePeer.objects.create(profile=profile, rid=rid, alias=name)

    def share(self, peer_ids):
        return self.client.post(
            "/api/share",
            {"data": json.dumps([{"value": str(pk)} for pk in peer_ids])},
            HTTP_IDEMPOTENCY_KEY=str(uuid.uuid4()),
        )

    def test_missing_share_owner_is_a_typed_client_error_and_never_creates_a_link(self):
        response = self.share([999999999])
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json()["code"], "share_owner_missing")
        self.assertEqual(ShareLink.objects.count(), 0)

    def test_mixed_share_owners_are_a_typed_client_error_and_never_create_a_link(self):
        other = UserProfile.objects.create_user("browser-http-other", "isolated-other-password")
        second = self.make_peer(other, "browser-http-other-book", "840006002")
        response = self.share([self.peer.pk, second.pk])
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json()["code"], "share_mixed_owner")
        self.assertEqual(ShareLink.objects.count(), 0)

    def test_fetch_form_csrf_failures_have_stable_json_codes_and_request_ids(self):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.admin)
        for path, body in (
            ("/api/user_action?action=login", {"account": "user", "password": "test-only"}),
            ("/api/user_action?action=register", {"user": "user", "pwd": "test-only", "repassword": "test-only"}),
            ("/api/share", {"data": json.dumps([{"value": str(self.peer.pk)}])}),
        ):
            with self.subTest(path=path):
                response = csrf_client.post(path, body)
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response["Content-Type"], "application/json")
                self.assertEqual(response.json()["code"], "csrf_failed")
                self.assertEqual(response.json()["response_schema_version"], 1)
                self.assertTrue(response.get("X-Request-ID"))
                self.assertIn("no-store", response["Cache-Control"])

    def test_unexpected_share_failure_is_json_without_exception_details(self):
        self.client.raise_request_exception = False
        with patch("api.views_front._state040_operation_id", side_effect=RuntimeError("private-error-canary")):
            response = self.share([self.peer.pk])
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertEqual(response.json()["code"], "internal_server_error")
        self.assertNotIn("private-error-canary", response.content.decode())
        self.assertEqual(ShareLink.objects.count(), 0)

    def test_share_selection_and_operation_failures_use_specific_codes_without_mutation(self):
        for data, operation_id, code in (
            ([], str(uuid.uuid4()), "share_empty_selection"),
            ([{"value": str(self.peer.pk)}] * 21, str(uuid.uuid4()), "share_selection_limit"),
            ([{"value": "bad-id"}], str(uuid.uuid4()), "share_invalid_selection"),
            ([{"value": str(self.peer.pk)}], "invalid", "invalid_operation_id"),
        ):
            with self.subTest(code=code):
                response = self.client.post("/api/share", {"data": json.dumps(data)}, HTTP_IDEMPOTENCY_KEY=operation_id)
                self.assertEqual(response.status_code, 400, response.content)
                self.assertEqual(response.json()["code"], code)
                self.assertFalse(response.json()["retryable"])
                self.assertEqual(ShareLink.objects.count(), 0)

    def test_english_pages_include_localized_feedback_and_csp_bounded_helper(self):
        with translation.override("en"):
            for path in ("/api/user_action?action=login", "/api/user_action?action=register", "/api/share"):
                with self.subTest(path=path):
                    response = self.client.get(path)
                    self.assertEqual(response.status_code, 200)
                    self.assertTrue(response["Content-Type"].startswith("text/html"))
                    html = response.content.decode()
                    self.assertIn("ui/http.js", html)
                    self.assertIn(escapejs("The request timed out; its outcome is unknown."), html)
                    self.assertNotIn("请求超时", html)
                    self.assertIn(escapejs("Safe operation storage is unavailable."), html)
                    if path == "/api/share":
                        self.assertIn("ui/mutation_outbox.js", html)
                        self.assertIn("Full links are shown only on creation or original-operation recovery.", html)
