from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import resolve

from api.middleware import SafeAccessLogMiddleware
from api.models import UserProfile
from api.response_security import SENSITIVE_RESPONSE_MARKER


@override_settings(
    STORAGES={
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    },
    ID_SERVER="management.example.test:21116",
    RELAY_SERVER="management.example.test:21117",
)
class SensitiveResponseSecurityTests(TestCase):
    def setUp(self):
        self.user = UserProfile.objects.create_user(
            username="sensitive-user",
            password="sensitive-pass",  # noqa: S106 - isolated test credential
        )
        self.admin = UserProfile.objects.create_user(
            username="sensitive-admin",
            password="sensitive-admin-pass",  # noqa: S106 - isolated test credential
            is_admin=True,
        )

    def assert_never_stored(self, response):
        self.assertEqual(response.headers.get("Cache-Control"), "no-store, private")
        self.assertEqual(response.headers.get("Pragma"), "no-cache")
        self.assertEqual(response.headers.get("Expires"), "0")
        self.assertEqual(response.headers.get("Referrer-Policy"), "no-referrer")

    def assert_not_sensitive_policy(self, response):
        cache_control = response.headers.get("Cache-Control", "")
        self.assertNotIn("no-store", cache_control)
        self.assertNotIn("private", cache_control)
        self.assertNotEqual(response.headers.get("Pragma"), "no-cache")

    def test_authenticated_html_and_exports_are_never_stored(self):
        self.client.force_login(self.user)

        home = self.client.get("/api/home")
        self.assertEqual(home.status_code, 200, home.content)
        self.assert_never_stored(home)

        for export_format, expected_type in (
            ("csv", "text/csv"),
            ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        ):
            with self.subTest(export_format=export_format):
                exported = self.client.get("/api/ab_books_export", {"format": export_format})
                self.assertEqual(exported.status_code, 200)
                self.assertTrue(exported.headers["Content-Type"].startswith(expected_type))
                self.assert_never_stored(exported)

        self.client.force_login(self.admin)
        device_export = self.client.get("/api/down_peers")
        self.assertEqual(device_export.status_code, 200)
        self.assertTrue(device_export.streaming)
        self.assert_never_stored(device_export)
        device_export.close()

    def test_sensitive_front_route_inventory_is_marked(self):
        sensitive_paths = (
            "/",
            "/api/user_action",
            "/api/home",
            "/api/work",
            "/api/ab_dashboard",
            "/api/ab_books",
            "/api/ab_book",
            "/api/ab_books_export",
            "/api/ab_book_export",
            "/api/tag_manage",
            "/api/tag_export",
            "/api/ab_manage",
            "/api/ab_rules_export",
            "/api/ab_shares_export",
            "/api/ab_rules",
            "/api/ab_audit",
            "/api/down_peers",
            "/api/share",
            f"/api/share/{'A' * 32}",
            "/api/conn_log",
            "/api/file_log",
            "/webui2/",
            "/webui2/status",
        )
        for path in sensitive_paths:
            with self.subTest(path=path):
                self.assertTrue(
                    getattr(resolve(path).func, SENSITIVE_RESPONSE_MARKER, False),
                    path,
                )

    def test_authentication_and_authorization_redirects_are_never_stored(self):
        unauthenticated = self.client.get("/api/home")
        self.assertEqual(unauthenticated.status_code, 302)
        self.assert_never_stored(unauthenticated)

        self.client.force_login(self.user)
        for path in ("/api/conn_log", "/api/file_log"):
            with self.subTest(path=path):
                denied = self.client.get(path)
                self.assertEqual(denied.status_code, 302)
                self.assert_never_stored(denied)

        logout = self.client.post("/api/user_action?action=logout")
        self.assertEqual(logout.status_code, 302)
        self.assert_never_stored(logout)

    def test_method_and_csrf_errors_are_never_stored(self):
        self.client.force_login(self.user)
        wrong_method = self.client.post("/api/home")
        self.assertEqual(wrong_method.status_code, 405)
        self.assert_never_stored(wrong_method)

        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        csrf_rejected = csrf_client.post("/api/user_action?action=logout")
        self.assertEqual(csrf_rejected.status_code, 403)
        self.assert_never_stored(csrf_rejected)

    def test_early_responses_are_protected_without_a_resolver_match(self):
        for status in (429, 500):
            with self.subTest(status=status):
                request = RequestFactory().get("/api/home")
                self.assertIsNone(getattr(request, "resolver_match", None))
                response = SafeAccessLogMiddleware(
                    lambda _request, response_status=status: HttpResponse(
                        "bounded early response",
                        status=response_status,
                    )
                )(request)
                self.assertEqual(response.status_code, status)
                self.assert_never_stored(response)

        health_request = RequestFactory().get("/health/live")
        health_response = SafeAccessLogMiddleware(lambda _request: HttpResponse("bounded early response", status=429))(
            health_request
        )
        self.assertEqual(health_response.status_code, 429)
        self.assert_not_sensitive_policy(health_response)

    def test_webui_and_root_session_routes_are_never_stored(self):
        anonymous_root = self.client.get("/")
        self.assertEqual(anonymous_root.status_code, 302)
        self.assert_never_stored(anonymous_root)

        self.client.force_login(self.admin)
        authenticated_root = self.client.get("/")
        self.assertEqual(authenticated_root.status_code, 302)
        self.assert_never_stored(authenticated_root)

        webui = self.client.get("/webui2/")
        self.assertEqual(webui.status_code, 200, webui.content)
        self.assert_never_stored(webui)

        status = self.client.get("/webui2/status")
        self.assertEqual(status.status_code, 200, status.content)
        self.assertEqual(status.json()["user"], self.admin.username)
        self.assert_never_stored(status)

    def test_health_and_static_assets_do_not_receive_the_sensitive_policy(self):
        for path, expected_statuses in (
            ("/health/live", {200}),
            ("/health/ready", {200, 503}),
            ("/static/ui/app.css", {200}),
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertIn(response.status_code, expected_statuses)
                self.assert_not_sensitive_policy(response)
