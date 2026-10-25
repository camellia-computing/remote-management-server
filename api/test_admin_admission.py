import concurrent.futures
import json
import threading

from django.contrib import admin
from django.contrib.auth import SESSION_KEY
from django.db import close_old_connections, connections
from django.test import Client, TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature

from api.admin_site import CamelliaAdminSite
from api.login_admission import reserve_login_attempt
from api.models import LoginAttempt, UserProfile

ADMIN_USERNAME = "admin-admission-canary"
ADMIN_PASSWORD = "correct-admin-admission-password"  # noqa: S105 - isolated test credential
ADMIN_IP = "198.51.100.230"
DEVICE_UUID = "YWRtaW4tYWRtaXNzaW9uLWRldmljZQ=="
TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


def admin_client(*, csrf=False, ip=ADMIN_IP):
    return Client(
        enforce_csrf_checks=csrf,
        REMOTE_ADDR=ip,
        HTTP_HOST="localhost",
    )


def csrf_token(client):
    client.get("/admin/login/")
    return client.cookies["csrftoken"].value


def post_admin_login(client, password, csrf=None):
    data = {
        "username": ADMIN_USERNAME,
        "password": password,
        "next": "/admin/",
    }
    headers = {}
    if csrf is not None:
        data["csrfmiddlewaretoken"] = csrf
        headers["HTTP_X_CSRFTOKEN"] = csrf
    return client.post("/admin/login/", data, **headers)


@override_settings(STORAGES=TEST_STORAGES)
class AdminAdmissionTests(TestCase):
    def setUp(self):
        self.admin = UserProfile.objects.create_superuser(ADMIN_USERNAME, ADMIN_PASSWORD)

    def test_project_uses_admission_admin_site(self):
        self.assertIsInstance(admin.site, CamelliaAdminSite)

    def test_csrf_failure_does_not_consume_admission(self):
        response = post_admin_login(admin_client(csrf=True), "wrong-password")

        self.assertEqual(response.status_code, 403)
        self.assertFalse(LoginAttempt.objects.exists())

    def test_admin_lockout_is_429_and_does_not_log_credentials(self):
        client = admin_client(csrf=True)
        csrf = csrf_token(client)
        with self.assertLogs("api.admin_site", level="WARNING") as captured:
            failures = [post_admin_login(client, "wrong-password", csrf) for _ in range(10)]
            locked = post_admin_login(client, "wrong-password", csrf)
            correct_while_locked = post_admin_login(client, ADMIN_PASSWORD, csrf)

        self.assertTrue(all(response.status_code == 200 for response in failures))
        self.assertEqual(locked.status_code, 429)
        self.assertEqual(correct_while_locked.status_code, 429)
        self.assertNotIn(SESSION_KEY, client.session)
        self.assertEqual(LoginAttempt.objects.filter(ip=ADMIN_IP).count(), 10)
        locked_errors = locked.context["form"].errors.as_data()["__all__"]
        self.assertEqual(locked_errors[0].code, "locked")
        log_output = "\n".join(captured.output)
        self.assertNotIn(ADMIN_USERNAME, log_output)
        self.assertNotIn(ADMIN_PASSWORD, log_output)
        self.assertNotIn("wrong-password", log_output)
        self.assertIn("event=admin_login_failed", log_output)
        self.assertIn("event=admin_login_locked", log_output)

    def test_success_rotates_session_and_clears_only_shared_login_scope(self):
        for _ in range(3):
            self.assertIsNotNone(reserve_login_attempt(ADMIN_IP, ADMIN_USERNAME))

        client = admin_client(csrf=True)
        session = client.session
        session["pre_login_marker"] = "rotate-me"
        session.save()
        old_session_key = session.session_key
        csrf = csrf_token(client)

        with self.assertLogs("api.admin_site", level="INFO") as captured:
            response = post_admin_login(client, ADMIN_PASSWORD, csrf)

        self.assertEqual(response.status_code, 302)
        self.assertNotEqual(client.session.session_key, old_session_key)
        self.assertEqual(client.session[SESSION_KEY], str(self.admin.pk))
        self.assertFalse(LoginAttempt.objects.filter(ip=ADMIN_IP).exists())
        self.assertIn("event=admin_login_success", "\n".join(captured.output))

    def test_api_front_and_admin_share_account_and_ip_budget(self):
        client = admin_client()
        api_payload = json.dumps(
            {
                "username": ADMIN_USERNAME,
                "password": "wrong-password",
                "id": "123456789",
                "uuid": DEVICE_UUID,
            }
        )
        for _ in range(4):
            response = client.post("/api/login", data=api_payload, content_type="application/json")
            self.assertEqual(response.status_code, 401)
        for _ in range(3):
            response = client.post(
                "/api/user_action?action=login",
                {"account": ADMIN_USERNAME, "password": "wrong-password"},
            )
            self.assertEqual(response.status_code, 401)
        for _ in range(3):
            self.assertEqual(post_admin_login(client, "wrong-password").status_code, 200)

        self.assertEqual(LoginAttempt.objects.filter(ip=ADMIN_IP).count(), 10)
        self.assertEqual(post_admin_login(client, "wrong-password").status_code, 429)


@override_settings(STORAGES=TEST_STORAGES)
class PostgreSQLAdminAdmissionTests(TransactionTestCase):
    @skipUnlessDBFeature("has_select_for_update")
    def test_concurrent_admin_authentication_is_serialized(self):
        UserProfile.objects.create_superuser(ADMIN_USERNAME, ADMIN_PASSWORD)
        workers = 32
        barrier = threading.Barrier(workers + 1)

        def authenticate(_index):
            close_old_connections()
            try:
                client = admin_client()
                barrier.wait(timeout=20)
                return post_admin_login(client, "wrong-password").status_code
            finally:
                connections.close_all()

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(authenticate, index) for index in range(workers)]
            barrier.wait(timeout=20)
            statuses = [future.result(timeout=60) for future in futures]

        self.assertEqual(statuses.count(200), 10)
        self.assertEqual(statuses.count(429), 22)
        self.assertEqual(LoginAttempt.objects.filter(ip=ADMIN_IP).count(), 10)
