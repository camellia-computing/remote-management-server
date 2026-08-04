import hashlib
import json

from django.http import JsonResponse
from django.test import TestCase, override_settings
from django.test.client import RequestFactory
from django.urls import resolve

from api.middleware import SafeAccessLogMiddleware
from api.models import AddressBookProfile, OidcPendingAuth, RemotePeer, ShareLink, UserProfile

DEVICE_UUID = "Y3JlZGVudGlhbC1yZXNwb25zZS10ZXN0"


@override_settings(
    STORAGES={
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }
)
class CredentialResponseSecurityTests(TestCase):
    def setUp(self):
        self.user = UserProfile.objects.create_user(username="alice", password="alice-pass")  # noqa: S106

    def assert_never_stored(self, response):
        self.assertEqual(response.headers.get("Cache-Control"), "no-store, private")
        self.assertEqual(response.headers.get("Pragma"), "no-cache")
        self.assertEqual(response.headers.get("Expires"), "0")
        self.assertEqual(response.headers.get("Referrer-Policy"), "no-referrer")

    def post_json(self, path, payload, token=None):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"} if token else {}
        return self.client.post(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )

    def login(self):
        response = self.post_json(
            "/api/login",
            {
                "username": "alice",
                "password": "alice-pass",
                "id": "123456789",
                "uuid": DEVICE_UUID,
                "deviceInfo": {"os": "linux", "type": "client", "name": "desktop"},
            },
        )
        self.assertEqual(response.status_code, 200, response.content)
        return response, response.json()["access_token"]

    def test_login_current_user_logout_and_failures_are_never_stored(self):
        malformed = self.client.post("/api/login", data=b'{"username":', content_type="application/json")
        self.assertEqual(malformed.status_code, 400)
        self.assert_never_stored(malformed)

        login_response, token = self.login()
        self.assert_never_stored(login_response)

        current = self.post_json("/api/currentUser", {}, token=token)
        self.assertEqual(current.status_code, 200, current.content)
        self.assertNotIn("access_token", current.json())
        self.assert_never_stored(current)

        wrong_method = self.client.get("/api/login")
        self.assertEqual(wrong_method.status_code, 405)
        self.assert_never_stored(wrong_method)

        logout = self.post_json("/api/logout", {}, token=token)
        self.assertEqual(logout.status_code, 200, logout.content)
        self.assert_never_stored(logout)

        unauthorized = self.post_json("/api/currentUser", {}, token=token)
        self.assertEqual(unauthorized.status_code, 401)
        self.assert_never_stored(unauthorized)

        internal_error_request = RequestFactory().post("/api/login")
        internal_error_request.resolver_match = resolve("/api/login")
        internal_error = SafeAccessLogMiddleware(
            lambda _request: JsonResponse({"error": "bounded failure"}, status=500)
        )(internal_error_request)
        self.assertEqual(internal_error.status_code, 500)
        self.assert_never_stored(internal_error)

    def make_completed_oidc(self, poll_code):
        return OidcPendingAuth.objects.create(
            state=f"state-{poll_code}",
            poll_code_hash=hashlib.sha256(poll_code.encode()).hexdigest(),
            provider="example",
            request_ip="127.0.0.1",
            rid="987654321",
            device_uuid=DEVICE_UUID,
            device_info={"os": "linux", "type": "client", "name": "desktop"},
            nonce=f"nonce-{poll_code}",
            code_verifier=f"verifier-{poll_code}",
            status=OidcPendingAuth.STATUS_DONE,
            authenticated_user=self.user,
        )

    def test_oidc_poll_uses_post_body_and_binds_the_initiating_device(self):
        unknown_provider = self.post_json(
            "/api/oidc/auth",
            {
                "op": "not-configured",
                "id": "987654321",
                "uuid": DEVICE_UUID,
                "deviceInfo": {"os": "linux", "type": "client", "name": "desktop"},
            },
        )
        self.assertEqual(unknown_provider.status_code, 404)
        self.assert_never_stored(unknown_provider)

        callback_error = self.client.get("/api/oidc/callback")
        self.assertEqual(callback_error.status_code, 400)
        self.assert_never_stored(callback_error)

        get_poll_code = "get-poll-code"
        self.make_completed_oidc(get_poll_code)
        rejected_get = self.client.get(
            "/api/oidc/auth-query",
            {"code": get_poll_code, "id": "987654321", "uuid": DEVICE_UUID},
        )
        self.assertEqual(rejected_get.status_code, 405)
        self.assert_never_stored(rejected_get)

        poll_code = "post-poll-code"
        pending = self.make_completed_oidc(poll_code)
        wrong_device = self.post_json(
            "/api/oidc/auth-query",
            {"code": poll_code, "id": "987654321", "uuid": "d3JvbmctZGV2aWNl"},
        )
        self.assertEqual(wrong_device.status_code, 403)
        self.assert_never_stored(wrong_device)
        self.assertTrue(OidcPendingAuth.objects.filter(pk=pending.pk).exists())

        completed = self.post_json(
            "/api/oidc/auth-query",
            {"code": poll_code, "id": "987654321", "uuid": DEVICE_UUID},
        )
        self.assertEqual(completed.status_code, 200, completed.content)
        self.assertIn("access_token", completed.json())
        self.assert_never_stored(completed)
        self.assertFalse(OidcPendingAuth.objects.filter(pk=pending.pk).exists())

    def test_shared_address_book_credentials_are_never_stored(self):
        _login_response, token = self.login()
        profile = AddressBookProfile.objects.create(
            guid="shared-credential-profile",
            name="Shared credentials",
            owner=self.user,
            info={"password": "profile-password-canary"},
            rule=3,
        )
        RemotePeer.objects.create(
            profile=profile,
            rid="246813579",
            password="peer-password-canary",  # noqa: S106
        )

        profiles = self.post_json("/api/ab/shared/profiles", {}, token=token)
        self.assertEqual(profiles.status_code, 200, profiles.content)
        self.assertEqual(profiles.json()["data"][0]["info"]["password"], "profile-password-canary")
        self.assert_never_stored(profiles)

        peers = self.post_json(f"/api/ab/peers?ab={profile.guid}", {}, token=token)
        self.assertEqual(peers.status_code, 200, peers.content)
        self.assertEqual(peers.json()["data"][0]["password"], "peer-password-canary")
        self.assert_never_stored(peers)

    def test_share_token_create_preview_and_errors_are_never_stored(self):
        profile = AddressBookProfile.objects.create(
            guid=f"personal-{self.user.pk}",
            name="My address book",
            owner=self.user,
            rule=3,
        )
        peer = RemotePeer.objects.create(profile=profile, rid="135792468", rhash="shared-password")
        self.client.force_login(self.user)
        created = self.client.post(
            "/api/share",
            {"data": json.dumps([{"value": str(peer.pk), "title": "desktop"}])},
        )
        self.assertEqual(created.status_code, 200, created.content)
        raw_token = created.json()["token"]
        self.assertTrue(ShareLink.objects.filter(shash=hashlib.sha256(raw_token.encode()).hexdigest()).exists())
        self.assert_never_stored(created)

        recipient = UserProfile.objects.create_user(username="bob", password="bob-pass")  # noqa: S106
        self.client.force_login(recipient)
        preview = self.client.get(f"/api/share/{raw_token}")
        self.assertEqual(preview.status_code, 200, preview.content)
        self.assert_never_stored(preview)

        accepted = self.client.post(f"/api/share/{raw_token}")
        self.assertEqual(accepted.status_code, 200, accepted.content)
        self.assert_never_stored(accepted)

        missing = self.client.get(f"/api/share/{'x' * 43}")
        self.assertEqual(missing.status_code, 404)
        self.assert_never_stored(missing)

        self.client.force_login(self.user)
        for index in range(20):
            link = ShareLink.objects.create(
                creator=self.user,
                shash=hashlib.sha256(f"limit-{index}".encode()).hexdigest(),
                token_prefix=f"limit-{index}",
            )
            link.peers.add(peer)
        rate_limited = self.client.post(
            "/api/share",
            {"data": json.dumps([{"value": str(peer.pk), "title": "desktop"}])},
        )
        self.assertEqual(rate_limited.status_code, 429)
        self.assert_never_stored(rate_limited)
