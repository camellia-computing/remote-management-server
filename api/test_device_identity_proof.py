import base64
import concurrent.futures
import datetime
import hashlib
import hmac
import json
import threading
from unittest import mock

from django.contrib import admin
from django.db import IntegrityError, close_old_connections, connections
from django.test import (
    Client,
    RequestFactory,
    TestCase,
    TransactionTestCase,
    override_settings,
    skipUnlessDBFeature,
)
from django.utils import timezone
from nacl.signing import SigningKey

from api import views_api
from api.admin_user import RemoteDeviceAdminCustom
from api.credential_sessions import revoke_user_credentials
from api.device_identity import (
    MAX_DEPLOYMENT_GENERATION,
    MAX_OUTSTANDING_CHALLENGES_PER_IP,
    DeviceProofError,
    issue_proof_challenge,
)
from api.models import (
    DeviceProofChallenge,
    DeviceRecoveryApproval,
    OidcPendingAuth,
    RemoteDevice,
    RemoteToken,
    UserProfile,
)
from api.views_api import _issue_access_token

DEVICE_UUID = base64.b64encode(b"auth-016-device").decode("ascii")


@override_settings(DEVICE_VERIFICATION_TOKEN="v" * 48)
class DeviceIdentityProofTests(TestCase):
    def setUp(self):
        self.user = UserProfile.objects.create_user(
            username="alice",
            password="alice-pass",  # noqa: S106 - isolated test credential
            is_active=True,
        )
        self.old_key = SigningKey.generate()
        self.new_key = SigningKey.generate()
        self.device = RemoteDevice.objects.create(
            rid="123456789",
            uuid=DEVICE_UUID,
            public_key_hash=hashlib.sha256(bytes(self.old_key.verify_key)).hexdigest(),
            owner=self.user,
            is_active=True,
            cpu="-",
            hostname="-",
            memory="-",
            os="-",
            username="",
            version="-",
        )

    def post_json(self, path, payload, token=None):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"} if token else {}
        return self.client.post(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )

    def delete_json(self, path, payload, token=None):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"} if token else {}
        return self.client.delete(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )

    def account_login(self):
        return self.post_json(
            "/api/login",
            {
                "username": "alice",
                "password": "alice-pass",
                "id": self.device.rid,
                "uuid": self.device.uuid,
                "deviceInfo": {"os": "Linux", "type": "client", "name": "replacement"},
            },
        )

    def proof(self, purpose, signing_key, token=None, rid=None, device_uuid=None):
        rid = self.device.rid if rid is None else rid
        device_uuid = self.device.uuid if device_uuid is None else device_uuid
        public_key = base64.b64encode(bytes(signing_key.verify_key)).decode("ascii")
        challenge = self.post_json(
            "/api/devices/proof-challenge",
            {
                "purpose": purpose,
                "id": rid,
                "uuid": device_uuid,
                "pk": public_key,
            },
            token=token,
        )
        self.assertEqual(challenge.status_code, 200, challenge.content)
        body = challenge.json()
        signature = signing_key.sign(body["message"].encode("utf-8")).signature
        return {
            "challenge": body["challenge"],
            "public_key": public_key,
            "signature": base64.b64encode(signature).decode("ascii"),
        }, body["message"]

    def login_with_proof(self, proof):
        payload = {
            "username": "alice",
            "password": "alice-pass",
            "id": self.device.rid,
            "uuid": self.device.uuid,
            "deviceInfo": {"os": "Linux", "type": "client", "name": "original"},
            "device_proof": proof,
        }
        return self.post_json("/api/login", payload)

    def post_json_without_raising(self, path, payload, token=None):
        previous = self.client.raise_request_exception
        self.client.raise_request_exception = False
        try:
            return self.post_json(path, payload, token=token)
        finally:
            self.client.raise_request_exception = previous

    def admin_bearer(self):
        operator = UserProfile.objects.create_superuser(
            username="lease-operator",
            password="operator-pass",  # noqa: S106 - isolated test credential
        )
        operator_device = RemoteDevice.objects.create(
            rid="987654321",
            uuid=base64.b64encode(b"lease-operator-device").decode("ascii"),
            public_key_hash=hashlib.sha256(b"operator-device-key").hexdigest(),
            owner=operator,
            is_active=True,
            cpu="-",
            hostname="-",
            memory="-",
            os="-",
            username="",
            version="-",
        )
        return _issue_access_token(operator, operator_device)[1]

    def login_bearer(self):
        proof, _message = self.proof("login", self.old_key)
        login = self.login_with_proof(proof)
        self.assertEqual(login.status_code, 200, login.content)
        return login.json()["access_token"]

    def assert_bound_revoked_heartbeat(self, bearer, rid=None, device_uuid=None):
        rid = self.device.rid if rid is None else rid
        device_uuid = self.device.uuid if device_uuid is None else device_uuid
        heartbeat = self.post_json(
            "/api/heartbeat",
            {"id": rid, "uuid": device_uuid, "modified_at": 0},
            token=bearer,
        )
        self.assertEqual(heartbeat.status_code, 401, heartbeat.content)
        self.assertEqual(heartbeat.headers.get("Cache-Control"), "no-store, private")
        self.assertEqual(
            heartbeat.json()["device_lease"],
            {
                "version": 1,
                "state": "revoked",
                "id": rid,
                "uuid": device_uuid,
            },
        )

    def test_deployed_device_login_requires_current_key_proof(self):
        response = self.account_login()

        self.assertEqual(response.status_code, 403, response.content)
        self.assertFalse(response.json().get("access_token"))

    def test_device_key_cannot_be_replaced_without_old_and_new_key_proofs(self):
        login = self.account_login()
        self.assertNotEqual(login.status_code, 200, login.content)

        # A password-only caller must never obtain the bearer needed to reach
        # the deployment mutation, let alone overwrite the enrolled key.
        self.device.refresh_from_db()
        self.assertEqual(
            self.device.public_key_hash,
            hashlib.sha256(bytes(self.old_key.verify_key)).hexdigest(),
        )

    def test_deployment_verification_returns_nonce_bound_assertion(self):
        response = self.post_json(
            "/api/devices/verify-deployment",
            {
                "id": self.device.rid,
                "uuid": self.device.uuid,
                "public_key_hash": self.device.public_key_hash,
                "request_nonce": base64.b64encode(b"n" * 32).decode("ascii"),
            },
            token="v" * 48,
        )

        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertEqual(body["deployment_generation"], 0)
        self.assertEqual(body["request_nonce"], base64.b64encode(b"n" * 32).decode("ascii"))
        message = "\n".join(
            (
                "camellia-deployment-assertion-v1",
                self.device.rid,
                self.device.uuid,
                self.device.public_key_hash,
                str(body["deployment_generation"]),
                body["request_nonce"],
                str(body["expires_at"]),
            )
        )
        expected = hmac.new(b"v" * 48, message.encode(), hashlib.sha256).digest()
        self.assertEqual(body["assertion"], base64.b64encode(expected).decode("ascii"))

    def test_active_heartbeat_issues_a_bounded_device_lease(self):
        proof, _message = self.proof("login", self.old_key)
        login = self.login_with_proof(proof)
        self.assertEqual(login.status_code, 200, login.content)

        heartbeat = self.post_json(
            "/api/heartbeat",
            {"id": self.device.rid, "uuid": self.device.uuid, "modified_at": 0},
            token=login.json()["access_token"],
        )

        self.assertEqual(heartbeat.status_code, 200, heartbeat.content)
        self.assertEqual(heartbeat.headers.get("Cache-Control"), "no-store, private")
        self.assertEqual(
            heartbeat.json()["device_lease"],
            {
                "version": 1,
                "state": "active",
                "id": self.device.rid,
                "uuid": self.device.uuid,
                "deployment_generation": 0,
                "valid_for_seconds": 60,
            },
        )

    def test_heartbeat_revocation_race_cannot_renew_a_deleted_token(self):
        bearer = self.login_bearer()
        token = RemoteToken.objects.get(device=self.device)
        original_expiry = token.expires_at

        with mock.patch("api.views_api.RemoteToken.objects.filter") as token_filter:
            token_filter.return_value.update.return_value = 0
            heartbeat = self.post_json(
                "/api/heartbeat",
                {"id": self.device.rid, "uuid": self.device.uuid, "modified_at": 0},
                token=bearer,
            )

        self.assertEqual(heartbeat.status_code, 401, heartbeat.content)
        self.assertEqual(
            heartbeat.json()["device_lease"],
            {
                "version": 1,
                "state": "revoked",
                "id": self.device.rid,
                "uuid": self.device.uuid,
            },
        )
        token.refresh_from_db()
        self.assertEqual(token.expires_at, original_expiry)

    def test_concurrent_device_denial_returns_a_bound_revocation_heartbeat(self):
        bearer = self.login_bearer()
        token = RemoteToken.objects.get(device=self.device)
        self.device.is_active = False
        self.device.save(update_fields=("is_active", "update_time"))

        with mock.patch(
            "api.views_api._get_device_token_user",
            return_value=(token, self.user),
        ):
            heartbeat = self.post_json(
                "/api/heartbeat",
                {"id": self.device.rid, "uuid": self.device.uuid, "modified_at": 0},
                token=bearer,
            )

        self.assertEqual(heartbeat.status_code, 403, heartbeat.content)
        self.assertEqual(
            heartbeat.json()["device_lease"],
            {
                "version": 1,
                "state": "revoked",
                "id": self.device.rid,
                "uuid": self.device.uuid,
            },
        )

    def test_revoked_heartbeat_returns_a_bound_revocation_state(self):
        bearer = self.login_bearer()
        self.device.is_active = False
        self.device.save(update_fields=("is_active", "update_time"))
        RemoteToken.objects.filter(device=self.device).delete()

        self.assert_bound_revoked_heartbeat(bearer)

    def test_device_disable_returns_a_bound_revocation_heartbeat(self):
        bearer = self.login_bearer()
        disabled = self.post_json(
            f"/api/devices/{self.device.pk}/disable",
            {},
            token=self.admin_bearer(),
        )
        self.assertEqual(disabled.status_code, 200, disabled.content)

        self.assert_bound_revoked_heartbeat(bearer)

    def test_device_delete_returns_a_bound_revocation_heartbeat(self):
        bearer = self.login_bearer()
        rid, device_uuid = self.device.rid, self.device.uuid
        deleted = self.delete_json(
            f"/api/devices/{self.device.pk}",
            {},
            token=self.admin_bearer(),
        )
        self.assertEqual(deleted.status_code, 200, deleted.content)

        self.assert_bound_revoked_heartbeat(bearer, rid, device_uuid)

    def test_user_disable_returns_a_bound_revocation_heartbeat(self):
        bearer = self.login_bearer()
        disabled = self.post_json(
            f"/api/users/{self.user.pk}/disable",
            {},
            token=self.admin_bearer(),
        )
        self.assertEqual(disabled.status_code, 200, disabled.content)

        self.assert_bound_revoked_heartbeat(bearer)

    def test_user_delete_returns_a_bound_revocation_heartbeat(self):
        bearer = self.login_bearer()
        rid, device_uuid = self.device.rid, self.device.uuid
        deleted = self.delete_json(
            f"/api/users/{self.user.pk}",
            {},
            token=self.admin_bearer(),
        )
        self.assertEqual(deleted.status_code, 200, deleted.content)

        self.assert_bound_revoked_heartbeat(bearer, rid, device_uuid)

    def test_force_logout_returns_a_bound_revocation_heartbeat(self):
        bearer = self.login_bearer()
        revoked = self.post_json(
            "/api/users/force-logout",
            {"user_guids": [str(self.user.pk)]},
            token=self.admin_bearer(),
        )
        self.assertEqual(revoked.status_code, 200, revoked.content)

        self.assert_bound_revoked_heartbeat(bearer)

    def test_current_key_login_consumes_challenge_once(self):
        proof, _message = self.proof("login", self.old_key)

        first = self.login_with_proof(proof)
        self.assertEqual(first.status_code, 200, first.content)
        replay = self.login_with_proof(proof)
        self.assertEqual(replay.status_code, 403, replay.content)
        self.assertFalse(DeviceProofChallenge.objects.exists())

    def test_login_finalization_failures_roll_back_token_device_and_proof_for_retry(self):
        bearer = self.login_bearer()
        old_token = RemoteToken.objects.get(device=self.device)
        old_token_hash = old_token.access_token
        self.device.refresh_from_db()
        old_hostname = self.device.hostname
        proof, _message = self.proof("login", self.old_key)
        payload = {
            "username": "alice",
            "password": "alice-pass",
            "id": self.device.rid,
            "uuid": self.device.uuid,
            "deviceInfo": {"os": "Linux", "type": "client", "name": "failed-login-hostname"},
            "device_proof": proof,
        }

        finalization_failures = (
            (
                "peer_io",
                "api.views_api._ensure_personal_device_peer",
                OSError("injected personal peer failure"),
            ),
            (
                "peer_integrity",
                "api.views_api._ensure_personal_device_peer",
                IntegrityError("injected personal peer integrity failure"),
            ),
            (
                "admission",
                "api.views_api.complete_login_success",
                RuntimeError("injected admission cleanup failure"),
            ),
        )
        for label, target, failure in finalization_failures:
            with self.subTest(finalizer=label), mock.patch(target, side_effect=failure):
                failed = self.post_json_without_raising("/api/login", payload)

                self.assertEqual(failed.status_code, 500, failed.content)
                self.device.refresh_from_db()
                self.assertEqual(self.device.hostname, old_hostname)
                self.assertEqual(RemoteToken.objects.get(device=self.device).access_token, old_token_hash)
                self.assertEqual(DeviceProofChallenge.objects.count(), 1)
                current = self.post_json("/api/currentUser", {}, token=bearer)
                self.assertEqual(current.status_code, 200, current.content)

        retried = self.post_json("/api/login", payload)
        self.assertEqual(retried.status_code, 200, retried.content)
        self.assertTrue(retried.json()["access_token"])
        self.device.refresh_from_db()
        self.assertEqual(self.device.hostname, "failed-login-hostname")
        self.assertFalse(DeviceProofChallenge.objects.exists())

    def test_deploy_finalization_failure_rolls_back_key_token_and_proof_for_retry(self):
        bearer = self.login_bearer()
        old_token_hash = RemoteToken.objects.get(device=self.device).access_token
        old_key_hash = self.device.public_key_hash
        old_generation = self.device.deployment_generation
        rotation_proof, message = self.proof("deploy", self.new_key, token=bearer)
        rotation_proof.update(
            {
                "old_public_key": base64.b64encode(bytes(self.old_key.verify_key)).decode("ascii"),
                "old_signature": base64.b64encode(self.old_key.sign(message.encode("utf-8")).signature).decode("ascii"),
            }
        )
        payload = {
            "id": self.device.rid,
            "uuid": self.device.uuid,
            "pk": rotation_proof["public_key"],
            "device_proof": rotation_proof,
        }

        finalization_failures = (
            ("io", OSError("injected personal peer failure")),
            ("integrity", IntegrityError("injected personal peer integrity failure")),
        )
        for label, failure in finalization_failures:
            with (
                self.subTest(finalizer=label),
                mock.patch(
                    "api.views_api._ensure_personal_device_peer",
                    side_effect=failure,
                ),
            ):
                failed = self.post_json_without_raising("/api/devices/deploy", payload, token=bearer)

                self.assertEqual(failed.status_code, 500, failed.content)
                self.device.refresh_from_db()
                self.assertEqual(self.device.public_key_hash, old_key_hash)
                self.assertEqual(self.device.deployment_generation, old_generation)
                self.assertEqual(RemoteToken.objects.get(device=self.device).access_token, old_token_hash)
                self.assertEqual(DeviceProofChallenge.objects.count(), 1)
                current = self.post_json("/api/currentUser", {}, token=bearer)
                self.assertEqual(current.status_code, 200, current.content)

        retried = self.post_json("/api/devices/deploy", payload, token=bearer)
        self.assertEqual(retried.status_code, 200, retried.content)
        self.device.refresh_from_db()
        self.assertEqual(self.device.public_key_hash, hashlib.sha256(bytes(self.new_key.verify_key)).hexdigest())
        self.assertEqual(self.device.deployment_generation, old_generation + 1)
        self.assertFalse(RemoteToken.objects.filter(device=self.device).exists())
        self.assertFalse(DeviceProofChallenge.objects.exists())

    def test_lost_login_response_recovers_with_a_fresh_current_key_proof(self):
        first_proof, _message = self.proof("login", self.old_key)
        first = self.login_with_proof(first_proof)
        self.assertEqual(first.status_code, 200, first.content)
        unknown_token = first.json()["access_token"]

        retry_proof, _message = self.proof("login", self.old_key)
        recovered = self.login_with_proof(retry_proof)

        self.assertEqual(recovered.status_code, 200, recovered.content)
        recovered_token = recovered.json()["access_token"]
        self.assertNotEqual(recovered_token, unknown_token)
        self.assertEqual(self.post_json("/api/currentUser", {}, token=unknown_token).status_code, 401)
        self.assertEqual(self.post_json("/api/currentUser", {}, token=recovered_token).status_code, 200)
        self.assertFalse(DeviceProofChallenge.objects.exists())

    def test_lost_deploy_response_recovers_by_logging_in_with_the_committed_new_key(self):
        bearer = self.login_bearer()
        rotation_proof, message = self.proof("deploy", self.new_key, token=bearer)
        rotation_proof.update(
            {
                "old_public_key": base64.b64encode(bytes(self.old_key.verify_key)).decode("ascii"),
                "old_signature": base64.b64encode(self.old_key.sign(message.encode("utf-8")).signature).decode("ascii"),
            }
        )
        committed = self.post_json(
            "/api/devices/deploy",
            {
                "id": self.device.rid,
                "uuid": self.device.uuid,
                "pk": rotation_proof["public_key"],
                "device_proof": rotation_proof,
            },
            token=bearer,
        )
        self.assertEqual(committed.status_code, 200, committed.content)
        self.assertEqual(self.post_json("/api/currentUser", {}, token=bearer).status_code, 401)

        recovery_login_proof, _message = self.proof("login", self.new_key)
        recovered = self.login_with_proof(recovery_login_proof)

        self.assertEqual(recovered.status_code, 200, recovered.content)
        recovered_token = recovered.json()["access_token"]
        self.assertEqual(self.post_json("/api/currentUser", {}, token=recovered_token).status_code, 200)
        self.device.refresh_from_db()
        self.assertEqual(self.device.public_key_hash, hashlib.sha256(bytes(self.new_key.verify_key)).hexdigest())
        self.assertEqual(self.device.deployment_generation, 1)
        self.assertFalse(DeviceProofChallenge.objects.exists())

    def test_oidc_poll_consumes_the_bound_current_key_proof_with_token_issue(self):
        proof, _message = self.proof("oidc", self.old_key)
        poll_code = "oidc-proof-poll-code"
        OidcPendingAuth.objects.create(
            state="oidc-proof-state",
            poll_code_hash=hashlib.sha256(poll_code.encode()).hexdigest(),
            provider="test",
            rid=self.device.rid,
            device_uuid=self.device.uuid,
            device_info={"os": "Linux", "type": "client", "name": "original"},
            device_proof=proof,
            nonce="oidc-nonce",
            code_verifier="oidc-verifier",
            status=OidcPendingAuth.STATUS_DONE,
            authenticated_user=self.user,
        )

        response = self.post_json(
            "/api/oidc/auth-query",
            {"code": poll_code, "id": self.device.rid, "uuid": self.device.uuid},
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(response.json()["access_token"])
        self.assertFalse(OidcPendingAuth.objects.exists())
        self.assertFalse(DeviceProofChallenge.objects.exists())

    def test_first_enrollment_requires_and_consumes_new_key_proof(self):
        self.device.public_key_hash = None
        self.device.save(update_fields=("public_key_hash", "update_time"))
        login = self.account_login()
        self.assertEqual(login.status_code, 200, login.content)
        bearer = login.json()["access_token"]

        without_proof = self.post_json(
            "/api/devices/deploy",
            {
                "id": self.device.rid,
                "uuid": self.device.uuid,
                "pk": base64.b64encode(bytes(self.new_key.verify_key)).decode("ascii"),
            },
            token=bearer,
        )
        self.assertEqual(without_proof.status_code, 403, without_proof.content)

        proof, _message = self.proof("deploy", self.new_key, token=bearer)
        deployed = self.post_json(
            "/api/devices/deploy",
            {
                "id": self.device.rid,
                "uuid": self.device.uuid,
                "pk": proof["public_key"],
                "device_proof": proof,
            },
            token=bearer,
        )
        self.assertEqual(deployed.status_code, 200, deployed.content)
        self.device.refresh_from_db()
        self.assertEqual(self.device.public_key_hash, hashlib.sha256(bytes(self.new_key.verify_key)).hexdigest())
        self.assertEqual(self.device.deployment_generation, 1)
        self.assertFalse(DeviceProofChallenge.objects.exists())

    def test_rotation_requires_old_and_new_signatures_and_revokes_bearer(self):
        login_proof, _message = self.proof("login", self.old_key)
        login = self.login_with_proof(login_proof)
        self.assertEqual(login.status_code, 200, login.content)
        bearer = login.json()["access_token"]
        rotation_proof, message = self.proof("deploy", self.new_key, token=bearer)
        rotation_proof.update(
            {
                "old_public_key": base64.b64encode(bytes(self.old_key.verify_key)).decode("ascii"),
                "old_signature": base64.b64encode(self.old_key.sign(message.encode("utf-8")).signature).decode("ascii"),
            }
        )

        rotated = self.post_json(
            "/api/devices/deploy",
            {
                "id": self.device.rid,
                "uuid": self.device.uuid,
                "pk": rotation_proof["public_key"],
                "device_proof": rotation_proof,
            },
            token=bearer,
        )

        self.assertEqual(rotated.status_code, 200, rotated.content)
        self.device.refresh_from_db()
        self.assertEqual(self.device.public_key_hash, hashlib.sha256(bytes(self.new_key.verify_key)).hexdigest())
        self.assertEqual(self.device.deployment_generation, 1)
        self.assertFalse(RemoteToken.objects.filter(device=self.device).exists())

    def test_current_key_proof_allows_a_bound_remote_id_change(self):
        login_proof, _message = self.proof("login", self.old_key)
        login = self.login_with_proof(login_proof)
        bearer = login.json()["access_token"]
        new_rid = "987654321"
        deploy_proof, _message = self.proof(
            "deploy",
            self.old_key,
            token=bearer,
            rid=new_rid,
        )

        changed = self.post_json(
            "/api/devices/deploy",
            {
                "id": new_rid,
                "uuid": self.device.uuid,
                "pk": deploy_proof["public_key"],
                "device_proof": deploy_proof,
            },
            token=bearer,
        )

        self.assertEqual(changed.status_code, 200, changed.content)
        self.device.refresh_from_db()
        self.assertEqual(self.device.rid, new_rid)
        self.assertEqual(self.device.deployment_generation, 1)
        self.assertFalse(RemoteToken.objects.filter(device=self.device).exists())

    def test_lost_key_rotation_consumes_short_lived_admin_approval_once(self):
        login_proof, _message = self.proof("login", self.old_key)
        login = self.login_with_proof(login_proof)
        bearer = login.json()["access_token"]
        recovery_proof, _message = self.proof("deploy", self.new_key, token=bearer)
        payload = {
            "id": self.device.rid,
            "uuid": self.device.uuid,
            "pk": recovery_proof["public_key"],
            "device_proof": recovery_proof,
        }
        denied = self.post_json("/api/devices/deploy", payload, token=bearer)
        self.assertEqual(denied.status_code, 409, denied.content)
        self.assertEqual(denied.json()["result"], "RECOVERY_REQUIRED")

        admin = UserProfile.objects.create_user(
            username="admin",
            password="admin-pass",  # noqa: S106 - isolated test credential
            is_active=True,
            is_admin=True,
        )
        admin_device = RemoteDevice.objects.create(
            rid="900000001",
            uuid=base64.b64encode(b"admin-device").decode("ascii"),
            owner=admin,
            is_active=True,
            cpu="-",
            hostname="-",
            memory="-",
            os="-",
            username="",
            version="-",
        )
        admin_login = self.post_json(
            "/api/login",
            {
                "username": "admin",
                "password": "admin-pass",
                "id": admin_device.rid,
                "uuid": admin_device.uuid,
                "deviceInfo": {},
            },
        )
        admin_bearer = admin_login.json()["access_token"]
        approved = self.post_json(
            f"/api/devices/{self.device.pk}/approve-recovery",
            {"pk": recovery_proof["public_key"]},
            token=admin_bearer,
        )
        self.assertEqual(approved.status_code, 200, approved.content)

        recovered = self.post_json("/api/devices/deploy", payload, token=bearer)
        self.assertEqual(recovered.status_code, 200, recovered.content)
        approval = DeviceRecoveryApproval.objects.get(device=self.device)
        self.assertIsNotNone(approval.consumed_at)
        self.assertLessEqual((approval.expires_at - approval.created_at).total_seconds(), 600)

    def test_failed_recovery_does_not_consume_approval_or_challenge(self):
        self.device.deployment_generation = MAX_DEPLOYMENT_GENERATION
        self.device.save(update_fields=("deployment_generation", "update_time"))
        login_proof, _message = self.proof("login", self.old_key)
        login = self.login_with_proof(login_proof)
        bearer = login.json()["access_token"]
        recovery_proof, _message = self.proof("deploy", self.new_key, token=bearer)
        admin = UserProfile.objects.create_user(
            username="recovery-admin",
            password="admin-pass",  # noqa: S106 - isolated test credential
            is_active=True,
            is_admin=True,
        )
        approval = DeviceRecoveryApproval.objects.create(
            device=self.device,
            public_key_hash=hashlib.sha256(bytes(self.new_key.verify_key)).hexdigest(),
            approved_by=admin,
            expires_at=timezone.now() + datetime.timedelta(minutes=10),
        )

        response = self.post_json(
            "/api/devices/deploy",
            {
                "id": self.device.rid,
                "uuid": self.device.uuid,
                "pk": recovery_proof["public_key"],
                "device_proof": recovery_proof,
            },
            token=bearer,
        )

        self.assertEqual(response.status_code, 403, response.content)
        approval.refresh_from_db()
        self.assertIsNone(approval.consumed_at)
        self.assertTrue(
            DeviceProofChallenge.objects.filter(
                code_hash=hashlib.sha256(recovery_proof["challenge"].encode()).hexdigest()
            ).exists()
        )

    def test_admin_state_change_revokes_pending_device_identity_state(self):
        self.proof("login", self.old_key)
        admin_user = UserProfile.objects.create_user(
            username="state-admin",
            password="admin-pass",  # noqa: S106 - isolated test credential
            is_active=True,
            is_admin=True,
        )
        DeviceRecoveryApproval.objects.create(
            device=self.device,
            public_key_hash=hashlib.sha256(bytes(self.new_key.verify_key)).hexdigest(),
            approved_by=admin_user,
            expires_at=timezone.now() + datetime.timedelta(minutes=10),
        )
        request = RequestFactory().post(f"/admin/api/remotedevice/{self.device.pk}/change/")
        request.user = admin_user
        model_admin = RemoteDeviceAdminCustom(RemoteDevice, admin.site)
        self.device.is_active = False

        model_admin.save_model(request, self.device, form=None, change=True)

        self.assertFalse(DeviceProofChallenge.objects.exists())
        self.assertFalse(DeviceRecoveryApproval.objects.filter(consumed_at__isnull=True).exists())
        self.assertFalse(model_admin.has_add_permission(request))


@override_settings(DEVICE_VERIFICATION_TOKEN="v" * 48)
class PostgreSQLDeviceIdentityProofTests(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        self.user = UserProfile.objects.create_user(
            username="concurrent-alice",
            password="alice-pass",  # noqa: S106 - isolated test credential
            is_active=True,
        )
        self.old_key = SigningKey.generate()
        self.new_key = SigningKey.generate()
        self.device = RemoteDevice.objects.create(
            rid="223456789",
            uuid=base64.b64encode(b"auth-016-concurrent-device").decode("ascii"),
            public_key_hash=hashlib.sha256(bytes(self.old_key.verify_key)).hexdigest(),
            owner=self.user,
            is_active=True,
            cpu="-",
            hostname="-",
            memory="-",
            os="-",
            username="",
            version="-",
        )

    @staticmethod
    def post_json(client, path, payload, token=None):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"} if token else {}
        return client.post(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )

    def proof(self, purpose, signing_key, token=None):
        public_key = base64.b64encode(bytes(signing_key.verify_key)).decode("ascii")
        response = self.post_json(
            self.client,
            "/api/devices/proof-challenge",
            {
                "purpose": purpose,
                "id": self.device.rid,
                "uuid": self.device.uuid,
                "pk": public_key,
            },
            token=token,
        )
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        signature = signing_key.sign(body["message"].encode()).signature
        return {
            "challenge": body["challenge"],
            "public_key": public_key,
            "signature": base64.b64encode(signature).decode("ascii"),
        }, body["message"]

    def login_payload(self, proof):
        return {
            "username": self.user.username,
            "password": "alice-pass",
            "id": self.device.rid,
            "uuid": self.device.uuid,
            "deviceInfo": {"os": "Linux", "type": "client", "name": "concurrent"},
            "device_proof": proof,
        }

    def login_bearer(self):
        proof, _message = self.proof("login", self.old_key)
        response = self.post_json(self.client, "/api/login", self.login_payload(proof))
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()["access_token"]

    @skipUnlessDBFeature("has_select_for_update")
    def test_concurrent_revocation_cannot_be_renewed_by_stale_heartbeat_auth(self):
        bearer = self.login_bearer()
        authenticated = threading.Event()
        resume_heartbeat = threading.Event()

        original_get_device_token_user = views_api._get_device_token_user

        def pause_after_auth(request, rid, device_uuid):
            result = original_get_device_token_user(request, rid, device_uuid)
            authenticated.set()
            if not resume_heartbeat.wait(timeout=20):
                raise TimeoutError("heartbeat revocation barrier timed out")
            return result

        def heartbeat():
            close_old_connections()
            try:
                return self.post_json(
                    Client(),
                    "/api/heartbeat",
                    {"id": self.device.rid, "uuid": self.device.uuid, "modified_at": 0},
                    token=bearer,
                )
            finally:
                connections.close_all()

        with mock.patch(
            "api.views_api._get_device_token_user",
            side_effect=pause_after_auth,
        ):
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                pending_heartbeat = executor.submit(heartbeat)
                self.assertTrue(authenticated.wait(timeout=20))
                try:
                    revocation = revoke_user_credentials((self.user.pk,))
                finally:
                    resume_heartbeat.set()
                response = pending_heartbeat.result(timeout=30)

        self.assertEqual(revocation.deleted_tokens, 1)
        self.assertEqual(response.status_code, 401, response.content)
        self.assertEqual(
            response.json()["device_lease"],
            {
                "version": 1,
                "state": "revoked",
                "id": self.device.rid,
                "uuid": self.device.uuid,
            },
        )
        self.assertFalse(RemoteToken.objects.filter(device=self.device).exists())

    @staticmethod
    def run_concurrently(payloads, token=None):
        start = threading.Barrier(len(payloads) + 1)

        def submit(payload):
            close_old_connections()
            try:
                client = Client()
                start.wait(timeout=10)
                return PostgreSQLDeviceIdentityProofTests.post_json(
                    client,
                    "/api/devices/deploy" if token else "/api/login",
                    payload,
                    token=token,
                ).status_code
            finally:
                connections.close_all()

        def execute():
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(payloads)) as executor:
                jobs = [executor.submit(submit, payload) for payload in payloads]
                start.wait(timeout=10)
                return [job.result(timeout=20) for job in jobs]

        if not token:
            return execute()

        from api import views_api

        authenticated = threading.Barrier(len(payloads))
        original_get_token_user = views_api._get_token_user

        def synchronize_after_authentication(request):
            result = original_get_token_user(request)
            authenticated.wait(timeout=10)
            return result

        with mock.patch(
            "api.views_api._get_token_user",
            side_effect=synchronize_after_authentication,
        ):
            return execute()

    @skipUnlessDBFeature("has_select_for_update")
    def test_one_login_challenge_can_issue_only_one_concurrent_bearer(self):
        proof, _message = self.proof("login", self.old_key)

        statuses = self.run_concurrently([self.login_payload(proof), self.login_payload(proof)])

        self.assertEqual(sorted(statuses), [200, 403])
        self.assertEqual(RemoteToken.objects.filter(device=self.device).count(), 1)
        self.assertFalse(DeviceProofChallenge.objects.exists())

    @skipUnlessDBFeature("has_select_for_update")
    def test_concurrent_challenge_admission_enforces_the_exact_ip_cap(self):
        workers = MAX_OUTSTANDING_CHALLENGES_PER_IP + 4
        start = threading.Barrier(workers + 1)
        public_key = base64.b64encode(bytes(self.old_key.verify_key)).decode("ascii")

        def issue():
            close_old_connections()
            try:
                start.wait(timeout=10)
                try:
                    issue_proof_challenge(
                        purpose="login",
                        rid=self.device.rid,
                        device_uuid=self.device.uuid,
                        public_key_text=public_key,
                        request_ip="192.0.2.50",
                        device=self.device,
                    )
                except DeviceProofError:
                    return False
                return True
            finally:
                connections.close_all()

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            jobs = [executor.submit(issue) for _ in range(workers)]
            start.wait(timeout=10)
            admitted = [job.result(timeout=30) for job in jobs]

        self.assertEqual(sum(admitted), MAX_OUTSTANDING_CHALLENGES_PER_IP)
        self.assertEqual(
            DeviceProofChallenge.objects.filter(request_ip="192.0.2.50").count(),
            MAX_OUTSTANDING_CHALLENGES_PER_IP,
        )

    @skipUnlessDBFeature("has_select_for_update")
    def test_same_generation_concurrent_rotations_have_one_winner(self):
        bearer = self.login_bearer()
        proofs = []
        for _ in range(2):
            proof, message = self.proof("deploy", self.new_key, token=bearer)
            proof["old_public_key"] = base64.b64encode(bytes(self.old_key.verify_key)).decode("ascii")
            proof["old_signature"] = base64.b64encode(self.old_key.sign(message.encode()).signature).decode("ascii")
            proofs.append(proof)
        payloads = [
            {
                "id": self.device.rid,
                "uuid": self.device.uuid,
                "pk": proof["public_key"],
                "device_proof": proof,
            }
            for proof in proofs
        ]

        statuses = self.run_concurrently(payloads, token=bearer)

        # The winning key rotation revokes the bearer. The request that was
        # authenticated concurrently must revalidate it after acquiring the
        # user authority lock and fail as unauthenticated, not continue with a
        # stale token until proof validation.
        self.assertEqual(sorted(statuses), [200, 401])
        self.device.refresh_from_db()
        self.assertEqual(self.device.deployment_generation, 1)
        self.assertEqual(
            self.device.public_key_hash,
            hashlib.sha256(bytes(self.new_key.verify_key)).hexdigest(),
        )

    @skipUnlessDBFeature("has_select_for_update")
    def test_recovery_approval_can_be_consumed_by_only_one_concurrent_rotation(self):
        bearer = self.login_bearer()
        proofs = [self.proof("deploy", self.new_key, token=bearer)[0] for _ in range(2)]
        admin = UserProfile.objects.create_user(
            username="concurrent-admin",
            password="admin-pass",  # noqa: S106 - isolated test credential
            is_active=True,
            is_admin=True,
        )
        approval = DeviceRecoveryApproval.objects.create(
            device=self.device,
            public_key_hash=hashlib.sha256(bytes(self.new_key.verify_key)).hexdigest(),
            approved_by=admin,
            expires_at=timezone.now() + datetime.timedelta(minutes=10),
        )
        payloads = [
            {
                "id": self.device.rid,
                "uuid": self.device.uuid,
                "pk": proof["public_key"],
                "device_proof": proof,
            }
            for proof in proofs
        ]

        statuses = self.run_concurrently(payloads, token=bearer)

        # The winning recovery revokes the bearer before the waiting request
        # acquires the user authority lock.
        self.assertEqual(sorted(statuses), [200, 401])
        approval.refresh_from_db()
        self.assertIsNotNone(approval.consumed_at)
        self.device.refresh_from_db()
        self.assertEqual(self.device.deployment_generation, 1)
