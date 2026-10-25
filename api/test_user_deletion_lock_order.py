import base64
import concurrent.futures
import datetime
import hashlib
import json
import threading
import time
from unittest import mock

from django.db import close_old_connections, connections
from django.test import Client, TransactionTestCase, override_settings, skipUnlessDBFeature
from django.utils import timezone
from nacl.signing import SigningKey

from api import views_api
from api.models import (
    DeviceProofChallenge,
    DeviceRecoveryApproval,
    RemoteDevice,
    RemoteToken,
    UserProfile,
)
from api.views_api import _issue_access_token


@override_settings(DEVICE_VERIFICATION_TOKEN="v" * 48)
class PostgreSQLUserDeletionLockOrderTests(TransactionTestCase):
    """Keep identity mutations on the authoritative user -> device lock order."""

    reset_sequences = True

    def setUp(self):
        self.admin = UserProfile.objects.create_superuser(
            username="deletion-lock-admin",
            password="admin-pass",  # noqa: S106 - isolated test credential
        )
        self.admin_device = self.create_device(
            self.admin,
            900000001,
            "deletion-lock-admin-device",
            hashlib.sha256(b"deletion-lock-admin-key").hexdigest(),
        )
        self.admin_bearer = _issue_access_token(self.admin, self.admin_device)[1]
        self.user = UserProfile.objects.create_user(
            username="deletion-lock-user",
            password="user-pass",  # noqa: S106 - isolated test credential
        )
        self.signing_key = SigningKey.generate()
        public_key_hash = hashlib.sha256(bytes(self.signing_key.verify_key)).hexdigest()
        self.devices = [
            self.create_device(
                self.user,
                900000010 + index,
                f"deletion-lock-device-{index}",
                public_key_hash if index == 0 else hashlib.sha256(f"device-key-{index}".encode()).hexdigest(),
            )
            for index in range(3)
        ]
        self.device = self.devices[0]
        self.user_bearer = _issue_access_token(self.user, self.device)[1]

    @staticmethod
    def create_device(owner, rid, uuid_seed, public_key_hash):
        return RemoteDevice.objects.create(
            rid=str(rid),
            uuid=base64.b64encode(uuid_seed.encode()).decode("ascii"),
            public_key_hash=public_key_hash,
            owner=owner,
            is_active=True,
            cpu="-",
            hostname=uuid_seed,
            memory="-",
            os="linux",
            username="",
            version="-",
        )

    @staticmethod
    def post_json(path, payload, token):
        return Client().post(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

    @staticmethod
    def delete_user(user_pk, token):
        return Client().delete(
            f"/api/users/{user_pk}",
            data="{}",
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

    def assert_user_fully_deleted(self):
        device_ids = [device.pk for device in self.devices]
        self.assertFalse(UserProfile.objects.filter(pk=self.user.pk).exists())
        self.assertFalse(RemoteToken.objects.filter(device_id__in=device_ids).exists())
        self.assertFalse(DeviceProofChallenge.objects.filter(device_id__in=device_ids).exists())
        self.assertFalse(DeviceRecoveryApproval.objects.filter(device_id__in=device_ids).exists())
        self.assertEqual(
            RemoteDevice.objects.filter(
                pk__in=device_ids,
                owner__isnull=True,
                is_active=False,
                public_key_hash__isnull=True,
            ).count(),
            len(device_ids),
        )

    @staticmethod
    def run_in_connection(operation):
        close_old_connections()
        try:
            return operation()
        finally:
            connections.close_all()

    @staticmethod
    def wait_until_backend_is_lock_blocked(backend_pid, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with connections["default"].cursor() as cursor:
                cursor.execute(
                    "SELECT wait_event_type FROM pg_stat_activity WHERE pid = %s",
                    (backend_pid,),
                )
                row = cursor.fetchone()
            if row and row[0] == "Lock":
                return
            time.sleep(0.01)
        raise TimeoutError(f"backend {backend_pid} did not reach a database lock wait")

    def deployment_proof(self):
        public_key = base64.b64encode(bytes(self.signing_key.verify_key)).decode("ascii")
        challenge = self.post_json(
            "/api/devices/proof-challenge",
            {
                "purpose": "deploy",
                "id": self.device.rid,
                "uuid": self.device.uuid,
                "pk": public_key,
            },
            self.user_bearer,
        )
        self.assertEqual(challenge.status_code, 200, challenge.content)
        body = challenge.json()
        signature = self.signing_key.sign(body["message"].encode()).signature
        return {
            "id": self.device.rid,
            "uuid": self.device.uuid,
            "pk": public_key,
            "device_proof": {
                "challenge": body["challenge"],
                "public_key": public_key,
                "signature": base64.b64encode(signature).decode("ascii"),
            },
        }

    @skipUnlessDBFeature("has_select_for_update")
    def test_delete_wins_before_stale_heartbeat_and_cannot_be_revived(self):
        authenticated = threading.Event()
        resume_heartbeat = threading.Event()
        original_authenticate = views_api._get_device_token_user

        def pause_after_authentication(request, rid, device_uuid):
            result = original_authenticate(request, rid, device_uuid)
            authenticated.set()
            if not resume_heartbeat.wait(timeout=20):
                raise TimeoutError("heartbeat deletion barrier timed out")
            return result

        def heartbeat():
            return self.run_in_connection(
                lambda: self.post_json(
                    "/api/heartbeat",
                    {"id": self.device.rid, "uuid": self.device.uuid, "modified_at": 0},
                    self.user_bearer,
                )
            )

        with mock.patch("api.views_api._get_device_token_user", side_effect=pause_after_authentication):
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                pending_heartbeat = executor.submit(heartbeat)
                self.assertTrue(authenticated.wait(timeout=20))
                try:
                    deleted = self.delete_user(self.user.pk, self.admin_bearer)
                finally:
                    resume_heartbeat.set()
                heartbeat_response = pending_heartbeat.result(timeout=30)

        self.assertEqual(deleted.status_code, 200, deleted.content)
        self.assertIn(heartbeat_response.status_code, (401, 403), heartbeat_response.content)
        self.assertEqual(heartbeat_response.json()["device_lease"]["state"], "revoked")
        self.assert_user_fully_deleted()

    @skipUnlessDBFeature("has_select_for_update")
    def test_delete_serializes_with_reverse_order_multi_device_token_issuance(self):
        for index, device in enumerate(self.devices[1:], start=1):
            DeviceProofChallenge.objects.create(
                code_hash=hashlib.sha256(f"challenge-{index}".encode()).hexdigest(),
                purpose=DeviceProofChallenge.PURPOSE_LOGIN,
                rid=device.rid,
                device_uuid=device.uuid,
                public_key_hash=device.public_key_hash,
                device=device,
                request_ip=f"192.0.2.{index}",
                expires_at=timezone.now() + datetime.timedelta(minutes=5),
            )
            DeviceRecoveryApproval.objects.create(
                device=device,
                public_key_hash=device.public_key_hash,
                approved_by=self.admin,
                expires_at=timezone.now() + datetime.timedelta(minutes=5),
            )

        start = threading.Barrier(len(self.devices) + 2)

        def issue(device_pk):
            def operation():
                thread_user = UserProfile.objects.get(pk=self.user.pk)
                thread_device = RemoteDevice.objects.get(pk=device_pk)
                start.wait(timeout=20)
                try:
                    return _issue_access_token(thread_user, thread_device)[1]
                except PermissionError:
                    return None

            return self.run_in_connection(operation)

        def delete():
            return self.run_in_connection(
                lambda: (start.wait(timeout=20), self.delete_user(self.user.pk, self.admin_bearer))[1]
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.devices) + 1) as executor:
            issuances = [executor.submit(issue, device.pk) for device in reversed(self.devices)]
            deletion = executor.submit(delete)
            start.wait(timeout=20)
            issued = [future.result(timeout=60) for future in issuances]
            deleted = deletion.result(timeout=60)

        self.assertEqual(deleted.status_code, 200, deleted.content)
        self.assertTrue(all(token is None or isinstance(token, str) for token in issued))
        self.assert_user_fully_deleted()

    @skipUnlessDBFeature("has_select_for_update")
    def test_delete_wins_before_stale_deploy_and_deploy_fails_closed(self):
        payload = self.deployment_proof()
        authenticated = threading.Event()
        resume_deploy = threading.Event()
        original_authenticate = views_api._get_token_user

        def pause_target_after_authentication(request):
            result = original_authenticate(request)
            if result[1] and result[1].pk == self.user.pk:
                authenticated.set()
                if not resume_deploy.wait(timeout=20):
                    raise TimeoutError("stale deploy deletion barrier timed out")
            return result

        def deploy():
            return self.run_in_connection(lambda: self.post_json("/api/devices/deploy", payload, self.user_bearer))

        with mock.patch("api.views_api._get_token_user", side_effect=pause_target_after_authentication):
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                pending_deploy = executor.submit(deploy)
                self.assertTrue(authenticated.wait(timeout=20))
                try:
                    deleted = self.delete_user(self.user.pk, self.admin_bearer)
                finally:
                    resume_deploy.set()
                deploy_response = pending_deploy.result(timeout=30)

        self.assertEqual(deleted.status_code, 200, deleted.content)
        self.assertIn(deploy_response.status_code, (401, 403, 404), deploy_response.content)
        self.assert_user_fully_deleted()

    @skipUnlessDBFeature("has_select_for_update")
    def test_deploy_then_delete_has_no_device_user_lock_cycle(self):
        payload = self.deployment_proof()
        device_locked = threading.Event()
        resume_deploy = threading.Event()
        delete_started = threading.Event()
        delete_backend = {}
        original_consume = views_api.consume_deployment_proof

        def pause_with_device_lock(**kwargs):
            device_locked.set()
            if not resume_deploy.wait(timeout=20):
                raise TimeoutError("deploy deletion barrier timed out")
            return original_consume(**kwargs)

        def deploy():
            return self.run_in_connection(lambda: self.post_json("/api/devices/deploy", payload, self.user_bearer))

        def delete():
            def operation():
                connection = connections["default"]
                connection.ensure_connection()
                delete_backend["pid"] = connection.connection.info.backend_pid
                delete_started.set()
                return self.delete_user(self.user.pk, self.admin_bearer)

            return self.run_in_connection(operation)

        with mock.patch("api.views_api.consume_deployment_proof", side_effect=pause_with_device_lock):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                pending_deploy = executor.submit(deploy)
                self.assertTrue(device_locked.wait(timeout=20))
                pending_delete = executor.submit(delete)
                self.assertTrue(delete_started.wait(timeout=20))
                try:
                    self.wait_until_backend_is_lock_blocked(delete_backend["pid"])
                finally:
                    resume_deploy.set()
                deploy_response = pending_deploy.result(timeout=60)
                delete_response = pending_delete.result(timeout=60)

        self.assertEqual(deploy_response.status_code, 200, deploy_response.content)
        self.assertEqual(delete_response.status_code, 200, delete_response.content)
        self.assert_user_fully_deleted()
