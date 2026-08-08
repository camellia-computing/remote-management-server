import base64
import concurrent.futures
import json
import threading
import uuid
from unittest.mock import patch

from django.db import OperationalError, close_old_connections, connections
from django.test import Client, TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature

from api import management_operations, views_api
from api.credential_sessions import MAX_CREDENTIAL_GENERATION, revoke_user_credentials
from api.device_identity import MAX_DEPLOYMENT_GENERATION
from api.models import ManagementBatchOperation, RemoteDevice, RemoteToken, UserProfile
from api.views_api import _issue_access_token

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


def _device_uuid(label):
    return base64.b64encode(label.encode()).decode()


@override_settings(STORAGES=TEST_STORAGES)
class ControlMutationTransactionTests(TestCase):
    def setUp(self):
        self.admin = UserProfile.objects.create_superuser(
            "control-admin",
            "control-admin-pass",  # noqa: S106 - isolated test credential
        )
        self.admin_device = self._device("751000001", "control-admin-device", self.admin)
        _token, self.bearer = _issue_access_token(self.admin, self.admin_device)
        self.target = UserProfile.objects.create_user(
            "control-target",
            "control-target-pass",  # noqa: S106 - isolated test credential
        )
        self.target_device = self._device("751000002", "control-target-device", self.target)
        _token, self.target_bearer = _issue_access_token(self.target, self.target_device)
        self.client = Client(raise_request_exception=False)

    @staticmethod
    def _device(rid, label, owner):
        return RemoteDevice.objects.create(
            rid=rid,
            uuid=_device_uuid(label),
            owner=owner,
            is_active=True,
            cpu="-",
            hostname=label,
            memory="-",
            os="Linux",
            username=owner.username,
            version="test",
        )

    def _request(self, method, path, *, operation_id=None):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {self.bearer}"}
        if operation_id is not None:
            headers["HTTP_IDEMPOTENCY_KEY"] = operation_id
        return getattr(self.client, method)(
            path,
            data=json.dumps({}),
            content_type="application/json",
            **headers,
        )

    def _assert_receipt(self, response, operation, operation_id, target_kind):
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertEqual(body["management_operation_receipt_version"], 1)
        self.assertEqual(body["operation_id"], operation_id)
        self.assertEqual(body["operation"], operation)
        self.assertIsInstance(body["operation_generation"], int)
        self.assertGreater(body["operation_generation"], 0)
        self.assertRegex(body["request_digest"], r"^[0-9a-f]{64}$")
        self.assertRegex(body["result_digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(body["requested"], {target_kind: 1})
        self.assertEqual(body["applied"], {target_kind: 1})
        return body

    def test_control_mutations_require_a_canonical_operation_identifier(self):
        missing_user = UserProfile.objects.create_user("missing-user-operation")
        missing_user_device = self._device("751000003", "missing-user-device", missing_user)
        cases = (
            ("post", f"/api/users/{missing_user.pk}/disable"),
            ("post", f"/api/users/{self.target.pk}/enable"),
            ("post", f"/api/devices/{missing_user_device.pk}/disable"),
            ("post", f"/api/devices/{self.target_device.pk}/enable"),
            ("delete", f"/api/devices/{self.target_device.pk}"),
        )

        for method, path in cases:
            with self.subTest(method=method, path=path):
                response = self._request(method, path)
                self.assertEqual(response.status_code, 400, response.content)
                self.assertEqual(response.json(), {"error": "Valid Idempotency-Key required"})

        invalid = self._request(
            "post",
            f"/api/users/{self.target.pk}/disable",
            operation_id="not-a-uuid",
        )
        self.assertEqual(invalid.status_code, 400, invalid.content)
        self.assertFalse(ManagementBatchOperation.objects.exists())

    def test_user_disable_replay_returns_the_same_receipt_and_revokes_once(self):
        operation_id = str(uuid.uuid4())
        path = f"/api/users/{self.target.pk}/disable"

        accepted = self._request("post", path, operation_id=operation_id)
        first_body = self._assert_receipt(
            accepted,
            "user_status_disable",
            operation_id,
            "users",
        )
        replayed = self._request("post", path, operation_id=operation_id)

        self.assertEqual(replayed.status_code, 200, replayed.content)
        self.assertEqual(replayed.json(), first_body)
        self.target.refresh_from_db()
        self.assertFalse(self.target.is_active)
        self.assertEqual(self.target.credential_generation, 1)
        self.assertFalse(RemoteToken.objects.filter(device=self.target_device).exists())
        self.assertEqual(ManagementBatchOperation.objects.filter(operation_id=operation_id).count(), 1)

    def test_device_disable_replay_returns_the_same_receipt_and_revokes_once(self):
        operation_id = str(uuid.uuid4())
        path = f"/api/devices/{self.target_device.pk}/disable"

        accepted = self._request("post", path, operation_id=operation_id)
        first_body = self._assert_receipt(
            accepted,
            "device_status_disable",
            operation_id,
            "devices",
        )
        replayed = self._request("post", path, operation_id=operation_id)

        self.assertEqual(replayed.status_code, 200, replayed.content)
        self.assertEqual(replayed.json(), first_body)
        self.target_device.refresh_from_db()
        self.assertFalse(self.target_device.is_active)
        self.assertEqual(self.target_device.deployment_generation, 1)
        self.assertFalse(RemoteToken.objects.filter(device=self.target_device).exists())
        self.assertEqual(ManagementBatchOperation.objects.filter(operation_id=operation_id).count(), 1)

    def test_device_delete_replay_returns_success_after_the_row_is_gone(self):
        operation_id = str(uuid.uuid4())
        target_pk = self.target_device.pk
        path = f"/api/devices/{target_pk}"

        accepted = self._request("delete", path, operation_id=operation_id)
        first_body = self._assert_receipt(
            accepted,
            "device_delete",
            operation_id,
            "devices",
        )
        replayed = self._request("delete", path, operation_id=operation_id)

        self.assertEqual(replayed.status_code, 200, replayed.content)
        self.assertEqual(replayed.json(), first_body)
        self.assertFalse(RemoteDevice.objects.filter(pk=target_pk).exists())
        self.assertEqual(ManagementBatchOperation.objects.filter(operation_id=operation_id).count(), 1)

    def test_user_and_device_enable_replays_do_not_repeat_authority_mutations(self):
        user_disable_id = str(uuid.uuid4())
        device_disable_id = str(uuid.uuid4())
        self.assertEqual(
            self._request(
                "post",
                f"/api/users/{self.target.pk}/disable",
                operation_id=user_disable_id,
            ).status_code,
            200,
        )
        self.assertEqual(
            self._request(
                "post",
                f"/api/devices/{self.target_device.pk}/disable",
                operation_id=device_disable_id,
            ).status_code,
            200,
        )

        user_enable_id = str(uuid.uuid4())
        user_path = f"/api/users/{self.target.pk}/enable"
        user_enabled = self._request("post", user_path, operation_id=user_enable_id)
        user_body = self._assert_receipt(
            user_enabled,
            "user_status_enable",
            user_enable_id,
            "users",
        )
        self.assertEqual(self._request("post", user_path, operation_id=user_enable_id).json(), user_body)

        device_enable_id = str(uuid.uuid4())
        device_path = f"/api/devices/{self.target_device.pk}/enable"
        device_enabled = self._request("post", device_path, operation_id=device_enable_id)
        device_body = self._assert_receipt(
            device_enabled,
            "device_status_enable",
            device_enable_id,
            "devices",
        )
        self.assertEqual(self._request("post", device_path, operation_id=device_enable_id).json(), device_body)

        self.target.refresh_from_db()
        self.target_device.refresh_from_db()
        self.assertTrue(self.target.is_active)
        self.assertTrue(self.target_device.is_active)
        self.assertEqual(self.target.credential_generation, 1)
        self.assertEqual(self.target_device.deployment_generation, 1)

    def test_generation_exhaustion_is_a_durable_zero_application_receipt(self):
        operation_id = str(uuid.uuid4())
        UserProfile.objects.filter(pk=self.target.pk).update(
            credential_generation=MAX_CREDENTIAL_GENERATION,
        )
        path = f"/api/users/{self.target.pk}/disable"

        rejected = self._request("post", path, operation_id=operation_id)
        first_body = rejected.json()
        replayed = self._request("post", path, operation_id=operation_id)

        self.assertEqual(rejected.status_code, 409, rejected.content)
        self.assertEqual(first_body["error"], "Credential revocation failed")
        self.assertEqual(first_body["requested"], {"users": 1})
        self.assertEqual(first_body["applied"], {"users": 0})
        self.assertEqual(replayed.status_code, 409, replayed.content)
        self.assertEqual(replayed.json(), first_body)
        self.target.refresh_from_db()
        self.assertTrue(self.target.is_active)
        self.assertEqual(self.target.credential_generation, MAX_CREDENTIAL_GENERATION)
        receipt = ManagementBatchOperation.objects.get(operation_id=operation_id)
        self.assertEqual(receipt.status_code, 409)
        self.assertEqual(receipt.response, first_body)

        device_operation_id = str(uuid.uuid4())
        RemoteDevice.objects.filter(pk=self.target_device.pk).update(
            deployment_generation=MAX_DEPLOYMENT_GENERATION,
        )
        device_path = f"/api/devices/{self.target_device.pk}/disable"
        device_rejected = self._request(
            "post",
            device_path,
            operation_id=device_operation_id,
        )
        first_device_body = device_rejected.json()
        device_replayed = self._request(
            "post",
            device_path,
            operation_id=device_operation_id,
        )

        self.assertEqual(device_rejected.status_code, 409, device_rejected.content)
        self.assertEqual(first_device_body["error"], "Device authority revocation failed")
        self.assertEqual(first_device_body["requested"], {"devices": 1})
        self.assertEqual(first_device_body["applied"], {"devices": 0})
        self.assertEqual(device_replayed.status_code, 409, device_replayed.content)
        self.assertEqual(device_replayed.json(), first_device_body)
        self.target_device.refresh_from_db()
        self.assertTrue(self.target_device.is_active)
        self.assertEqual(self.target_device.deployment_generation, MAX_DEPLOYMENT_GENERATION)
        self.assertTrue(RemoteToken.objects.filter(device=self.target_device).exists())

    def test_current_admin_device_cannot_destroy_its_receipt_replay_authority(self):
        disable_id = str(uuid.uuid4())
        disable_path = f"/api/devices/{self.admin_device.pk}/disable"
        disabled = self._request("post", disable_path, operation_id=disable_id)
        first_disable_body = disabled.json()

        self.assertEqual(disabled.status_code, 400, disabled.content)
        self.assertEqual(first_disable_body["error"], "Cannot disable current device")
        self.assertEqual(first_disable_body["applied"], {"devices": 0})
        replayed = self._request("post", disable_path, operation_id=disable_id)
        self.assertEqual(replayed.status_code, 400, replayed.content)
        self.assertEqual(replayed.json(), first_disable_body)

        delete_id = str(uuid.uuid4())
        deleted = self._request(
            "delete",
            f"/api/devices/{self.admin_device.pk}",
            operation_id=delete_id,
        )
        self.assertEqual(deleted.status_code, 400, deleted.content)
        self.assertEqual(deleted.json()["error"], "Cannot delete current device")
        self.assertEqual(deleted.json()["applied"], {"devices": 0})
        self.admin_device.refresh_from_db()
        self.assertTrue(self.admin_device.is_active)
        self.assertTrue(RemoteToken.objects.filter(device=self.admin_device).exists())

    def test_operation_identifier_cannot_be_rebound_to_another_control_mutation(self):
        operation_id = str(uuid.uuid4())
        disabled = self._request(
            "post",
            f"/api/users/{self.target.pk}/disable",
            operation_id=operation_id,
        )
        self.assertEqual(disabled.status_code, 200, disabled.content)

        conflict = self._request(
            "post",
            f"/api/devices/{self.target_device.pk}/disable",
            operation_id=operation_id,
        )

        self.assertEqual(conflict.status_code, 409, conflict.content)
        self.assertEqual(conflict.json(), {"error": "Operation identifier conflict"})
        self.target_device.refresh_from_db()
        self.assertTrue(self.target_device.is_active)
        self.assertEqual(ManagementBatchOperation.objects.filter(operation_id=operation_id).count(), 1)

    def test_user_disable_failure_rolls_back_state_credentials_and_receipt(self):
        operation_id = str(uuid.uuid4())

        def revoke_then_fail(user_ids):
            revoke_user_credentials(user_ids)
            raise OperationalError("injected user revocation failure")

        with patch("api.views_api.revoke_user_credentials", side_effect=revoke_then_fail):
            response = self._request(
                "post",
                f"/api/users/{self.target.pk}/disable",
                operation_id=operation_id,
            )

        self.assertEqual(response.status_code, 500, response.content)
        self.target.refresh_from_db()
        self.assertTrue(self.target.is_active)
        self.assertEqual(self.target.credential_generation, 0)
        self.assertTrue(RemoteToken.objects.filter(device=self.target_device).exists())
        self.assertFalse(ManagementBatchOperation.objects.filter(operation_id=operation_id).exists())

    def test_device_disable_failure_rolls_back_state_credentials_and_receipt(self):
        operation_id = str(uuid.uuid4())
        revoke_device_tokens = views_api._revoke_device_tokens

        def revoke_then_fail(device):
            revoke_device_tokens(device)
            raise OperationalError("injected device revocation failure")

        with patch("api.views_api._revoke_device_tokens", side_effect=revoke_then_fail):
            response = self._request(
                "post",
                f"/api/devices/{self.target_device.pk}/disable",
                operation_id=operation_id,
            )

        self.assertEqual(response.status_code, 500, response.content)
        self.target_device.refresh_from_db()
        self.assertTrue(self.target_device.is_active)
        self.assertEqual(self.target_device.deployment_generation, 0)
        self.assertTrue(RemoteToken.objects.filter(device=self.target_device).exists())
        self.assertFalse(ManagementBatchOperation.objects.filter(operation_id=operation_id).exists())

    def test_device_delete_failure_rolls_back_row_credentials_and_receipt(self):
        operation_id = str(uuid.uuid4())
        delete_device = RemoteDevice.delete

        def delete_then_fail(device, *args, **kwargs):
            delete_device(device, *args, **kwargs)
            raise OperationalError("injected device delete failure")

        with patch.object(RemoteDevice, "delete", new=delete_then_fail):
            response = self._request(
                "delete",
                f"/api/devices/{self.target_device.pk}",
                operation_id=operation_id,
            )

        self.assertEqual(response.status_code, 500, response.content)
        self.target_device.refresh_from_db()
        self.assertTrue(self.target_device.is_active)
        self.assertTrue(RemoteToken.objects.filter(device=self.target_device).exists())
        self.assertFalse(ManagementBatchOperation.objects.filter(operation_id=operation_id).exists())


@override_settings(STORAGES=TEST_STORAGES)
class ControlMutationConcurrencyTests(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        self.admin = UserProfile.objects.create_superuser(
            "control-concurrent-admin",
            "control-concurrent-admin-pass",  # noqa: S106 - isolated test credential
        )
        self.admin_device = ControlMutationTransactionTests._device(
            "752000001",
            "control-concurrent-admin-device",
            self.admin,
        )
        self.target = UserProfile.objects.create_user(
            "control-concurrent-target",
            "control-concurrent-target-pass",  # noqa: S106 - isolated test credential
        )
        self.target_device = ControlMutationTransactionTests._device(
            "752000002",
            "control-concurrent-target-device",
            self.target,
        )
        _token, self.bearer = _issue_access_token(self.admin, self.admin_device)
        _token, _raw = _issue_access_token(self.target, self.target_device)

    def _disable_user(self, operation_id, barrier):
        close_old_connections()
        try:
            barrier.wait(timeout=20)
            return Client(raise_request_exception=False).post(
                f"/api/users/{self.target.pk}/disable",
                data=json.dumps({}),
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {self.bearer}",
                HTTP_IDEMPOTENCY_KEY=operation_id,
            )
        finally:
            connections.close_all()

    @staticmethod
    def _disable_user_as(actor_bearer, target_id, operation_id):
        close_old_connections()
        try:
            return Client(raise_request_exception=False).post(
                f"/api/users/{target_id}/disable",
                data=json.dumps({}),
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {actor_bearer}",
                HTTP_IDEMPOTENCY_KEY=operation_id,
            )
        finally:
            connections.close_all()

    @skipUnlessDBFeature("has_select_for_update")
    def test_concurrent_identical_user_disable_revokes_once_and_replays_one_receipt(self):
        operation_id = str(uuid.uuid4())
        barrier = threading.Barrier(3)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(self._disable_user, operation_id, barrier)
            second = executor.submit(self._disable_user, operation_id, barrier)
            barrier.wait(timeout=20)
            responses = (first.result(timeout=60), second.result(timeout=60))

        self.assertTrue(all(response.status_code == 200 for response in responses))
        self.assertEqual(responses[0].json(), responses[1].json())
        self.target.refresh_from_db()
        self.assertFalse(self.target.is_active)
        self.assertEqual(self.target.credential_generation, 1)
        self.assertFalse(RemoteToken.objects.filter(device=self.target_device).exists())
        self.assertEqual(ManagementBatchOperation.objects.filter(operation_id=operation_id).count(), 1)

    @skipUnlessDBFeature("has_select_for_update")
    def test_cross_actor_receipts_do_not_deadlock_with_control_target_locks(self):
        second_admin = UserProfile.objects.create_superuser(
            "control-concurrent-second-admin",
            "control-concurrent-second-admin-pass",  # noqa: S106 - isolated test credential
        )
        second_admin_device = ControlMutationTransactionTests._device(
            "752000003",
            "control-concurrent-second-admin-device",
            second_admin,
        )
        _token, second_bearer = _issue_access_token(second_admin, second_admin_device)
        lock_entry = threading.Barrier(2)
        acquire_mutation_lock = management_operations._acquire_batch_mutation_lock

        def synchronized_mutation_lock():
            lock_entry.wait(timeout=20)
            acquire_mutation_lock()

        with patch(
            "api.management_operations._acquire_batch_mutation_lock",
            side_effect=synchronized_mutation_lock,
        ):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(
                    self._disable_user_as,
                    self.bearer,
                    second_admin.pk,
                    str(uuid.uuid4()),
                )
                second = executor.submit(
                    self._disable_user_as,
                    second_bearer,
                    self.admin.pk,
                    str(uuid.uuid4()),
                )
                responses = (first.result(timeout=60), second.result(timeout=60))

        self.assertTrue(all(response.status_code == 200 for response in responses), [r.content for r in responses])
        self.admin.refresh_from_db()
        second_admin.refresh_from_db()
        self.assertFalse(self.admin.is_active)
        self.assertFalse(second_admin.is_active)
        self.assertEqual(self.admin.credential_generation, 1)
        self.assertEqual(second_admin.credential_generation, 1)
        self.assertEqual(ManagementBatchOperation.objects.count(), 2)
