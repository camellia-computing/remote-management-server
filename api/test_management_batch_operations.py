import base64
import concurrent.futures
import datetime
import json
import threading
import uuid
from io import StringIO
from unittest.mock import patch

from django.conf import settings
from django.core.management import call_command
from django.db import close_old_connections, connections, transaction
from django.test import (
    Client,
    TestCase,
    TransactionTestCase,
    override_settings,
    skipUnlessDBFeature,
)
from django.utils import timezone

from api import management_operations
from api.encrypted_fields import FIELD_PREFIX
from api.management_operations import document_digest, execute_management_operation
from api.models import (
    DeviceGroup,
    ManagementBatchOperation,
    RemoteDevice,
    RemoteToken,
    StrategyProfile,
    UserProfile,
)
from api.views_api import _issue_access_token

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


def _device_uuid(label):
    return base64.b64encode(label.encode()).decode()


@override_settings(STORAGES=TEST_STORAGES)
class ManagementBatchOperationTests(TestCase):
    def setUp(self):
        self.admin = UserProfile.objects.create_superuser(
            "batch-admin",
            "batch-admin-pass",  # noqa: S106 - isolated test credential
        )
        self.admin_device = self._device("741000001", "batch-admin-device", self.admin)
        _token, self.bearer = _issue_access_token(self.admin, self.admin_device)
        self.first_user = UserProfile.objects.create_user(
            "batch-first-user",
            "batch-first-pass",  # noqa: S106 - isolated test credential
        )
        self.second_user = UserProfile.objects.create_user(
            "batch-second-user",
            "batch-second-pass",  # noqa: S106 - isolated test credential
        )
        self.first_device = self._device("741000002", "batch-first-device", self.first_user)
        self.second_device = self._device("741000003", "batch-second-device", self.second_user)
        self.first_group = DeviceGroup.objects.create(name="batch-first-group")
        self.second_group = DeviceGroup.objects.create(name="batch-second-group")
        self.strategy = StrategyProfile.objects.create(name="batch-strategy", config_options={})
        self.client = Client(raise_request_exception=False)

    def test_cross_repository_canonical_request_digest_vector(self):
        self.assertEqual(
            document_digest(
                {
                    "operation": "strategy_assign",
                    "strategy": None,
                    "peers": ["3"],
                    "users": ["7"],
                    "groups": [],
                    "expected_generations": {
                        "devices": {"3": 0},
                        "users": {"7": 0},
                        "groups": {},
                    },
                }
            ),
            "26c6b44fa09cf1d964dfb7a78de7ca95e65628b04332176243de9f4213649721",
        )

    def test_batch_target_inventory_supports_exact_identifiers_and_generations(self):
        cases = (
            (
                f"/api/devices?guid={self.first_device.pk}",
                str(self.first_device.pk),
            ),
            (
                f"/api/users?guid={self.first_user.pk}",
                str(self.first_user.pk),
            ),
            (
                f"/api/device-groups?guid={self.first_group.guid}",
                str(self.first_group.guid),
            ),
        )
        for path, expected_guid in cases:
            with self.subTest(path=path):
                response = self.client.get(
                    path,
                    HTTP_AUTHORIZATION=f"Bearer {self.bearer}",
                )
                self.assertEqual(response.status_code, 200, response.content)
                self.assertEqual(response.json()["total"], 1)
                self.assertEqual(response.json()["data"][0]["guid"], expected_guid)
                self.assertEqual(response.json()["data"][0]["mutation_generation"], 0)

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

    def _json_request(
        self,
        method,
        path,
        payload,
        *,
        operation_id=None,
        expected_generation=None,
    ):
        operation_id = operation_id or str(uuid.uuid4())
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {self.bearer}",
            "HTTP_IDEMPOTENCY_KEY": operation_id,
        }
        if expected_generation is not None:
            headers["HTTP_IF_MATCH"] = f'"{expected_generation}"'
        return getattr(self.client, method)(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )

    def _post(self, path, payload, *, operation_id=None, expected_generation=None):
        return self._json_request(
            "post",
            path,
            payload,
            operation_id=operation_id,
            expected_generation=expected_generation,
        )

    def _delete(self, path, payload, *, operation_id=None, expected_generation=None):
        return self._json_request(
            "delete",
            path,
            payload,
            operation_id=operation_id,
            expected_generation=expected_generation,
        )

    def assert_zero_application_conflict(self, response):
        self.assertEqual(response.status_code, 409, response.content)
        body = response.json()
        self.assertIn("message", body)
        self.assertNotIn("error", body)
        self.assertRegex(body["code"], r"^[a-z][a-z0-9_]{0,63}$")
        self.assertFalse(body["retryable"])
        self.assertEqual(body["applied"], dict.fromkeys(body["requested"], 0))
        self.assertEqual(body["management_operation_receipt_version"], 1)
        self.assertRegex(body["request_digest"], r"^[0-9a-f]{64}$")

    def assert_success_receipt(self, response, operation, operation_id, requested):
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertEqual(body["result"], "OK")
        self.assertEqual(body["management_operation_receipt_version"], 1)
        self.assertEqual(body["operation"], operation)
        self.assertEqual(body["operation_id"], operation_id)
        self.assertIsInstance(body["operation_generation"], int)
        self.assertGreater(body["operation_generation"], 0)
        self.assertRegex(body["request_digest"], r"^[0-9a-f]{64}$")
        self.assertRegex(body["result_digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(body["requested"], requested)
        self.assertEqual(body["applied"], requested)
        return body

    def test_strategy_assignment_rejects_mixed_targets_without_partial_mutation(self):
        missing_group = str(uuid.uuid4())
        response = self._post(
            "/api/strategies/assign",
            {
                "strategy": str(self.strategy.guid),
                "peers": [str(self.first_device.pk), "2147483647"],
                "users": [str(self.first_user.pk), "2147483647"],
                "groups": [str(self.first_group.guid), missing_group],
                "expected_generations": {
                    "devices": {
                        str(self.first_device.pk): 0,
                        "2147483647": 0,
                    },
                    "users": {
                        str(self.first_user.pk): 0,
                        "2147483647": 0,
                    },
                    "groups": {
                        str(self.first_group.guid): 0,
                        missing_group: 0,
                    },
                },
            },
        )

        self.assert_zero_application_conflict(response)
        self.first_device.refresh_from_db()
        self.first_user.refresh_from_db()
        self.first_group.refresh_from_db()
        self.assertIsNone(self.first_device.strategy_id)
        self.assertIsNone(self.first_user.strategy_id)
        self.assertIsNone(self.first_group.strategy_id)

    def test_group_add_and_remove_reject_mixed_membership_without_partial_mutation(self):
        missing_rid = "missing001"
        added = self._post(
            f"/api/device-groups/{self.first_group.guid}",
            [self.first_device.rid, missing_rid],
            expected_generation=0,
        )
        self.assert_zero_application_conflict(added)
        self.first_device.refresh_from_db()
        self.assertIsNone(self.first_device.device_group_id)

        self.first_device.device_group = self.first_group
        self.first_device.save(update_fields=("device_group",))
        removed = self._delete(
            f"/api/device-groups/{self.first_group.guid}/devices",
            [self.first_device.rid, missing_rid],
            expected_generation=0,
        )
        self.assert_zero_application_conflict(removed)
        self.first_device.refresh_from_db()
        self.assertEqual(self.first_device.device_group_id, self.first_group.pk)

    def test_group_remove_rejects_a_device_that_is_not_in_the_group(self):
        self.first_device.device_group = self.first_group
        self.first_device.save(update_fields=("device_group",))

        response = self._delete(
            f"/api/device-groups/{self.first_group.guid}/devices",
            [self.first_device.rid, self.second_device.rid],
            expected_generation=0,
        )

        self.assert_zero_application_conflict(response)
        self.first_device.refresh_from_db()
        self.assertEqual(self.first_device.device_group_id, self.first_group.pk)

    def test_force_logout_rejects_mixed_users_without_revoking_an_existing_user(self):
        _token, first_token = _issue_access_token(self.first_user, self.first_device)
        original_generation = self.first_user.credential_generation

        response = self._post(
            "/api/users/force-logout",
            {"user_guids": [str(self.first_user.pk), "2147483647"]},
        )

        self.assert_zero_application_conflict(response)
        self.first_user.refresh_from_db()
        self.assertEqual(self.first_user.credential_generation, original_generation)
        self.assertTrue(RemoteToken.objects.filter(device=self.first_device).exists())
        current = self.client.post(
            "/api/currentUser",
            data=json.dumps({}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {first_token}",
        )
        self.assertNotEqual(first_token, self.bearer)
        self.assertEqual(current.status_code, 200, current.content)

    def test_force_logout_rejects_the_receipt_actor_before_revoking_its_replay_authority(self):
        original_generation = self.admin.credential_generation

        response = self._post(
            "/api/users/force-logout",
            {"user_guids": [str(self.admin.pk)]},
        )

        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(response.json()["message"], "Cannot force logout current user")
        self.assertEqual(response.json()["response_schema_version"], 1)
        self.assertFalse(response.json()["retryable"])
        self.assertNotIn("error", response.json())
        self.admin.refresh_from_db()
        self.assertEqual(self.admin.credential_generation, original_generation)
        self.assertTrue(RemoteToken.objects.filter(device=self.admin_device).exists())

    def test_duplicate_targets_are_rejected_before_any_mutation(self):
        duplicate_device = self._post(
            f"/api/device-groups/{self.first_group.guid}",
            [self.first_device.rid, self.first_device.rid],
        )
        self.assertEqual(duplicate_device.status_code, 400, duplicate_device.content)
        self.first_device.refresh_from_db()
        self.assertIsNone(self.first_device.device_group_id)

        duplicate_user = self._post(
            "/api/users/force-logout",
            {"user_guids": [str(self.first_user.pk), str(self.first_user.pk)]},
        )
        self.assertEqual(duplicate_user.status_code, 400, duplicate_user.content)
        self.first_user.refresh_from_db()
        self.assertEqual(self.first_user.credential_generation, 0)

    def test_success_receipt_is_replayed_without_advancing_target_generations_twice(self):
        operation_id = str(uuid.uuid4())
        payload = {
            "strategy": str(self.strategy.guid),
            "peers": [str(self.first_device.pk)],
            "users": [str(self.first_user.pk)],
            "groups": [str(self.first_group.guid)],
            "expected_generations": {
                "devices": {str(self.first_device.pk): 0},
                "users": {str(self.first_user.pk): 0},
                "groups": {str(self.first_group.guid): 0},
            },
        }

        accepted = self._post("/api/strategies/assign", payload, operation_id=operation_id)
        first_body = self.assert_success_receipt(
            accepted,
            "strategy_assign",
            operation_id,
            {"devices": 1, "users": 1, "groups": 1},
        )
        self.first_device.refresh_from_db()
        self.first_user.refresh_from_db()
        self.first_group.refresh_from_db()
        first_generation = self.first_device.policy_generation
        first_mutation_generations = (
            self.first_device.mutation_generation,
            self.first_user.mutation_generation,
            self.first_group.mutation_generation,
        )
        self.assertEqual(first_mutation_generations, (1, 1, 1))

        replayed = self._post("/api/strategies/assign", payload, operation_id=operation_id)

        self.assertEqual(replayed.status_code, 200, replayed.content)
        self.assertEqual(replayed.json(), first_body)
        self.first_device.refresh_from_db()
        self.first_user.refresh_from_db()
        self.first_group.refresh_from_db()
        self.assertEqual(self.first_device.policy_generation, first_generation)
        self.assertEqual(
            (
                self.first_device.mutation_generation,
                self.first_user.mutation_generation,
                self.first_group.mutation_generation,
            ),
            first_mutation_generations,
        )

    def test_strategy_assignment_rejects_non_exact_generation_snapshots_before_mutation(self):
        device_id = str(self.first_device.pk)
        exact = {
            "devices": {device_id: 0},
            "users": {},
            "groups": {},
        }
        invalid_snapshots = (
            {"devices": {device_id: 0}, "users": {}},
            {**exact, "roles": {}},
            {"devices": {}, "users": {}, "groups": {}},
            {
                "devices": {device_id: 0, str(self.second_device.pk): 0},
                "users": {},
                "groups": {},
            },
            {"devices": {device_id: True}, "users": {}, "groups": {}},
            {"devices": {device_id: -1}, "users": {}, "groups": {}},
            {"devices": {device_id: 1 << 63}, "users": {}, "groups": {}},
        )

        for snapshot in invalid_snapshots:
            with self.subTest(snapshot=snapshot):
                response = self._post(
                    "/api/strategies/assign",
                    {
                        "strategy": str(self.strategy.guid),
                        "peers": [device_id],
                        "expected_generations": snapshot,
                    },
                )
                self.assertEqual(response.status_code, 400, response.content)

        self.first_device.refresh_from_db()
        self.assertIsNone(self.first_device.strategy_id)
        self.assertEqual(self.first_device.mutation_generation, 0)
        self.assertFalse(ManagementBatchOperation.objects.exists())

    def test_strategy_assignment_stale_snapshot_is_durable_and_zero_mutation(self):
        RemoteDevice._base_manager.filter(pk=self.first_device.pk).update(mutation_generation=1)
        payload = {
            "strategy": str(self.strategy.guid),
            "peers": [str(self.first_device.pk)],
            "users": [str(self.first_user.pk)],
            "groups": [str(self.first_group.guid)],
            "expected_generations": {
                "devices": {str(self.first_device.pk): 0},
                "users": {str(self.first_user.pk): 0},
                "groups": {str(self.first_group.guid): 0},
            },
        }
        operation_id = str(uuid.uuid4())

        response = self._post(
            "/api/strategies/assign",
            payload,
            operation_id=operation_id,
        )

        self.assert_zero_application_conflict(response)
        self.assertEqual(
            response.json()["stale"]["devices"][str(self.first_device.pk)],
            1,
        )
        self.first_device.refresh_from_db()
        self.first_user.refresh_from_db()
        self.first_group.refresh_from_db()
        self.assertIsNone(self.first_device.strategy_id)
        self.assertIsNone(self.first_user.strategy_id)
        self.assertIsNone(self.first_group.strategy_id)
        self.assertEqual(
            (
                self.first_device.mutation_generation,
                self.first_user.mutation_generation,
                self.first_group.mutation_generation,
            ),
            (1, 0, 0),
        )
        receipt = ManagementBatchOperation.objects.get(operation_id=operation_id)
        self.assertEqual(receipt.status_code, 409)
        self.assertEqual(receipt.response, response.json())

    def test_missing_or_invalid_operation_identifier_is_rejected(self):
        missing = self.client.post(
            "/api/strategies/assign",
            data=json.dumps(
                {
                    "strategy": None,
                    "peers": [str(self.first_device.pk)],
                    "expected_generations": {
                        "devices": {str(self.first_device.pk): 0},
                        "users": {},
                        "groups": {},
                    },
                }
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.bearer}",
        )
        invalid = self._post(
            "/api/strategies/assign",
            {
                "strategy": None,
                "peers": [str(self.first_device.pk)],
                "expected_generations": {
                    "devices": {str(self.first_device.pk): 0},
                    "users": {},
                    "groups": {},
                },
            },
            operation_id="not-a-uuid",
        )

        self.assertEqual(missing.status_code, 400, missing.content)
        self.assertEqual(invalid.status_code, 400, invalid.content)
        self.first_device.refresh_from_db()
        self.assertIsNone(self.first_device.strategy_id)

    def test_rejected_operation_is_durable_and_replays_after_the_missing_target_appears(self):
        operation_id = str(uuid.uuid4())
        payload = [self.first_device.rid, "missing001"]
        rejected = self._post(
            f"/api/device-groups/{self.first_group.guid}",
            payload,
            operation_id=operation_id,
            expected_generation=0,
        )
        first_body = rejected.json()
        self.assert_zero_application_conflict(rejected)
        receipt = ManagementBatchOperation.objects.get(operation_id=operation_id)
        self.assertEqual(receipt.status_code, 409)
        self.assertEqual(receipt.response, first_body)

        late_device = self._device("missing001", "batch-late-device", self.second_user)
        replayed = self._post(
            f"/api/device-groups/{self.first_group.guid}",
            payload,
            operation_id=operation_id,
            expected_generation=0,
        )

        self.assertEqual(replayed.status_code, 409, replayed.content)
        self.assertEqual(replayed.json(), first_body)
        self.first_device.refresh_from_db()
        late_device.refresh_from_db()
        self.assertIsNone(self.first_device.device_group_id)
        self.assertIsNone(late_device.device_group_id)

    def test_operation_identifier_cannot_be_rebound_to_another_request(self):
        operation_id = str(uuid.uuid4())
        accepted = self._post(
            f"/api/device-groups/{self.first_group.guid}",
            [self.first_device.rid],
            operation_id=operation_id,
            expected_generation=0,
        )
        self.assert_success_receipt(
            accepted,
            "device_group_add_devices",
            operation_id,
            {"devices": 1},
        )

        conflict = self._post(
            f"/api/device-groups/{self.first_group.guid}",
            [self.second_device.rid],
            operation_id=operation_id,
            expected_generation=0,
        )

        self.assertEqual(conflict.status_code, 409, conflict.content)
        self.assertEqual(conflict.json()["message"], "Operation identifier conflict")
        self.assertEqual(conflict.json()["response_schema_version"], 1)
        self.assertFalse(conflict.json()["retryable"])
        self.assertNotIn("error", conflict.json())
        self.second_device.refresh_from_db()
        self.assertIsNone(self.second_device.device_group_id)
        self.assertEqual(ManagementBatchOperation.objects.filter(operation_id=operation_id).count(), 1)

    def test_operation_identifier_cannot_be_replayed_by_another_actor(self):
        operation_id = str(uuid.uuid4())
        payload = [self.first_device.rid]
        accepted = self._post(
            f"/api/device-groups/{self.first_group.guid}",
            payload,
            operation_id=operation_id,
            expected_generation=0,
        )
        self.assertEqual(accepted.status_code, 200, accepted.content)
        other_admin = UserProfile.objects.create_superuser(
            "batch-other-admin",
            "batch-other-admin-pass",  # noqa: S106 - isolated test credential
        )
        other_device = self._device("741000004", "batch-other-admin-device", other_admin)
        _token, other_bearer = _issue_access_token(other_admin, other_device)

        conflict = self.client.post(
            f"/api/device-groups/{self.first_group.guid}",
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {other_bearer}",
            HTTP_IDEMPOTENCY_KEY=operation_id,
            HTTP_IF_MATCH='"0"',
        )

        self.assertEqual(conflict.status_code, 409, conflict.content)
        self.assertEqual(conflict.json()["message"], "Operation identifier conflict")
        self.assertEqual(conflict.json()["response_schema_version"], 1)
        self.assertFalse(conflict.json()["retryable"])
        self.assertNotIn("error", conflict.json())
        self.assertEqual(ManagementBatchOperation.objects.filter(operation_id=operation_id).count(), 1)

    def test_group_and_force_logout_success_receipts_report_exact_application(self):
        add_operation_id = str(uuid.uuid4())
        added = self._post(
            f"/api/device-groups/{self.first_group.guid}",
            [self.first_device.rid, self.second_device.rid],
            operation_id=add_operation_id,
            expected_generation=0,
        )
        self.assert_success_receipt(
            added,
            "device_group_add_devices",
            add_operation_id,
            {"devices": 2},
        )
        self.first_device.refresh_from_db()
        self.second_device.refresh_from_db()
        self.first_group.refresh_from_db()
        self.assertEqual(self.first_device.device_group_id, self.first_group.pk)
        self.assertEqual(self.second_device.device_group_id, self.first_group.pk)
        self.assertEqual(self.first_device.mutation_generation, 1)
        self.assertEqual(self.second_device.mutation_generation, 1)
        self.assertEqual(self.first_group.mutation_generation, 1)
        self.assertEqual(added["ETag"], '"1"')

        _token, _raw = _issue_access_token(self.first_user, self.first_device)
        _token, _raw = _issue_access_token(self.second_user, self.second_device)
        logout_operation_id = str(uuid.uuid4())
        logged_out = self._post(
            "/api/users/force-logout",
            {"user_guids": [str(self.first_user.pk), str(self.second_user.pk)]},
            operation_id=logout_operation_id,
        )
        body = self.assert_success_receipt(
            logged_out,
            "users_force_logout",
            logout_operation_id,
            {"users": 2},
        )
        self.assertEqual(body["revoked_users"], 2)
        self.assertEqual(body["deleted"], 2)
        self.assertFalse(RemoteToken.objects.filter(device__in=(self.first_device, self.second_device)).exists())

    def test_group_membership_replay_and_stale_generation_are_zero_additional_mutation(self):
        add_operation_id = str(uuid.uuid4())
        payload = [self.first_device.rid]
        accepted = self._post(
            f"/api/device-groups/{self.first_group.guid}",
            payload,
            operation_id=add_operation_id,
            expected_generation=0,
        )
        first_body = self.assert_success_receipt(
            accepted,
            "device_group_add_devices",
            add_operation_id,
            {"devices": 1},
        )

        replayed = self._post(
            f"/api/device-groups/{self.first_group.guid}",
            payload,
            operation_id=add_operation_id,
            expected_generation=0,
        )
        stale = self._delete(
            f"/api/device-groups/{self.first_group.guid}/devices",
            payload,
            expected_generation=0,
        )

        self.assertEqual(replayed.status_code, 200, replayed.content)
        self.assertEqual(replayed.json(), first_body)
        self.assert_zero_application_conflict(stale)
        self.first_device.refresh_from_db()
        self.first_group.refresh_from_db()
        self.assertEqual(self.first_device.device_group_id, self.first_group.pk)
        self.assertEqual(self.first_device.mutation_generation, 1)
        self.assertEqual(self.first_group.mutation_generation, 1)

        removed = self._delete(
            f"/api/device-groups/{self.first_group.guid}/devices",
            payload,
            expected_generation=1,
        )
        self.assertEqual(removed.status_code, 200, removed.content)
        self.first_device.refresh_from_db()
        self.first_group.refresh_from_db()
        self.assertIsNone(self.first_device.device_group_id)
        self.assertEqual(self.first_device.mutation_generation, 2)
        self.assertEqual(self.first_group.mutation_generation, 2)

    def test_device_group_assignment_advances_old_and_new_group_generations(self):
        self.first_device.device_group = self.first_group
        self.first_device.save(update_fields=("device_group",))

        response = self._post(
            f"/api/devices/{self.first_device.pk}/assign",
            {"type": "device_group_name", "value": self.second_group.name},
            expected_generation=0,
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.first_device.refresh_from_db()
        self.first_group.refresh_from_db()
        self.second_group.refresh_from_db()
        self.assertEqual(self.first_device.device_group_id, self.second_group.pk)
        self.assertEqual(self.first_device.mutation_generation, 1)
        self.assertEqual(self.first_group.mutation_generation, 1)
        self.assertEqual(self.second_group.mutation_generation, 1)

    def test_bulk_move_and_device_delete_advance_group_membership_generations_once(self):
        self.first_device.device_group = self.first_group
        self.first_device.save(update_fields=("device_group",))
        move_id = str(uuid.uuid4())
        payload = [self.first_device.rid]
        path = f"/api/device-groups/{self.second_group.guid}"
        moved = self._post(path, payload, operation_id=move_id, expected_generation=0)
        replayed = self._post(path, payload, operation_id=move_id, expected_generation=0)
        self.assertEqual(moved.status_code, 200, moved.content)
        self.assertEqual(replayed.json(), moved.json())
        self.first_group.refresh_from_db()
        self.second_group.refresh_from_db()
        self.first_device.refresh_from_db()
        self.assertEqual(self.first_group.mutation_generation, 1)
        self.assertEqual(self.second_group.mutation_generation, 1)
        self.assertEqual(self.first_device.device_group_id, self.second_group.pk)

        delete_id = str(uuid.uuid4())
        path = f"/api/devices/{self.first_device.pk}"
        deleted = self._delete(path, {}, operation_id=delete_id, expected_generation=1)
        replayed_delete = self._delete(path, {}, operation_id=delete_id, expected_generation=1)
        self.assertEqual(deleted.status_code, 200, deleted.content)
        self.assertEqual(replayed_delete.json(), deleted.json())
        self.second_group.refresh_from_db()
        self.assertEqual(self.second_group.mutation_generation, 2)
        self.assertFalse(RemoteDevice.objects.filter(pk=self.first_device.pk).exists())

    def test_user_group_and_strategy_deletes_advance_detached_resource_generations(self):
        group_device = self.first_device
        group_device.device_group = self.first_group
        group_device.save(update_fields=("device_group",))
        deleted_group = self._delete(
            f"/api/device-groups/{self.first_group.guid}",
            {},
            expected_generation=0,
        )
        self.assertEqual(deleted_group.status_code, 200, deleted_group.content)
        group_device.refresh_from_db()
        self.assertIsNone(group_device.device_group_id)
        self.assertEqual(group_device.mutation_generation, 1)

        strategy_user = self.first_user
        strategy_group = self.second_group
        strategy_device = self.second_device
        strategy_user.strategy = self.strategy
        strategy_user.save(update_fields=("strategy",))
        strategy_group.strategy = self.strategy
        strategy_group.save(update_fields=("strategy",))
        strategy_device.strategy = self.strategy
        strategy_device.save(update_fields=("strategy",))
        deleted_strategy = self._delete(
            f"/api/strategies/{self.strategy.guid}",
            {},
            expected_generation=0,
        )
        self.assertEqual(deleted_strategy.status_code, 200, deleted_strategy.content)
        strategy_user.refresh_from_db()
        strategy_group.refresh_from_db()
        strategy_device.refresh_from_db()
        self.assertIsNone(strategy_user.strategy_id)
        self.assertIsNone(strategy_group.strategy_id)
        self.assertIsNone(strategy_device.strategy_id)
        self.assertEqual(strategy_user.mutation_generation, 1)
        self.assertEqual(strategy_group.mutation_generation, 1)
        self.assertEqual(strategy_device.mutation_generation, 1)

        user_device_generation = group_device.mutation_generation
        deleted_user = self._delete(
            f"/api/users/{self.first_user.pk}",
            {},
            expected_generation=strategy_user.mutation_generation,
        )
        self.assertEqual(deleted_user.status_code, 200, deleted_user.content)
        group_device.refresh_from_db()
        self.assertIsNone(group_device.owner_id)
        self.assertFalse(group_device.is_active)
        self.assertEqual(
            group_device.mutation_generation,
            user_device_generation + 1,
        )

    def test_unhandled_database_failure_rolls_back_mutation_and_receipt(self):
        operation_id = uuid.uuid4()
        original_note = self.first_user.note

        def fail_after_write():
            UserProfile.objects.filter(pk=self.first_user.pk).update(note="must-roll-back")
            raise RuntimeError("injected database boundary failure")

        with self.assertRaisesRegex(RuntimeError, "injected database boundary failure"):
            execute_management_operation(
                actor=self.admin,
                operation_id=operation_id,
                operation="failure_injection",
                request_document={"operation": "failure_injection", "users": [str(self.first_user.pk)]},
                requested={"users": 1},
                mutation=fail_after_write,
            )

        self.first_user.refresh_from_db()
        self.assertEqual(self.first_user.note, original_note)
        self.assertFalse(ManagementBatchOperation.objects.filter(operation_id=operation_id).exists())

    def test_receipt_recovery_returns_sensitive_result_only_to_original_actor(self):
        operation_id = uuid.uuid4()
        execute_management_operation(
            actor=self.admin,
            operation_id=operation_id,
            operation="recovery_test",
            request_document={"operation": "recovery_test"},
            requested={"results": 1},
            mutation=lambda: management_operations.ManagementMutation(
                status_code=200,
                body={"result": "OK", "token": "one-time-recovered-value"},
                applied={"results": 1},
                result_state={"created": True},
            ),
            sensitive_response=True,
        )
        path = f"/api/management-operations/{operation_id}"

        recovered = self.client.get(
            path,
            HTTP_AUTHORIZATION=f"Bearer {self.bearer}",
        )

        self.assertEqual(recovered.status_code, 200, recovered.content)
        self.assertEqual(recovered.json()["original_status_code"], 200)
        self.assertEqual(
            recovered.json()["receipt"]["token"],
            "one-time-recovered-value",
        )
        self.assertEqual(recovered["Cache-Control"], "no-store, private")
        self.assertEqual(recovered["Referrer-Policy"], "no-referrer")

        self.client.force_login(self.admin)
        session_recovered = self.client.get(path)
        self.assertEqual(session_recovered.status_code, 200, session_recovered.content)
        self.client.force_login(self.first_user)
        isolated = self.client.get(path)
        self.assertEqual(isolated.status_code, 404, isolated.content)
        self.assertNotIn(b"one-time-recovered-value", isolated.content)

    def test_data_encryption_rotation_includes_sensitive_operation_receipts(self):
        operation_id = uuid.uuid4()
        execute_management_operation(
            actor=self.admin,
            operation_id=operation_id,
            operation="receipt_rotation_test",
            request_document={"operation": "receipt_rotation_test"},
            requested={"results": 1},
            mutation=lambda: management_operations.ManagementMutation(
                status_code=200,
                body={"result": "OK", "token": "rotation-sensitive-value"},
                applied={"results": 1},
                result_state={"created": True},
            ),
            sensitive_response=True,
        )
        old_key_id = settings.DATA_ENCRYPTION_PRIMARY_KEY_ID
        old_key = settings.DATA_ENCRYPTION_KEYS[old_key_id]
        new_key_id = "operation-receipt-rotation"
        new_key = b"r" * 32
        db_operation_id = ManagementBatchOperation._meta.get_field("operation_id").get_db_prep_value(
            operation_id,
            connections["default"],
        )
        with connections["default"].cursor() as cursor:
            cursor.execute(
                "SELECT secret_response FROM api_managementbatchoperation WHERE operation_id = %s",
                [db_operation_id],
            )
            old_envelope = cursor.fetchone()[0]
        self.assertTrue(old_envelope.startswith(f"{FIELD_PREFIX}{old_key_id}:"))
        self.assertNotIn("rotation-sensitive-value", old_envelope)

        with override_settings(
            DATA_ENCRYPTION_KEY_BYTES=new_key,
            DATA_ENCRYPTION_KEYS={old_key_id: old_key, new_key_id: new_key},
            DATA_ENCRYPTION_PRIMARY_KEY_ID=new_key_id,
            DATA_ENCRYPTION_V1_KEY_ID=old_key_id,
        ):
            call_command("rotate_data_encryption", stdout=StringIO())
            with connections["default"].cursor() as cursor:
                cursor.execute(
                    "SELECT secret_response FROM api_managementbatchoperation WHERE operation_id = %s",
                    [db_operation_id],
                )
                new_envelope = cursor.fetchone()[0]
            self.assertTrue(new_envelope.startswith(f"{FIELD_PREFIX}{new_key_id}:"))
            receipt = ManagementBatchOperation.objects.get(operation_id=operation_id)
            self.assertEqual(
                json.loads(receipt.secret_response)["token"],
                "rotation-sensitive-value",
            )

    @override_settings(MANAGEMENT_OPERATION_RETENTION_DAYS=30)
    def test_cleanup_purges_expired_receipts_in_bounded_batches(self):
        for device in (self.first_device, self.second_device):
            self.first_group.refresh_from_db()
            response = self._post(
                f"/api/device-groups/{self.first_group.guid}",
                [device.rid],
                operation_id=str(uuid.uuid4()),
                expected_generation=self.first_group.mutation_generation,
            )
            self.assertEqual(response.status_code, 200, response.content)
        cutoff_time = timezone.now() - datetime.timedelta(days=31)
        ManagementBatchOperation.objects.update(created_at=cutoff_time)
        output = StringIO()

        with (
            patch(
                "api.management.commands.purge_expired_state.purge_recording_retention",
                return_value={},
            ),
            patch(
                "api.management.commands.purge_expired_state.purge_audit_retention",
                return_value={},
            ),
        ):
            call_command("purge_expired_state", batch_size=1, stdout=output)

        result = json.loads(output.getvalue())
        self.assertEqual(result["expired_management_batch_operations"], 2)
        self.assertEqual(result["management_batch_operations_purged"], 1)
        self.assertEqual(result["management_batch_operations_remaining"], 1)
        self.assertEqual(ManagementBatchOperation.objects.count(), 1)


@override_settings(STORAGES=TEST_STORAGES)
class ManagementBatchOperationConcurrencyTests(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        self.admin = UserProfile.objects.create_superuser(
            "batch-concurrent-admin",
            "batch-concurrent-admin-pass",  # noqa: S106 - isolated test credential
        )
        self.user = UserProfile.objects.create_user(
            "batch-concurrent-user",
            "batch-concurrent-user-pass",  # noqa: S106 - isolated test credential
        )
        self.admin_device = ManagementBatchOperationTests._device(
            "742000001",
            "batch-concurrent-admin-device",
            self.admin,
        )
        self.device = ManagementBatchOperationTests._device(
            "742000002",
            "batch-concurrent-device",
            self.user,
        )
        self.group = DeviceGroup.objects.create(name="batch-concurrent-group")
        self.first_strategy = StrategyProfile.objects.create(name="batch-concurrent-first", config_options={})
        self.second_strategy = StrategyProfile.objects.create(name="batch-concurrent-second", config_options={})
        _token, self.bearer = _issue_access_token(self.admin, self.admin_device)

    def _request(self, path, payload, operation_id, expected_generation=None):
        close_old_connections()
        try:
            headers = {
                "HTTP_AUTHORIZATION": f"Bearer {self.bearer}",
                "HTTP_IDEMPOTENCY_KEY": operation_id,
            }
            if expected_generation is not None:
                headers["HTTP_IF_MATCH"] = f'"{expected_generation}"'
            return Client(raise_request_exception=False).post(
                path,
                data=json.dumps(payload),
                content_type="application/json",
                **headers,
            )
        finally:
            connections.close_all()

    @skipUnlessDBFeature("has_select_for_update")
    def test_concurrent_identical_operation_mutates_once_and_returns_one_receipt(self):
        operation_id = str(uuid.uuid4())
        barrier = threading.Barrier(3)

        def add_group():
            barrier.wait(timeout=20)
            return self._request(
                f"/api/device-groups/{self.group.guid}",
                [self.device.rid],
                operation_id,
                0,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(add_group)
            second = executor.submit(add_group)
            barrier.wait(timeout=20)
            responses = (first.result(timeout=60), second.result(timeout=60))

        self.assertTrue(all(response.status_code == 200 for response in responses))
        self.assertEqual(responses[0].json(), responses[1].json())
        self.assertEqual(ManagementBatchOperation.objects.filter(operation_id=operation_id).count(), 1)
        self.device.refresh_from_db()
        self.assertEqual(self.device.device_group_id, self.group.pk)
        self.assertEqual(self.device.policy_generation, 1)

    @skipUnlessDBFeature("has_select_for_update")
    def test_group_delete_committing_before_target_lock_yields_durable_zero_application(self):
        group_locked = threading.Event()
        release_delete = threading.Event()

        def delete_group():
            close_old_connections()
            try:
                with transaction.atomic():
                    locked = DeviceGroup.objects.select_for_update().get(pk=self.group.pk)
                    group_locked.set()
                    if not release_delete.wait(timeout=20):
                        raise RuntimeError("delete release timed out")
                    locked.delete()
            finally:
                connections.close_all()

        operation_id = str(uuid.uuid4())
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            deleting = executor.submit(delete_group)
            self.assertTrue(group_locked.wait(timeout=20))
            assigning = executor.submit(
                self._request,
                f"/api/device-groups/{self.group.guid}",
                [self.device.rid],
                operation_id,
                0,
            )
            release_delete.set()
            deleting.result(timeout=60)
            response = assigning.result(timeout=60)

        self.assertEqual(response.status_code, 404, response.content)
        self.assertEqual(response.json()["applied"], {"devices": 0})
        receipt = ManagementBatchOperation.objects.get(operation_id=operation_id)
        self.assertEqual(receipt.status_code, 404)
        self.device.refresh_from_db()
        self.assertIsNone(self.device.device_group_id)

    @skipUnlessDBFeature("has_select_for_update")
    def test_competing_strategy_operations_serialize_complete_target_generations(self):
        barrier = threading.Barrier(3)

        def assign(strategy):
            barrier.wait(timeout=20)
            return self._request(
                "/api/strategies/assign",
                {
                    "strategy": str(strategy.guid),
                    "peers": [str(self.device.pk)],
                    "expected_generations": {
                        "devices": {str(self.device.pk): 0},
                        "users": {},
                        "groups": {},
                    },
                },
                str(uuid.uuid4()),
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(assign, self.first_strategy)
            second = executor.submit(assign, self.second_strategy)
            barrier.wait(timeout=20)
            responses = (first.result(timeout=60), second.result(timeout=60))

        self.assertEqual(sorted(response.status_code for response in responses), [200, 409])
        self.assertEqual(
            sorted(response.json()["applied"]["devices"] for response in responses),
            [0, 1],
        )
        self.device.refresh_from_db()
        self.assertIn(self.device.strategy_id, (self.first_strategy.pk, self.second_strategy.pk))
        self.assertEqual(self.device.policy_generation, 1)
        self.assertEqual(self.device.mutation_generation, 1)
        self.assertEqual(ManagementBatchOperation.objects.count(), 2)

    @skipUnlessDBFeature("has_select_for_update")
    def test_crossed_group_and_device_strategy_targets_lock_all_affected_devices_in_pk_order(self):
        second_user = UserProfile.objects.create_user(
            "batch-crossed-user",
            "batch-crossed-user-pass",  # noqa: S106 - isolated test credential
        )
        second_device = ManagementBatchOperationTests._device(
            "742000003",
            "batch-crossed-device",
            second_user,
        )
        second_group = DeviceGroup.objects.create(name="batch-crossed-group")
        RemoteDevice.objects.filter(pk=self.device.pk).update(device_group=self.group)
        RemoteDevice.objects.filter(pk=second_device.pk).update(device_group=second_group)
        self.device.refresh_from_db()
        second_device.refresh_from_db()
        initial_generations = (self.device.policy_generation, second_device.policy_generation)
        mutation_lock_entry = threading.Barrier(2)
        acquire_mutation_lock = management_operations._acquire_batch_mutation_lock

        def synchronized_mutation_lock():
            mutation_lock_entry.wait(timeout=20)
            acquire_mutation_lock()

        def assign(strategy, group, device):
            return self._request(
                "/api/strategies/assign",
                {
                    "strategy": str(strategy.guid),
                    "peers": [str(device.pk)],
                    "groups": [str(group.guid)],
                    "expected_generations": {
                        "devices": {str(device.pk): 0},
                        "users": {},
                        "groups": {str(group.guid): 0},
                    },
                },
                str(uuid.uuid4()),
            )

        with patch(
            "api.management_operations._acquire_batch_mutation_lock",
            side_effect=synchronized_mutation_lock,
        ):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(assign, self.first_strategy, self.group, second_device)
                second = executor.submit(assign, self.second_strategy, second_group, self.device)
                responses = (first.result(timeout=60), second.result(timeout=60))

        self.assertTrue(all(response.status_code == 200 for response in responses))
        self.assertTrue(
            all(response.json()["applied"] == {"devices": 1, "users": 0, "groups": 1} for response in responses)
        )
        self.device.refresh_from_db()
        second_device.refresh_from_db()
        generation_deltas = sorted(
            (
                self.device.policy_generation - initial_generations[0],
                second_device.policy_generation - initial_generations[1],
            )
        )
        self.assertEqual(generation_deltas, [1, 2])
