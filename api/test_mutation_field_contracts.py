import base64
import datetime
import hashlib
import json
import uuid
from unittest.mock import patch

from django.test import Client, TestCase, override_settings
from django.utils import timezone

from api.models import DeviceGroup, RemoteDevice, StrategyProfile, UserProfile
from api.views_api import _issue_access_token

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


def _device_uuid(label):
    return base64.b64encode(label.encode()).decode()


@override_settings(STORAGES=TEST_STORAGES)
class MutationFieldContractTests(TestCase):
    def setUp(self):
        self.admin = UserProfile.objects.create_superuser(
            "field-contract-admin",
            "field-contract-admin-pass",  # noqa: S106 - isolated test credential
        )
        self.admin_device = self._device(
            "761000001",
            "field-contract-admin-device",
            self.admin,
        )
        _token, self.bearer = _issue_access_token(self.admin, self.admin_device)
        self.target = UserProfile.objects.create_user(
            "field-contract-target",
            "field-contract-target-pass",  # noqa: S106 - isolated test credential
        )
        self.target_device = self._device(
            "761000002",
            "field-contract-target-device",
            self.target,
        )
        self.group = DeviceGroup.objects.create(name="field-contract-group")
        self.strategy = StrategyProfile.objects.create(
            name="field-contract-strategy",
            config_options={"quality": "balanced"},
            enabled=False,
        )
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

    def request(self, method, path, payload):
        return self.client.generic(
            method,
            path,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.bearer}",
            HTTP_IDEMPOTENCY_KEY=str(uuid.uuid4()),
        )

    def assert_field_error(self, response, *, unknown=None, conflicting=None):
        self.assertEqual(response.status_code, 400, response.content)
        body = response.json()
        self.assertEqual(body["error"], "Invalid request fields")
        self.assertEqual(body["code"], "invalid_request_fields")
        self.assertEqual(body["field_contract_version"], 1)
        if unknown is not None:
            self.assertEqual(body["unknown_fields"], sorted(unknown))
        if conflicting is not None:
            self.assertEqual(body["conflicting_fields"], sorted(conflicting))
        self.assertLessEqual(len(response.content), 512)

    def test_user_create_rejects_known_plus_unknown_and_ambiguous_aliases(self):
        unknown = self.request(
            "POST",
            "/api/users",
            {
                "name": "field-contract-new-user",
                "password": "Field-contract-user-9!pass",
                "is_admin": True,
            },
        )
        self.assert_field_error(unknown, unknown=["is_admin"])
        self.assertFalse(UserProfile.objects.filter(username="field-contract-new-user").exists())

        aliases = self.request(
            "POST",
            "/api/users",
            {
                "name": "field-contract-name",
                "username": "field-contract-username",
                "password": "Field-contract-user-9!pass",
            },
        )
        self.assert_field_error(aliases, conflicting=["name", "username"])
        self.assertFalse(UserProfile.objects.filter(username__startswith="field-contract-name").exists())

    def test_user_control_mutations_reject_unknown_fields_before_state_change(self):
        generation = self.target.credential_generation
        force_logout = self.request(
            "POST",
            "/api/users/force-logout",
            {
                "user_guids": [str(self.target.pk)],
                "credential_generations": [generation],
            },
        )
        self.assert_field_error(force_logout, unknown=["credential_generations"])

        status = self.request(
            "POST",
            f"/api/users/{self.target.pk}/disable",
            {"disabledd": True},
        )
        self.assert_field_error(status, unknown=["disabledd"])
        self.target.refresh_from_db()
        self.assertTrue(self.target.is_active)
        self.assertEqual(self.target.credential_generation, generation)

        deleted = self.request(
            "DELETE",
            f"/api/users/{self.target.pk}",
            {"cascade": True},
        )
        self.assert_field_error(deleted, unknown=["cascade"])
        self.assertTrue(UserProfile.objects.filter(pk=self.target.pk).exists())

    def test_device_control_mutations_reject_top_level_and_nested_unknown_fields(self):
        status = self.request(
            "POST",
            f"/api/devices/{self.target_device.pk}/disable",
            {"disabledd": True},
        )
        self.assert_field_error(status, unknown=["disabledd"])

        assigned = self.request(
            "POST",
            f"/api/devices/{self.target_device.pk}/assign",
            {"type": "note", "value": "kept", "device_guid": str(self.target_device.pk)},
        )
        self.assert_field_error(assigned, unknown=["device_guid"])

        nested = self.request(
            "POST",
            f"/api/devices/{self.target_device.pk}/assign",
            {
                "type": "ab",
                "value": {
                    "address_book_name": "managed",
                    "address_book_naem": "typo",
                },
            },
        )
        self.assert_field_error(nested, unknown=["value.address_book_naem"])

        recovery = self.request(
            "POST",
            f"/api/devices/{self.target_device.pk}/approve-recovery",
            {"pk": base64.b64encode(b"k" * 32).decode(), "expires_in": 3600},
        )
        self.assert_field_error(recovery, unknown=["expires_in"])

        deleted = self.request(
            "DELETE",
            f"/api/devices/{self.target_device.pk}",
            {"retain_tokens": True},
        )
        self.assert_field_error(deleted, unknown=["retain_tokens"])
        self.target_device.refresh_from_db()
        self.assertTrue(self.target_device.is_active)
        self.assertEqual(self.target_device.note, "")
        self.assertEqual(self.target_device.address_book_name, "")

    def test_device_group_create_patch_and_delete_reject_unknown_fields_without_timestamp_change(self):
        created = self.request(
            "POST",
            "/api/device-groups",
            {"name": "field-contract-new-group", "stratgey_name": self.strategy.name},
        )
        self.assert_field_error(created, unknown=["stratgey_name"])
        self.assertFalse(DeviceGroup.objects.filter(name="field-contract-new-group").exists())

        previous_updated_at = self.group.updated_at
        unknown_patch = self.request(
            "PATCH",
            f"/api/device-groups/{self.group.guid}",
            {"stratgey_name": self.strategy.name},
        )
        self.assert_field_error(unknown_patch, unknown=["stratgey_name"])
        known_and_unknown = self.request(
            "PATCH",
            f"/api/device-groups/{self.group.guid}",
            {"note": "must-not-apply", "status": 0},
        )
        self.assert_field_error(known_and_unknown, unknown=["status"])

        deleted = self.request(
            "DELETE",
            f"/api/device-groups/{self.group.guid}",
            {"detach": True},
        )
        self.assert_field_error(deleted, unknown=["detach"])
        self.group.refresh_from_db()
        self.assertEqual(self.group.note, "")
        self.assertEqual(self.group.updated_at, previous_updated_at)

    def test_strategy_create_patch_status_assign_and_delete_reject_unknown_fields(self):
        created = self.request(
            "POST",
            "/api/strategies",
            {"name": "field-contract-new-strategy", "enabledd": True},
        )
        self.assert_field_error(created, unknown=["enabledd"])
        self.assertFalse(StrategyProfile.objects.filter(name="field-contract-new-strategy").exists())

        previous_updated_at = self.strategy.updated_at
        unknown_patch = self.request(
            "PATCH",
            f"/api/strategies/{self.strategy.guid}",
            {"enabledd": True},
        )
        self.assert_field_error(unknown_patch, unknown=["enabledd"])
        known_and_unknown = self.request(
            "PATCH",
            f"/api/strategies/{self.strategy.guid}",
            {"enabled": True, "guid": str(uuid.uuid4())},
        )
        self.assert_field_error(known_and_unknown, unknown=["guid"])

        status = self.request(
            "PUT",
            f"/api/strategies/{self.strategy.guid}/status",
            {"enabled": True, "reason": "manual"},
        )
        self.assert_field_error(status, unknown=["reason"])
        assigned = self.request(
            "POST",
            "/api/strategies/assign",
            {
                "strategy": str(self.strategy.guid),
                "groups": [str(self.group.guid)],
                "dry_run": True,
            },
        )
        self.assert_field_error(assigned, unknown=["dry_run"])
        deleted = self.request(
            "DELETE",
            f"/api/strategies/{self.strategy.guid}",
            {"force": True},
        )
        self.assert_field_error(deleted, unknown=["force"])

        self.strategy.refresh_from_db()
        self.assertFalse(self.strategy.enabled)
        self.assertEqual(self.strategy.updated_at, previous_updated_at)
        self.group.refresh_from_db()
        self.assertIsNone(self.group.strategy_id)

    def test_legal_partial_patches_save_only_explicit_model_fields_and_log_them(self):
        strategy_save = StrategyProfile.save
        strategy_calls = []

        def capture_strategy_save(instance, *args, **kwargs):
            strategy_calls.append(set(kwargs.get("update_fields") or ()))
            return strategy_save(instance, *args, **kwargs)

        with (
            patch.object(StrategyProfile, "save", new=capture_strategy_save),
            patch("api.views_api._log_event") as log_event,
        ):
            strategy_response = self.request(
                "PATCH",
                f"/api/strategies/{self.strategy.guid}",
                {"name": "field-contract-renamed-strategy"},
            )

        self.assertEqual(strategy_response.status_code, 200, strategy_response.content)
        self.assertEqual(strategy_calls, [{"name", "updated_at"}])
        self.assertEqual(log_event.call_args.kwargs["changed_fields"], ["name"])

        group_save = DeviceGroup.save
        group_calls = []

        def capture_group_save(instance, *args, **kwargs):
            group_calls.append(set(kwargs.get("update_fields") or ()))
            return group_save(instance, *args, **kwargs)

        with (
            patch.object(DeviceGroup, "save", new=capture_group_save),
            patch("api.views_api._log_event") as log_event,
        ):
            group_response = self.request(
                "PATCH",
                f"/api/device-groups/{self.group.guid}",
                {"note": "explicit note"},
            )

        self.assertEqual(group_response.status_code, 200, group_response.content)
        self.assertEqual(group_calls, [{"note", "updated_at"}])
        self.assertEqual(log_event.call_args.kwargs["changed_fields"], ["note"])

    def test_strategy_status_keeps_the_documented_boolean_and_object_forms(self):
        scalar = self.client.generic(
            "PUT",
            f"/api/strategies/{self.strategy.guid}/status",
            data="true",
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.bearer}",
        )
        self.assertEqual(scalar.status_code, 200, scalar.content)
        self.assertTrue(scalar.json()["enabled"])

        document = self.request(
            "PUT",
            f"/api/strategies/{self.strategy.guid}/status",
            {"enabled": False},
        )
        self.assertEqual(document.status_code, 200, document.content)
        self.assertFalse(document.json()["enabled"])

    def test_explicit_policy_assignment_fields_keep_generation_hooks(self):
        self.target_device.device_group = self.group
        self.target_device.save(update_fields=("device_group",))
        self.target_device.refresh_from_db()
        initial_generation = self.target_device.policy_generation

        group_response = self.request(
            "PATCH",
            f"/api/device-groups/{self.group.guid}",
            {"strategy_name": self.strategy.name},
        )
        self.assertEqual(group_response.status_code, 200, group_response.content)
        self.target_device.refresh_from_db()
        self.assertEqual(self.target_device.policy_generation, initial_generation + 1)

        direct_strategy = StrategyProfile.objects.create(
            name="field-contract-direct-strategy",
            config_options={"quality": "best"},
        )
        device_save = RemoteDevice.save
        device_calls = []

        def capture_device_save(instance, *args, **kwargs):
            device_calls.append(set(kwargs.get("update_fields") or ()))
            return device_save(instance, *args, **kwargs)

        with patch.object(RemoteDevice, "save", new=capture_device_save):
            device_response = self.request(
                "POST",
                f"/api/devices/{self.target_device.pk}/assign",
                {"type": "strategy_name", "value": direct_strategy.name},
            )

        self.assertEqual(device_response.status_code, 200, device_response.content)
        self.assertEqual(device_calls, [{"strategy", "update_time"}])
        self.target_device.refresh_from_db()
        self.assertEqual(self.target_device.strategy_id, direct_strategy.pk)
        self.assertEqual(self.target_device.policy_generation, initial_generation + 2)

    def test_valid_recovery_payload_still_reaches_domain_validation(self):
        response = self.request(
            "POST",
            f"/api/devices/{self.target_device.pk}/approve-recovery",
            {"pk": base64.b64encode(b"k" * 32).decode()},
        )

        self.assertEqual(response.status_code, 409, response.content)
        self.assertEqual(response.json(), {"error": "Device is not eligible for recovery"})

    def test_field_errors_are_sorted_and_do_not_echo_values(self):
        secret = "must-not-appear-" + hashlib.sha256(b"field-contract-secret").hexdigest()
        response = self.request(
            "POST",
            f"/api/devices/{self.target_device.pk}/assign",
            {"type": "note", "value": "safe", "z_typo": secret, "a_typo": secret},
        )

        self.assert_field_error(response, unknown=["a_typo", "z_typo"])
        self.assertNotIn(secret.encode(), response.content)

    def test_unknown_field_error_list_is_bounded(self):
        payload = {"type": "note", "value": "safe"}
        payload.update({f"unknown_{index:03d}": "ignored" for index in range(100)})

        response = self.request(
            "POST",
            f"/api/devices/{self.target_device.pk}/assign",
            payload,
        )

        self.assertEqual(response.status_code, 400, response.content)
        body = response.json()
        self.assertEqual(body["unknown_field_count"], 100)
        self.assertEqual(len(body["unknown_fields"]), 16)
        self.assertEqual(body["unknown_fields"], sorted(body["unknown_fields"]))
        self.assertLessEqual(len(response.content), 1024)

    def test_empty_patch_reports_the_bounded_mutable_field_contract(self):
        response = self.request(
            "PATCH",
            f"/api/strategies/{self.strategy.guid}",
            {},
        )

        self.assertEqual(response.status_code, 400, response.content)
        body = response.json()
        self.assertEqual(body["code"], "invalid_request_fields")
        self.assertEqual(body["required_any_of"], ["config_options", "enabled", "name"])
        self.assertNotIn("unknown_fields", body)

    def test_error_response_does_not_mutate_domain_timestamps(self):
        StrategyProfile.objects.filter(pk=self.strategy.pk).update(
            updated_at=timezone.now() - datetime.timedelta(minutes=5),
        )
        self.strategy.refresh_from_db()
        previous = self.strategy.updated_at

        response = self.request(
            "PATCH",
            f"/api/strategies/{self.strategy.guid}",
            {"updated_at": timezone.now().isoformat()},
        )

        self.assert_field_error(response, unknown=["updated_at"])
        self.strategy.refresh_from_db()
        self.assertEqual(self.strategy.updated_at, previous)
