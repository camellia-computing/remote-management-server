import base64
import json
import uuid
from urllib.parse import quote

from django.core.exceptions import ValidationError
from django.db import DatabaseError
from django.test import Client, RequestFactory, TestCase, override_settings

from api.identifiers import (
    InvalidIdentifier,
    parse_model_pk,
    parse_model_pk_list,
    parse_uuid,
    parse_uuid_list,
)
from api.middleware import ApiExceptionMiddleware
from api.models import DeviceGroup, RemoteDevice, StrategyProfile, UserProfile
from api.views_api import _issue_access_token

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}
AUTO_FIELD_MAX = (1 << 31) - 1


@override_settings(STORAGES=TEST_STORAGES)
class ManagementIdentifierHttpTests(TestCase):
    def setUp(self):
        self.admin = UserProfile.objects.create_superuser(
            "identifier-admin",
            "identifier-admin-pass",  # noqa: S106 - isolated test credential
        )
        self.target = UserProfile.objects.create_user(
            "identifier-target",
            "identifier-target-pass",  # noqa: S106 - isolated test credential
        )
        self.device = RemoteDevice.objects.create(
            rid="731000001",
            uuid=base64.b64encode(b"identifier-admin-device").decode("ascii"),
            owner=self.admin,
            is_active=True,
            cpu="-",
            hostname="identifier-device",
            memory="-",
            os="Linux",
            username="identifier-admin",
            version="test",
        )
        _token, self.bearer = _issue_access_token(self.admin, self.device)
        self.managed_device = RemoteDevice.objects.create(
            rid="731000002",
            uuid=base64.b64encode(b"identifier-managed-device").decode("ascii"),
            owner=self.target,
            is_active=True,
            cpu="-",
            hostname="identifier-managed-device",
            memory="-",
            os="Linux",
            username="identifier-target",
            version="test",
        )
        self.group = DeviceGroup.objects.create(name="identifier-group")
        self.strategy = StrategyProfile.objects.create(
            name="identifier-strategy",
            config_options={},
        )
        self.client = Client(raise_request_exception=False)

    @property
    def auth(self):
        return {"HTTP_AUTHORIZATION": f"Bearer {self.bearer}"}

    def post_json(self, path, payload):
        return self.client.post(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_IDEMPOTENCY_KEY=str(uuid.uuid4()),
            **self.auth,
        )

    def put_json(self, path, payload):
        return self.client.put(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            **self.auth,
        )

    def assert_error(self, response, status):
        self.assertEqual(response.status_code, status, response.content[:1000])
        self.assertEqual(response.headers["Content-Type"], "application/json")
        self.assertIn("error", json.loads(response.content))
        self.assertNotIn(b"Traceback", response.content)

    def test_malformed_and_out_of_range_pk_paths_are_400_before_mutation(self):
        invalid_values = (
            "0",
            "01",
            "+1",
            "-1",
            f" {self.target.pk}",
            f"{self.target.pk} ",
            "1.0",
            "１",
            str(AUTO_FIELD_MAX + 1),
            "9" * 20,
            "9" * 64,
            "9" * 2000,
        )
        original_user_active = self.target.is_active
        original_device_active = self.managed_device.is_active

        for value in invalid_values:
            encoded = quote(value, safe="")
            with self.subTest(kind="user", value=value[:80]):
                self.assert_error(
                    self.client.post(f"/api/users/{encoded}/disable", **self.auth),
                    400,
                )
            with self.subTest(kind="device", value=value[:80]):
                self.assert_error(
                    self.client.post(f"/api/devices/{encoded}/disable", **self.auth),
                    400,
                )

        self.target.refresh_from_db()
        self.managed_device.refresh_from_db()
        self.assertEqual(self.target.is_active, original_user_active)
        self.assertEqual(self.managed_device.is_active, original_device_active)

    def test_valid_but_missing_pk_paths_are_404_at_autofield_boundary(self):
        self.assert_error(
            self.client.post(
                f"/api/users/{AUTO_FIELD_MAX}/enable",
                HTTP_IDEMPOTENCY_KEY=str(uuid.uuid4()),
                **self.auth,
            ),
            404,
        )
        self.assert_error(
            self.client.post(
                f"/api/devices/{AUTO_FIELD_MAX}/disable",
                HTTP_IDEMPOTENCY_KEY=str(uuid.uuid4()),
                **self.auth,
            ),
            404,
        )

    def test_pk_batch_rejects_non_text_and_out_of_range_values_without_revocation(self):
        invalid_values = (
            None,
            True,
            False,
            self.target.pk,
            1.0,
            {},
            [],
            "",
            "+1",
            "-1",
            " 1",
            "1 ",
            "１",
            "0",
            "01",
            str(AUTO_FIELD_MAX + 1),
            "9" * 20,
            "9" * 64,
            "9" * 2000,
        )
        original_generation = self.target.credential_generation

        for value in invalid_values:
            with self.subTest(value=repr(value)[:80]):
                response = self.post_json(
                    "/api/users/force-logout",
                    {"user_guids": [value]},
                )
                self.assert_error(response, 400)

        self.target.refresh_from_db()
        self.assertEqual(self.target.credential_generation, original_generation)

        mixed = self.post_json(
            "/api/users/force-logout",
            {"user_guids": [str(self.target.pk), str(AUTO_FIELD_MAX + 1)]},
        )
        self.assert_error(mixed, 400)
        self.target.refresh_from_db()
        self.assertEqual(self.target.credential_generation, original_generation)

    def test_strategy_assignment_uses_typed_pk_and_uuid_lists(self):
        invalid_pk_values = (
            None,
            True,
            self.target.pk,
            1.0,
            {},
            [],
            "0",
            "01",
            str(AUTO_FIELD_MAX + 1),
            "9" * 2000,
        )
        invalid_uuid_values = (
            None,
            True,
            1,
            1.0,
            {},
            [],
            "",
            "not-a-uuid",
            "{" + str(self.group.guid) + "}",
            self.group.guid.hex,
            " " + str(self.group.guid),
        )

        for value in invalid_pk_values:
            with self.subTest(kind="device-pk", value=repr(value)[:80]):
                self.assert_error(
                    self.post_json("/api/strategies/assign", {"strategy": None, "peers": [value]}),
                    400,
                )
            with self.subTest(kind="user-pk", value=repr(value)[:80]):
                self.assert_error(
                    self.post_json("/api/strategies/assign", {"strategy": None, "users": [value]}),
                    400,
                )
        for value in invalid_uuid_values:
            with self.subTest(kind="group-uuid", value=repr(value)[:80]):
                self.assert_error(
                    self.post_json("/api/strategies/assign", {"strategy": None, "groups": [value]}),
                    400,
                )

        self.target.refresh_from_db()
        self.managed_device.refresh_from_db()
        self.group.refresh_from_db()
        self.assertIsNone(self.target.strategy_id)
        self.assertIsNone(self.managed_device.strategy_id)
        self.assertIsNone(self.group.strategy_id)

        mixed = self.post_json(
            "/api/strategies/assign",
            {
                "strategy": None,
                "users": [str(self.target.pk), str(AUTO_FIELD_MAX + 1)],
            },
        )
        self.assert_error(mixed, 400)
        self.target.refresh_from_db()
        self.assertIsNone(self.target.strategy_id)

    def test_uuid_paths_require_canonical_shape_but_accept_uppercase(self):
        strategy_guid = str(self.strategy.guid)
        group_guid = str(self.group.guid)
        invalid_strategy_values = (
            "not-a-uuid",
            "{" + strategy_guid + "}",
            self.strategy.guid.hex,
            " " + strategy_guid,
        )
        invalid_group_values = (
            "not-a-uuid",
            "{" + group_guid + "}",
            self.group.guid.hex,
            " " + group_guid,
        )

        for value in invalid_strategy_values:
            with self.subTest(kind="strategy", value=value):
                self.assert_error(
                    self.client.get(f"/api/strategies/{quote(value, safe='')}", **self.auth),
                    400,
                )
        for value in invalid_group_values:
            with self.subTest(kind="group", value=value):
                self.assert_error(
                    self.post_json(f"/api/device-groups/{quote(value, safe='')}", []),
                    400,
                )

        self.assertEqual(
            self.client.get(f"/api/strategies/{strategy_guid.upper()}", **self.auth).status_code,
            200,
        )
        self.assertEqual(
            self.post_json(
                f"/api/device-groups/{group_guid.upper()}",
                [self.managed_device.rid],
            ).status_code,
            200,
        )
        missing = str(uuid.UUID(int=0))
        self.assert_error(self.client.get(f"/api/strategies/{missing}", **self.auth), 404)
        self.assert_error(
            self.post_json(f"/api/device-groups/{missing}", [self.managed_device.rid]),
            404,
        )

    def test_every_uuid_path_method_rejects_before_payload_or_mutation(self):
        invalid = "not-a-uuid"
        group_path = f"/api/device-groups/{invalid}"
        strategy_path = f"/api/strategies/{invalid}"

        responses = (
            self.client.patch(
                group_path,
                data=json.dumps({"name": "changed"}),
                content_type="application/json",
                **self.auth,
            ),
            self.client.delete(group_path, **self.auth),
            self.client.delete(f"{group_path}/devices", data="[]", content_type="application/json", **self.auth),
            self.client.patch(
                strategy_path,
                data=json.dumps({"name": "changed"}),
                content_type="application/json",
                **self.auth,
            ),
            self.client.delete(strategy_path, **self.auth),
            self.put_json(f"{strategy_path}/status", {"enabled": False}),
        )
        for response in responses:
            self.assert_error(response, 400)

        self.group.refresh_from_db()
        self.strategy.refresh_from_db()
        self.assertEqual(self.group.name, "identifier-group")
        self.assertEqual(self.strategy.name, "identifier-strategy")
        self.assertTrue(self.strategy.enabled)

    def test_every_device_pk_path_rejects_before_payload_or_mutation(self):
        invalid = str(AUTO_FIELD_MAX + 1)
        path = f"/api/devices/{invalid}"
        responses = (
            self.post_json(f"{path}/approve-recovery", {"pk": "invalid"}),
            self.post_json(f"{path}/assign", {"type": "note", "value": "changed"}),
            self.client.delete(path, **self.auth),
        )
        for response in responses:
            self.assert_error(response, 400)

        self.managed_device.refresh_from_db()
        self.assertEqual(self.managed_device.note, "")
        self.assertTrue(RemoteDevice.objects.filter(pk=self.managed_device.pk).exists())

    def test_strategy_identifier_rejects_wrong_types_and_noncanonical_uuid(self):
        original_strategy_id = self.target.strategy_id
        invalid_values = (
            False,
            True,
            0,
            1,
            1.0,
            {},
            [],
            "not-a-uuid",
            "{" + str(self.strategy.guid) + "}",
            self.strategy.guid.hex,
        )

        for value in invalid_values:
            with self.subTest(value=repr(value)):
                self.assert_error(
                    self.post_json(
                        "/api/strategies/assign",
                        {"strategy": value, "users": [str(self.target.pk)]},
                    ),
                    400,
                )

        self.target.refresh_from_db()
        self.assertEqual(self.target.strategy_id, original_strategy_id)

        accepted = self.post_json(
            "/api/strategies/assign",
            {
                "strategy": str(self.strategy.guid).upper(),
                "users": [str(self.target.pk)],
            },
        )
        self.assertEqual(accepted.status_code, 200, accepted.content)
        self.target.refresh_from_db()
        self.assertEqual(self.target.strategy_id, self.strategy.pk)


class IdentifierExceptionBoundaryTests(TestCase):
    def test_validation_error_is_a_bounded_400_but_database_errors_are_not_hidden(self):
        middleware = ApiExceptionMiddleware(lambda request: None)
        request = RequestFactory().get("/api/strategies/not-a-uuid")

        response = middleware.process_exception(request, InvalidIdentifier("invalid UUID"))

        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content), {"error": "Invalid identifier"})
        self.assertIsNone(middleware.process_exception(request, ValidationError("non-identifier validation failure")))
        self.assertIsNone(middleware.process_exception(request, DatabaseError("database unavailable")))


class TypedIdentifierParserTests(TestCase):
    def test_model_pk_parser_uses_declared_autofield_range_without_queries(self):
        with self.assertNumQueries(0):
            self.assertEqual(parse_model_pk("1", UserProfile), 1)
            self.assertEqual(parse_model_pk(str(AUTO_FIELD_MAX), RemoteDevice), AUTO_FIELD_MAX)
            for value in (
                None,
                True,
                1,
                1.0,
                {},
                [],
                "",
                "0",
                "01",
                "+1",
                "-1",
                " 1",
                "1 ",
                "１",
                str(AUTO_FIELD_MAX + 1),
                "9" * 64,
                "9" * 2000,
            ):
                with self.subTest(value=repr(value)[:80]), self.assertRaises(InvalidIdentifier):
                    parse_model_pk(value, UserProfile)

    def test_uuid_parser_normalizes_case_and_rejects_noncanonical_shapes_without_queries(self):
        expected = uuid.uuid4()
        with self.assertNumQueries(0):
            self.assertEqual(parse_uuid(str(expected)), expected)
            self.assertEqual(parse_uuid(str(expected).upper()), expected)
            for value in (
                None,
                True,
                1,
                1.0,
                {},
                [],
                "",
                "not-a-uuid",
                "{" + str(expected) + "}",
                expected.hex,
                " " + str(expected),
                str(expected) + " ",
            ):
                with self.subTest(value=repr(value)), self.assertRaises(InvalidIdentifier):
                    parse_uuid(value)

    def test_typed_lists_reject_duplicates_and_fail_whole_mixed_input(self):
        expected = uuid.uuid4()
        with self.assertNumQueries(0):
            with self.assertRaises(InvalidIdentifier):
                parse_model_pk_list(["1", "1", "2"], UserProfile, max_items=3)
            with self.assertRaises(InvalidIdentifier):
                parse_uuid_list([str(expected), str(expected).upper()], max_items=2)
            with self.assertRaises(InvalidIdentifier):
                parse_model_pk_list(["1", str(AUTO_FIELD_MAX + 1)], UserProfile, max_items=2)
            with self.assertRaises(InvalidIdentifier):
                parse_uuid_list([str(expected), "not-a-uuid"], max_items=2)
            with self.assertRaises(InvalidIdentifier):
                parse_model_pk_list(["1"] * 501, UserProfile, max_items=500)
