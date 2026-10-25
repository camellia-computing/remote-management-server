import importlib

from django.contrib.auth.models import Group
from django.contrib.postgres.indexes import GinIndex
from django.db import connection
from django.test import Client, SimpleTestCase, TestCase, override_settings, skipUnlessDBFeature

from api.control_filters import (
    CONTROL_FILTER_CONTRACT_VERSION,
    CONTROL_FILTER_MIN_SUBSTRING_CHARACTERS,
    ControlFilter,
    ControlFilterError,
    apply_control_filter,
    parse_control_filter,
)
from api.models import DeviceGroup, RemoteDevice
from api.tests import ApiTestMixin

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


class ControlFilterParserTests(SimpleTestCase):
    def test_filter_modes_are_explicit_and_bounded(self):
        self.assertEqual(parse_control_filter("hostname", "host-42"), ControlFilter("exact", "host-42"))
        self.assertEqual(parse_control_filter("hostname", "host-42%"), ControlFilter("prefix", "host-42"))
        self.assertEqual(parse_control_filter("hostname", "%host-42%"), ControlFilter("substring", "host-42"))
        self.assertIsNone(parse_control_filter("hostname", ""))
        self.assertIsNone(parse_control_filter("hostname", None))

    def test_short_or_ambiguous_substrings_fail_before_query_construction(self):
        invalid = ("%", "%%", "%ab%", "%host", "host%name", "%host%%")
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ControlFilterError) as context:
                parse_control_filter("hostname", value)
            self.assertEqual(context.exception.field, "hostname")

    def test_length_and_contract_details_are_stable(self):
        self.assertEqual(CONTROL_FILTER_CONTRACT_VERSION, 1)
        self.assertEqual(CONTROL_FILTER_MIN_SUBSTRING_CHARACTERS, 3)
        self.assertEqual(parse_control_filter("hostname", "x" * 128), ControlFilter("exact", "x" * 128))
        with self.assertRaises(ControlFilterError) as context:
            parse_control_filter("hostname", "x" * 129)
        self.assertEqual(context.exception.reason, "too_long")
        with self.assertRaises(ControlFilterError) as context:
            parse_control_filter("hostname", "界" * 86)
        self.assertEqual(context.exception.reason, "too_long")

    def test_postgresql_indexes_are_retryable_concurrent_operations(self):
        migration = importlib.import_module("api.migrations.0031_control_filter_indexes")

        self.assertFalse(migration.Migration.atomic)
        self.assertEqual(
            {name for name, _statement in migration.POSTGRES_INDEXES},
            {
                "auth_group_search_trgm_idx",
                "dev_group_search_trgm_idx",
                "dev_host_search_trgm_idx",
                "dev_user_search_trgm_idx",
                "device_hostname_idx",
                "device_username_idx",
            },
        )
        for name, statement in migration.POSTGRES_INDEXES:
            with self.subTest(index=name):
                self.assertIn("CREATE INDEX CONCURRENTLY", statement)

    def test_model_index_state_covers_exposed_device_fields(self):
        indexes = {index.name: index for index in (*RemoteDevice._meta.indexes, *DeviceGroup._meta.indexes)}
        self.assertEqual(indexes["device_hostname_idx"].fields, ["hostname"])
        self.assertEqual(indexes["device_username_idx"].fields, ["username"])
        for name, field in (
            ("dev_host_search_trgm_idx", "hostname"),
            ("dev_user_search_trgm_idx", "username"),
            ("dev_group_search_trgm_idx", "name"),
        ):
            with self.subTest(index=name):
                self.assertIsInstance(indexes[name], GinIndex)
                self.assertIn(field, repr(indexes[name].expressions))


@override_settings(
    STORAGES=TEST_STORAGES,
    REQUEST_RATE_LIMIT_ENABLED=False,
)
class ControlFilterApiTests(ApiTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.client = Client(raise_request_exception=False)
        self.token = self._login("admin", "admin-pass")
        self.device = self._device(
            owner=self.admin,
            rid="filter-device-42",
            uuid="ZmlsdGVyLWRldmljZS00Mg==",
            hostname="rack-host-42-prod",
            username="operator-42",
        )
        self.other_device = self._device(
            owner=self.admin,
            rid="filter-device-99",
            uuid="ZmlsdGVyLWRldmljZS05OQ==",
            hostname="rack-host-99-prod",
            username="operator-99",
        )
        self.group = DeviceGroup.objects.create(name="rack-group-42")
        self.device.device_group = self.group
        self.device.save(update_fields=("device_group",))
        Group.objects.create(name="operators-42").user_set.add(self.admin)

    def _get(self, path):
        return self.client.get(path, **self._auth_headers(self.token))

    def test_exact_prefix_and_substring_filters_have_stable_results(self):
        exact = self._get("/api/devices?device_name=rack-host-42-prod")
        self.assertEqual(exact.status_code, 200, exact.content)
        self.assertEqual([row["id"] for row in exact.json()["data"]], [self.device.rid])

        prefix = self._get("/api/devices?device_name=RACK-HOST-42-%25")
        self.assertEqual(prefix.status_code, 200, prefix.content)
        self.assertEqual([row["id"] for row in prefix.json()["data"]], [self.device.rid])

        substring = self._get("/api/devices?device_name=%25HOST-42%25")
        self.assertEqual(substring.status_code, 200, substring.content)
        self.assertEqual([row["id"] for row in substring.json()["data"]], [self.device.rid])

        system_username = self._get("/api/devices?device_username=%25OPERATOR-42%25")
        self.assertEqual(system_username.status_code, 200, system_username.content)
        self.assertEqual([row["id"] for row in system_username.json()["data"]], [self.device.rid])

        group = self._get("/api/devices?device_group_name=%25rack-group-42%25")
        self.assertEqual(group.status_code, 200, group.content)
        self.assertEqual([row["id"] for row in group.json()["data"]], [self.device.rid])

        owner = self._get("/api/devices?user_name=ADM%25")
        self.assertEqual(owner.status_code, 200, owner.content)
        expected_owner_devices = list(
            RemoteDevice.objects.filter(owner=self.admin).order_by("rid").values_list("rid", flat=True)
        )
        self.assertEqual([row["id"] for row in owner.json()["data"]], expected_owner_devices)

        owner_group = self._get("/api/devices?group_name=%25OPERATORS-42%25")
        self.assertEqual(owner_group.status_code, 200, owner_group.content)
        self.assertEqual([row["id"] for row in owner_group.json()["data"]], expected_owner_devices)

        users = self._get("/api/users?name=%25dmi%25")
        self.assertEqual(users.status_code, 200, users.content)
        self.assertEqual([row["name"] for row in users.json()["data"]], [self.admin.username])

        user_group = self._get("/api/users?group_name=OPERATORS%25")
        self.assertEqual(user_group.status_code, 200, user_group.content)
        self.assertEqual([row["name"] for row in user_group.json()["data"]], [self.admin.username])

        device_groups = self._get("/api/device-groups?name=%25group-42%25")
        self.assertEqual(device_groups.status_code, 200, device_groups.content)
        self.assertEqual([row["name"] for row in device_groups.json()["data"]], [self.group.name])

    def test_invalid_substring_returns_typed_400(self):
        response = self._get("/api/devices?device_name=%25ab%25")
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(
            response.json(),
            {
                "code": "invalid_control_filter",
                "control_filter_contract_version": CONTROL_FILTER_CONTRACT_VERSION,
                "field": "device_name",
                "message": "Invalid control-list filter",
                "reason": "substring_too_short",
                "response_schema_version": 1,
                "retryable": False,
            },
        )

    def test_duplicate_filter_returns_typed_400(self):
        response = self._get("/api/devices?device_name=first&device_name=second")
        self.assertEqual(response.status_code, 400, response.content)
        payload = response.json()
        self.assertEqual(payload["code"], "invalid_control_filter")
        self.assertEqual(payload["field"], "device_name")
        self.assertEqual(payload["reason"], "duplicate")

    def test_device_identifier_filter_is_exact_only(self):
        exact = self._get("/api/devices?id=filter-device-42")
        self.assertEqual(exact.status_code, 200, exact.content)
        self.assertEqual([row["id"] for row in exact.json()["data"]], [self.device.rid])

        response = self._get("/api/devices?id=filter-device-%25")
        self.assertEqual(response.status_code, 400, response.content)
        payload = response.json()
        self.assertEqual(payload["code"], "invalid_control_filter")
        self.assertEqual(payload["field"], "id")
        self.assertEqual(payload["reason"], "unsupported_mode")

    def test_apply_rejects_before_query_evaluation(self):
        with self.assertNumQueries(0), self.assertRaises(ControlFilterError):
            apply_control_filter(RemoteDevice.objects.all(), "hostname", "%ab%")

    @skipUnlessDBFeature("supports_expression_indexes")
    def test_postgresql_control_search_indexes_are_present(self):
        if connection.vendor != "postgresql":
            self.skipTest("expression index inventory is PostgreSQL-specific")
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT indexname
                FROM pg_indexes
                WHERE schemaname = current_schema()
                  AND indexname IN (
                    'dev_host_search_trgm_idx',
                    'dev_user_search_trgm_idx',
                    'dev_group_search_trgm_idx',
                    'auth_group_search_trgm_idx',
                    'device_hostname_idx',
                    'device_username_idx'
                  )
                ORDER BY indexname
                """
            )
            self.assertEqual(
                [row[0] for row in cursor.fetchall()],
                [
                    "auth_group_search_trgm_idx",
                    "dev_group_search_trgm_idx",
                    "dev_host_search_trgm_idx",
                    "dev_user_search_trgm_idx",
                    "device_hostname_idx",
                    "device_username_idx",
                ],
            )
