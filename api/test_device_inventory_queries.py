import re
from datetime import timedelta
from unittest.mock import patch

from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from api.models import AddressBookProfile, RemoteDevice, RemotePeer
from api.tests import ApiTestMixin, device_uuid
from api.xlsx import SpreadsheetBudgetExceeded, bounded_xlsx_file_response

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


def _inventory_selects(queries):
    return [
        query["sql"]
        for query in queries
        if 'FROM "api_remotedevice"' in query["sql"]
        and '"api_remotetoken"' not in query["sql"]
        and not query["sql"].lstrip().upper().startswith("UPDATE")
    ]


def _has_limit(sql, limit):
    return re.search(rf"\bLIMIT\s+{limit}\b", sql, flags=re.IGNORECASE) is not None


@override_settings(STORAGES=TEST_STORAGES)
class DeviceInventoryQueryTests(ApiTestMixin, TestCase):
    def _create_devices(self, owner, count):
        RemoteDevice.objects.bulk_create(
            [
                RemoteDevice(
                    owner=owner,
                    rid=f"8{index:08d}",
                    uuid=device_uuid(f"inventory-{owner.pk}-{index}"),
                    cpu="cpu",
                    hostname=f"host-{index}",
                    memory="memory",
                    os="linux",
                    username=f"user-{index}",
                    version="2.0.0",
                )
                for index in range(count)
            ]
        )

    def test_device_inventory_index_contract(self):
        with connection.cursor() as cursor:
            constraints = connection.introspection.get_constraints(
                cursor,
                RemoteDevice._meta.db_table,
            )
        expected = {
            "device_owner_rid_idx",
            "device_owner_active_rid_idx",
            "device_active_rid_idx",
            "device_owner_updated_rid_idx",
        }
        self.assertTrue(expected <= constraints.keys())
        for name in expected:
            with self.subTest(index=name):
                self.assertTrue(constraints[name]["index"])

    def test_peers_page_size_one_is_limited_in_the_database(self):
        token = self._login("alice", "alice-pass")
        self._create_devices(self.user, 16)

        with CaptureQueriesContext(connection) as captured:
            response = self.client.get(
                "/api/peers?current=1&pageSize=1&status=1",
                **self._auth_headers(token),
            )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(len(response.json()["data"]), 1)
        inventory_sql = _inventory_selects(captured.captured_queries)
        self.assertTrue(
            any(_has_limit(sql, 1) for sql in inventory_sql),
            "inventory rows must be sliced by the database before Python materialization",
        )
        self.assertFalse(
            any("address_book_password" in sql for sql in inventory_sql),
            "inventory projections must never load write-only credentials",
        )

    def test_work_page_is_limited_in_the_database(self):
        self._create_devices(self.user, 16)
        self.client.force_login(self.user)

        with CaptureQueriesContext(connection) as captured:
            response = self.client.get("/api/work")

        self.assertEqual(response.status_code, 200, response.content)
        inventory_sql = _inventory_selects(captured.captured_queries)
        self.assertTrue(
            any(_has_limit(sql, 15) for sql in inventory_sql),
            "the work page must not construct the complete inventory before pagination",
        )
        self.assertFalse(any("address_book_password" in sql for sql in inventory_sql))

    def test_home_recent_devices_use_a_top_six_query(self):
        self._create_devices(self.user, 16)
        self.client.force_login(self.user)

        with CaptureQueriesContext(connection) as captured:
            response = self.client.get("/api/home")

        self.assertEqual(response.status_code, 200, response.content)
        inventory_sql = _inventory_selects(captured.captured_queries)
        self.assertTrue(
            any(_has_limit(sql, 6) for sql in inventory_sql),
            "the home page must query only the six most recently updated devices",
        )
        self.assertFalse(any("address_book_password" in sql for sql in inventory_sql))

    def test_device_export_uses_a_streaming_response(self):
        self._create_devices(self.admin, 1)
        self.client.force_login(self.admin)

        response = self.client.get("/api/down_peers")

        self.assertEqual(response.status_code, 200, getattr(response, "content", b""))
        self.assertTrue(response.streaming)
        b"".join(response.streaming_content)
        for closer in response._resource_closers:
            closer()
        response._resource_closers.clear()

    def test_bounded_xlsx_spools_and_enforces_byte_and_deadline_budgets(self):
        response, row_count, response_bytes = bounded_xlsx_file_response(
            "bounded.xlsx",
            "bounded",
            ("rid", "value"),
            ((f"rid-{index}", f"value-{index}-" + "x" * 100) for index in range(100)),
            max_rows=100,
            max_bytes=1024 * 1024,
            deadline_seconds=60,
            spool_memory_bytes=1024,
        )
        self.assertEqual(row_count, 100)
        self.assertGreater(response_bytes, 1024)
        self.assertTrue(response.file_to_stream._rolled)
        self.assertEqual(sum(len(chunk) for chunk in response.streaming_content), response_bytes)
        for closer in response._resource_closers:
            closer()
        response._resource_closers.clear()

        with self.assertRaises(SpreadsheetBudgetExceeded):
            bounded_xlsx_file_response(
                "byte-budget.xlsx",
                "bounded",
                ("rid",),
                (("rid-1",),),
                max_rows=1,
                max_bytes=1,
                deadline_seconds=60,
                spool_memory_bytes=1024,
            )

        with (
            patch("api.xlsx.monotonic", side_effect=(100.0, 102.0)),
            self.assertRaises(SpreadsheetBudgetExceeded),
        ):
            bounded_xlsx_file_response(
                "deadline.xlsx",
                "bounded",
                ("rid",),
                (("rid-1",),),
                max_rows=1,
                max_bytes=1024 * 1024,
                deadline_seconds=1,
                spool_memory_bytes=1024,
            )

    def test_personal_union_uses_the_exact_profile_and_owner_keys(self):
        personal = AddressBookProfile.objects.create(
            owner=self.user,
            guid=f"personal-{self.user.pk}",
            name="My address book",
            rule=3,
        )
        other_profile = AddressBookProfile.objects.create(
            owner=self.user,
            guid="personal-shadow-profile",
            name="Shadow",
            rule=3,
        )
        device = self._device(
            owner=self.user,
            rid="700000001",
            uuid=device_uuid("exact-profile-device"),
            username="",
            note="",
        )
        RemotePeer.objects.create(
            profile=other_profile,
            rid=device.rid,
            username="WRONG-PROFILE-USERNAME",
            alias="WRONG-PROFILE-ALIAS",
            device_group_name="WRONG-PROFILE-GROUP",
        )
        RemotePeer.objects.create(
            profile=personal,
            rid=device.rid,
            username="exact-peer-username",
            alias="exact-peer-alias",
            device_group_name="exact-peer-group",
            note="exact-peer-note",
        )
        token = self._login(
            "alice",
            "alice-pass",
            rid="700000002",
            uuid=device_uuid("exact-profile-session-device"),
        )

        response = self.client.get(
            "/api/peers?current=1&pageSize=100&status=1",
            **self._auth_headers(token),
        )

        self.assertEqual(response.status_code, 200, response.content)
        item = next(row for row in response.json()["data"] if row["id"] == device.rid)
        self.assertEqual(item["info"]["username"], "exact-peer-username")
        self.assertEqual(item["device_group_name"], "exact-peer-group")
        self.assertNotContains(response, "WRONG-PROFILE")

        admin_token = self._login(
            "admin",
            "admin-pass",
            rid="700000003",
            uuid=device_uuid("exact-profile-admin-session-device"),
        )
        admin_response = self.client.get(
            "/api/peers?current=1&pageSize=100&status=1",
            **self._auth_headers(admin_token),
        )
        self.assertEqual(admin_response.status_code, 200, admin_response.content)
        admin_item = next(row for row in admin_response.json()["data"] if row["id"] == device.rid)
        self.assertEqual(admin_item["info"]["username"], "exact-peer-username")
        self.assertEqual(admin_item["device_group_name"], "exact-peer-group")
        self.assertNotContains(admin_response, "WRONG-PROFILE")

        self.client.force_login(self.user)
        work_response = self.client.get("/api/work")
        self.assertEqual(work_response.status_code, 200, work_response.content)
        front_item = next(row for row in work_response.context["page_obj"] if row["rid"] == device.rid)
        self.assertEqual(front_item["alias"], "exact-peer-alias")
        self.assertEqual(front_item["note"], "exact-peer-note")
        self.assertEqual(front_item["_inventory_source"], "device")
        self.assertEqual(front_item["_inventory_owner_id"], self.user.pk)

    def test_status_filter_preserves_peer_only_semantics(self):
        token = self._login("alice", "alice-pass")
        inactive = self._device(
            owner=self.user,
            rid="700000010",
            uuid=device_uuid("inactive-inventory-device"),
            is_active=False,
        )
        personal = AddressBookProfile.objects.create(
            owner=self.user,
            guid=f"personal-{self.user.pk}",
            name="My address book",
            rule=3,
        )
        peer_only = RemotePeer.objects.create(
            profile=personal,
            rid="700000011",
            username="peer-only-user",
        )

        active_response = self.client.get(
            "/api/peers?status=1&pageSize=100",
            **self._auth_headers(token),
        )
        inactive_response = self.client.get(
            "/api/peers?status=0&pageSize=100",
            **self._auth_headers(token),
        )

        self.assertEqual(active_response.status_code, 200, active_response.content)
        self.assertEqual(inactive_response.status_code, 200, inactive_response.content)
        active_ids = {row["id"] for row in active_response.json()["data"]}
        inactive_ids = {row["id"] for row in inactive_response.json()["data"]}
        self.assertIn(peer_only.rid, active_ids)
        self.assertNotIn(peer_only.rid, inactive_ids)
        self.assertIn(inactive.rid, inactive_ids)
        self.assertNotIn(inactive.rid, active_ids)

    def test_signed_cursor_is_stable_across_insert_and_delete(self):
        token = self._login("alice", "alice-pass")
        for index, rid in enumerate(("200000000", "300000000", "400000000")):
            self._device(
                owner=self.user,
                rid=rid,
                uuid=device_uuid(f"cursor-device-{index}"),
            )

        first = self.client.get(
            "/api/peers?status=1&pageSize=2",
            **self._auth_headers(token),
        )
        self.assertEqual(first.status_code, 200, first.content)
        first_ids = [row["id"] for row in first.json()["data"]]
        cursor = first.json()["nextCursor"]
        self.assertEqual(first_ids, ["123456789", "200000000"])
        self.assertTrue(cursor)

        self._device(
            owner=self.user,
            rid="150000000",
            uuid=device_uuid("cursor-insert-before-boundary"),
        )
        self._device(
            owner=self.user,
            rid="250000000",
            uuid=device_uuid("cursor-insert-after-boundary"),
        )
        RemoteDevice.objects.filter(rid="200000000").delete()

        second = self.client.get(
            "/api/peers?status=1&pageSize=2&cursor=" + cursor,
            **self._auth_headers(token),
        )
        self.assertEqual(second.status_code, 200, second.content)
        second_ids = [row["id"] for row in second.json()["data"]]
        self.assertEqual(second_ids, ["250000000", "300000000"])
        self.assertFalse(set(first_ids) & set(second_ids))

        filter_mismatch = self.client.get(
            "/api/peers?status=0&pageSize=2&cursor=" + cursor,
            **self._auth_headers(token),
        )
        tampered = self.client.get(
            "/api/peers?status=1&pageSize=2&cursor=" + cursor + "x",
            **self._auth_headers(token),
        )
        self.assertEqual(filter_mismatch.status_code, 400)
        self.assertEqual(tampered.status_code, 400)

    def test_home_summary_counts_devices_and_peer_only_rows_in_sql(self):
        personal = AddressBookProfile.objects.create(
            owner=self.user,
            guid=f"personal-{self.user.pk}",
            name="My address book",
            rule=3,
        )
        self._create_devices(self.user, 7)
        offline_ids = list(
            RemoteDevice.objects.filter(owner=self.user).order_by("rid").values_list("pk", flat=True)[:2]
        )
        RemoteDevice.objects.filter(pk__in=offline_ids).update(update_time=timezone.now() - timedelta(days=1))
        RemotePeer.objects.create(profile=personal, rid="900000001", alias="peer-only")
        self.client.force_login(self.user)

        response = self.client.get("/api/home")

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            response.context["summary"],
            {"total": 8, "online": 5, "offline": 2, "unknown": 1},
        )
        self.assertEqual(len(response.context["recent"]), 6)
        self.assertTrue(all(row["_inventory_source"] == "device" for row in response.context["recent"]))

    def test_page_query_count_is_constant_for_large_inventory(self):
        token = self._login("alice", "alice-pass")
        with CaptureQueriesContext(connection) as small_queries:
            small = self.client.get(
                "/api/peers?status=1&pageSize=1",
                **self._auth_headers(token),
            )
        self.assertEqual(small.status_code, 200, small.content)

        self._create_devices(self.user, 5000)
        with CaptureQueriesContext(connection) as large_queries:
            large = self.client.get(
                "/api/peers?status=1&pageSize=1",
                **self._auth_headers(token),
            )
        self.assertEqual(large.status_code, 200, large.content)
        small_inventory_queries = _inventory_selects(small_queries.captured_queries)
        large_inventory_queries = _inventory_selects(large_queries.captured_queries)
        self.assertLessEqual(abs(len(small_inventory_queries) - len(large_inventory_queries)), 1)
        self.assertLessEqual(max(len(small_inventory_queries), len(large_inventory_queries)), 6)
        self.assertEqual(len(large.json()["data"]), 1)

    @override_settings(DEVICE_INVENTORY_EXPORT_MAX_ROWS=1)
    def test_device_export_rejects_rows_over_the_hard_budget(self):
        self._create_devices(self.admin, 2)
        self.client.force_login(self.admin)

        response = self.client.get("/api/down_peers")

        self.assertEqual(response.status_code, 413)
        self.assertFalse(response.streaming)
