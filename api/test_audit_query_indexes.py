import datetime
import importlib

from django.contrib.postgres.indexes import GinIndex
from django.db import connection
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from api.admin_user import AuditAdminPaginator
from api.audit_queries import filter_address_book_audits, filter_alarm_logs
from api.models import AddressBookRuleAudit, AlarmLog, UserProfile
from api.views_front import _ab_audit_page

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


class AuditQueryIndexContractTests(SimpleTestCase):
    def test_postgresql_indexes_are_retryable_concurrent_operations(self):
        migration = importlib.import_module("api.migrations.0021_audit_ordering_indexes")

        self.assertFalse(migration.Migration.atomic)
        self.assertEqual(
            {name for name, _statement in migration.POSTGRES_INDEXES},
            {
                "ab_audit_created_pk_idx",
                "ab_audit_search_trgm_idx",
                "alarm_created_pk_idx",
                "alarm_type_created_pk_idx",
                "alarm_search_trgm_idx",
                "user_name_search_trgm_idx",
            },
        )
        for name, statement in migration.POSTGRES_INDEXES:
            with self.subTest(index=name):
                self.assertIn("CREATE INDEX CONCURRENTLY", statement)
        self.assertNotIn("ab_audit_search_trgm_idx", {name for name, _statement in migration.SQLITE_INDEXES})
        self.assertNotIn("alarm_search_trgm_idx", {name for name, _statement in migration.SQLITE_INDEXES})
        self.assertNotIn("user_name_search_trgm_idx", {name for name, _statement in migration.SQLITE_INDEXES})

    def test_time_ordered_audit_models_have_stable_matching_indexes(self):
        expected = {
            "alarm_created_pk_idx": ("-created_at", "-id"),
            "alarm_type_created_pk_idx": ("typ", "-created_at", "-id"),
            "ab_audit_created_pk_idx": ("-created_at", "-id"),
        }
        actual = {
            index.name: tuple(index.fields)
            for model in (AlarmLog, AddressBookRuleAudit)
            for index in model._meta.indexes
            if index.fields
        }

        for name, fields in expected.items():
            with self.subTest(index=name):
                self.assertEqual(actual.get(name), fields)

        self.assertEqual(AlarmLog._meta.ordering, ("-created_at", "-id"))
        self.assertEqual(AddressBookRuleAudit._meta.ordering, ("-created_at", "-id"))

    def test_text_search_indexes_match_every_local_icontains_expression(self):
        expected = {
            "alarm_search_trgm_idx": (
                "reporter_device_id",
                "reporter_device_uuid",
                "audit_ref",
            ),
            "ab_audit_search_trgm_idx": (
                "profile_name",
                "profile_guid",
                "profile_owner_name",
                "target_name",
                "action",
            ),
        }
        indexes = {
            index.name: index
            for model in (AlarmLog, AddressBookRuleAudit, UserProfile)
            for index in model._meta.indexes
            if isinstance(index, GinIndex)
        }

        self.assertIn("username", repr(indexes["user_name_search_trgm_idx"].expressions))
        self.assertEqual(indexes["user_name_search_trgm_idx"].expressions[0].extra["name"], "gin_trgm_ops")

        for name, field_names in expected.items():
            with self.subTest(index=name):
                index = indexes[name]
                self.assertEqual(len(index.expressions), 1)
                expression_text = repr(index.expressions)
                for field_name in field_names:
                    self.assertIn(field_name, expression_text)
                for expression in index.expressions:
                    self.assertEqual(expression.extra["name"], "gin_trgm_ops")


@override_settings(STORAGES=TEST_STORAGES)
class AddressBookAuditCursorTests(TestCase):
    def setUp(self):
        self.admin = UserProfile.objects.create_superuser(
            username="audit-cursor-admin",
            password="admin-pass",  # noqa: S106 - isolated test credential
        )
        self.client.force_login(self.admin)

    def _audit(self, number, *, actor=None, created_at=None, target_name=None):
        return AddressBookRuleAudit(
            profile_guid=f"profile-{number:02d}",
            profile_name=f"Profile {number:02d}",
            profile_owner_name="owner",
            actor=actor,
            action="rule_add",
            target_type="user",
            target_name=target_name or f"CURSOR-{number:02d}",
            rule=1,
            created_at=created_at or timezone.now(),
        )

    def test_cursor_pages_stably_across_equal_timestamps_without_count_or_offset(self):
        observed_at = timezone.now() - datetime.timedelta(minutes=1)
        AddressBookRuleAudit.objects.bulk_create([self._audit(number, created_at=observed_at) for number in range(45)])

        with CaptureQueriesContext(connection) as first_queries:
            direct_rows, direct_has_newer, direct_has_older = _ab_audit_page(
                AddressBookRuleAudit.objects.select_related("profile", "actor"),
                None,
            )
        first_query_log = list(first_queries.captured_queries)
        boundary = direct_rows[-1]
        with CaptureQueriesContext(connection) as cursor_queries:
            _ab_audit_page(
                AddressBookRuleAudit.objects.select_related("profile", "actor"),
                ("older", boundary.created_at, boundary.pk),
            )
        cursor_query_log = list(cursor_queries.captured_queries)
        first = self.client.get("/api/ab_audit")
        older = first.context["older_cursor"]
        second = self.client.get("/api/ab_audit", {"cursor": older})
        third = self.client.get("/api/ab_audit", {"cursor": second.context["older_cursor"]})
        back = self.client.get("/api/ab_audit", {"cursor": second.context["newer_cursor"]})

        self.assertEqual(first.status_code, 200, first.content)
        self.assertEqual(
            [entry["target_name"] for entry in first.context["entries"]],
            [f"CURSOR-{number:02d}" for number in range(44, 24, -1)],
        )
        self.assertEqual(
            [entry["target_name"] for entry in second.context["entries"]],
            [f"CURSOR-{number:02d}" for number in range(24, 4, -1)],
        )
        self.assertEqual(
            [entry["target_name"] for entry in third.context["entries"]],
            [f"CURSOR-{number:02d}" for number in range(4, -1, -1)],
        )
        self.assertEqual(back.context["entries"], first.context["entries"])
        self.assertFalse(first.context["has_newer"])
        self.assertTrue(first.context["has_older"])
        self.assertEqual(
            [row.target_name for row in direct_rows], [f"CURSOR-{number:02d}" for number in range(44, 24, -1)]
        )
        self.assertFalse(direct_has_newer)
        self.assertTrue(direct_has_older)
        self.assertTrue(second.context["has_newer"])
        self.assertTrue(second.context["has_older"])
        self.assertTrue(third.context["has_newer"])
        self.assertFalse(third.context["has_older"])
        audit_sql = "\n".join(query["sql"] for query in first_query_log if "target_name" in query["sql"].lower())
        self.assertNotIn("COUNT(", audit_sql.upper())
        self.assertNotIn("OFFSET", audit_sql.upper())
        self.assertIn("LIMIT 21", audit_sql.upper())
        cursor_sql = "\n".join(query["sql"] for query in cursor_query_log if "target_name" in query["sql"].lower())
        self.assertIn('CREATED_AT", "API_ADDRESSBOOKRULEAUDIT"."ID") < (', cursor_sql.upper())
        self.assertNotIn('"CREATED_AT" <', cursor_sql.upper())

    def test_search_resolves_actor_ids_before_the_indexed_audit_query_and_rejects_short_terms(self):
        actor = UserProfile.objects.create_user(username="needle-actor")
        self._audit(1, actor=actor, target_name="actor-only").save()
        self._audit(2, target_name="needle-target").save()

        with CaptureQueriesContext(connection) as captured:
            filtered, too_broad = filter_address_book_audits(AddressBookRuleAudit.objects.all(), "needle")
            list(filtered.order_by("-created_at", "-id")[:21])
        query_log = list(captured.captured_queries)
        found = self.client.get("/api/ab_audit", {"q": "needle"})
        rejected = self.client.get("/api/ab_audit", {"q": "ab"})
        too_long = self.client.get("/api/ab_audit", {"q": "a" * 345})

        self.assertEqual(found.status_code, 200, found.content)
        self.assertEqual(
            {entry["target_name"] for entry in found.context["entries"]},
            {"actor-only", "needle-target"},
        )
        self.assertFalse(too_broad)
        audit_sql = "\n".join(query["sql"] for query in query_log if "target_name" in query["sql"].lower())
        self.assertNotIn('UPPER("API_USERPROFILE"."USERNAME"', audit_sql.upper())
        self.assertNotIn("COUNT(", audit_sql.upper())
        self.assertIn("COALESCE", audit_sql.upper())
        self.assertEqual(rejected.context["entries"], [])
        self.assertContains(rejected, "至少需要 3 个字符")
        self.assertEqual(too_long.context["entries"], [])
        self.assertContains(too_long, "不能超过 344 个字符")

    def test_tampered_cursor_fails_closed_to_the_latest_page(self):
        AddressBookRuleAudit.objects.bulk_create([self._audit(number) for number in range(21)])
        first = self.client.get("/api/ab_audit")
        tampered = f"{first.context['older_cursor']}tampered"

        response = self.client.get("/api/ab_audit", {"cursor": tampered})

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.context["entries"], first.context["entries"])
        self.assertContains(response, "分页游标无效")


@override_settings(STORAGES=TEST_STORAGES)
class AlarmAdminPaginationTests(TestCase):
    def setUp(self):
        self.admin = UserProfile.objects.create_superuser(
            username="alarm-query-admin",
            password="admin-pass",  # noqa: S106 - isolated test credential
        )
        self.client.force_login(self.admin)

    def test_admin_caps_browse_depth_without_full_table_count(self):
        AlarmLog.objects.bulk_create(
            [
                AlarmLog(
                    typ=AlarmLog.TYPE_IP_WHITELIST,
                    reporter_device_id=f"{number:09d}",
                    reporter_device_uuid=f"alarm-device-{number}",
                    audit_ref=f"alarm-ref-{number}",
                )
                for number in range(10_005)
            ]
        )

        with CaptureQueriesContext(connection) as captured:
            direct_count = AuditAdminPaginator(AlarmLog.objects.all(), 100).count
        query_log = list(captured.captured_queries)
        response = self.client.get("/admin/api/alarmlog/")

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(direct_count, 10_000)
        self.assertEqual(response.context["cl"].result_count, 10_000)
        self.assertIsNone(response.context["cl"].full_result_count)
        alarm_sql = "\n".join(query["sql"] for query in query_log if "api_alarmlog" in query["sql"].lower())
        self.assertNotIn("COUNT(", alarm_sql.upper())
        self.assertIn("LIMIT 10001", alarm_sql.upper())
        self.assertContains(response, "最新的 10,000 条记录")

    def test_admin_search_resolves_reporter_without_joining_username_into_the_or_predicate(self):
        reporter = UserProfile.objects.create_user(username="needle-reporter")
        AlarmLog.objects.create(
            typ=AlarmLog.TYPE_RAPID_ATTEMPTS,
            reporter=reporter,
            reporter_device_id="100000001",
            reporter_device_uuid="actor-only-device",
            audit_ref="actor-only-reference",
        )

        with CaptureQueriesContext(connection) as captured:
            filtered, too_broad = filter_alarm_logs(AlarmLog.objects.all(), "needle")
            list(filtered.order_by("-created_at", "-id")[:101])
        query_log = list(captured.captured_queries)
        response = self.client.get("/admin/api/alarmlog/", {"q": "needle"})

        self.assertEqual(response.status_code, 200, response.content)
        self.assertFalse(too_broad)
        self.assertContains(response, "100000001")
        alarm_sql = "\n".join(query["sql"] for query in query_log if "reporter_device_id" in query["sql"].lower())
        self.assertNotIn('UPPER("API_USERPROFILE"."USERNAME"', alarm_sql.upper())
        self.assertIn("COALESCE", alarm_sql.upper())

    def test_admin_rejects_short_search_terms_explicitly(self):
        AlarmLog.objects.create(typ=0, reporter_device_id="100000002")

        response = self.client.get("/admin/api/alarmlog/", {"q": "ab"})
        too_long = self.client.get("/admin/api/alarmlog/", {"q": "a" * 345})

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.context["cl"].result_count, 0)
        self.assertContains(response, "每个词都至少需要 3 个字符")
        self.assertEqual(too_long.status_code, 200, too_long.content)
        self.assertEqual(too_long.context["cl"].result_count, 0)
        self.assertContains(too_long, "每个词都不能超过 344 个字符")
