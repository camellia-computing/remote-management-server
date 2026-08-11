import json
import queue
import threading

from django.contrib.auth.models import Group, Permission
from django.core import serializers
from django.db import DatabaseError, close_old_connections, connection, models
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

from api.migration_test_support import restore_latest_migration_state
from api.models import AddressBookProfile, LoginAttempt, UserProfile
from api.models_work import RemotePeer, RemoteTag, ShareLink

INTEGER_MAX = (1 << 31) - 1
BIGINT_MAX = (1 << 63) - 1
MIGRATE_FROM = ("api", "0029_strategy_config_options_authority")
MIGRATE_TO = ("api", "0030_bigint_primary_key_capacity")
SQLITE_AUTHORITY_TRIGGERS = {
    "api_peer_tag_scope_insert_guard",
    "api_peer_tag_scope_update_guard",
    "api_share_peer_scope_insert_guard",
    "api_share_peer_scope_update_guard",
    "api_remotepeer_scope_update_guard",
    "api_remotetag_scope_update_guard",
    "api_sharelink_scope_update_guard",
    "api_abprofile_owner_scope_update_guard",
    "api_strategy_options_insert_guard",
    "api_strategy_options_update_guard",
}


def _historical_auto_models(historical_apps):
    return [
        model
        for model in historical_apps.get_app_config("api").get_models(include_auto_created=True)
        if isinstance(model._meta.pk, models.AutoField)
    ]


class BigintPrimaryKeyMigrationTests(TransactionTestCase):
    def test_forward_reverse_forward_preserves_rows_and_database_authority(self):
        executor = MigrationExecutor(connection)
        try:
            executor.migrate([MIGRATE_FROM])
            old_apps = executor.loader.project_state([MIGRATE_FROM]).apps
            OldLoginAttempt = old_apps.get_model("api", "LoginAttempt")
            existing = OldLoginAttempt.objects.create(ip="192.0.2.20", username="migration-boundary")
            self.assertEqual(OldLoginAttempt._meta.pk.get_internal_type(), "AutoField")
            self._assert_parent_schema()

            executor = MigrationExecutor(connection)
            executor.migrate([MIGRATE_TO])
            current_apps = executor.loader.project_state([MIGRATE_TO]).apps
            auto_models = _historical_auto_models(current_apps)
            self.assertEqual(len(auto_models), 30)
            self.assertTrue(all(model._meta.pk.get_internal_type() == "BigAutoField" for model in auto_models))
            self.assertTrue(current_apps.get_model("api", "LoginAttempt").objects.filter(pk=existing.pk).exists())
            self._assert_bigint_schema()

            executor = MigrationExecutor(connection)
            executor.migrate([MIGRATE_FROM])
            restored_apps = executor.loader.project_state([MIGRATE_FROM]).apps
            restored_auto_types = [
                model._meta.pk.get_internal_type() for model in _historical_auto_models(restored_apps)
            ]
            # The two implicit UserProfile M2M models are reconstructed from
            # the current app default; PostgreSQL's physical parent-schema
            # widths are asserted independently below.
            self.assertEqual(restored_auto_types.count("AutoField"), 27)
            self.assertEqual(restored_auto_types.count("BigAutoField"), 3)
            self.assertTrue(restored_apps.get_model("api", "LoginAttempt").objects.filter(pk=existing.pk).exists())
            self._assert_parent_schema()

            MigrationExecutor(connection).migrate([MIGRATE_TO])
            self._assert_bigint_schema()
        finally:
            restore_latest_migration_state()

    def _assert_parent_schema(self):
        if connection.vendor == "postgresql":
            self.assertEqual(self._postgresql_sequence_widths(), {INTEGER_MAX: 29, BIGINT_MAX: 1})
            self._assert_postgresql_scope_authority("integer")
        else:
            self.assertEqual(self._sqlite_authority_triggers(), SQLITE_AUTHORITY_TRIGGERS)

    def _assert_bigint_schema(self):
        if connection.vendor == "postgresql":
            self.assertEqual(self._postgresql_sequence_widths(), {BIGINT_MAX: 30})
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT table_name, data_type
                    FROM information_schema.columns
                    WHERE table_schema = current_schema()
                      AND table_name IN ('api_userprofile_groups', 'api_userprofile_user_permissions')
                      AND column_name = 'id'
                    ORDER BY table_name
                    """
                )
                self.assertEqual(
                    cursor.fetchall(),
                    [
                        ("api_userprofile_groups", "bigint"),
                        ("api_userprofile_user_permissions", "bigint"),
                    ],
                )
                cursor.execute(
                    """
                    SELECT count(*)
                    FROM pg_constraint AS constraint_row
                    JOIN pg_class AS child ON child.oid = constraint_row.conrelid
                    JOIN LATERAL unnest(constraint_row.conkey, constraint_row.confkey)
                      AS keys(child_attnum, parent_attnum) ON true
                    JOIN pg_attribute AS child_attribute
                      ON child_attribute.attrelid = child.oid
                     AND child_attribute.attnum = keys.child_attnum
                    JOIN pg_attribute AS parent_attribute
                      ON parent_attribute.attrelid = constraint_row.confrelid
                     AND parent_attribute.attnum = keys.parent_attnum
                    WHERE constraint_row.contype = 'f'
                      AND left(child.relname, 4) = 'api_'
                      AND child_attribute.atttypid <> parent_attribute.atttypid
                    """
                )
                self.assertEqual(cursor.fetchone(), (0,))
            self._assert_postgresql_scope_authority("bigint")
        else:
            self.assertEqual(self._sqlite_authority_triggers(), SQLITE_AUTHORITY_TRIGGERS)

    @staticmethod
    def _postgresql_sequence_widths():
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT sequence_parameters.seqmax, count(*)
                FROM pg_class AS sequence_class
                JOIN pg_sequence AS sequence_parameters
                  ON sequence_parameters.seqrelid = sequence_class.oid
                JOIN pg_depend AS dependency
                  ON dependency.objid = sequence_class.oid
                 AND dependency.deptype IN ('a', 'i')
                JOIN pg_class AS table_class ON table_class.oid = dependency.refobjid
                JOIN pg_namespace AS table_namespace ON table_namespace.oid = table_class.relnamespace
                WHERE sequence_class.relkind = 'S'
                  AND table_namespace.nspname = current_schema()
                  AND left(table_class.relname, 4) = 'api_'
                GROUP BY sequence_parameters.seqmax
                """
            )
            return dict(cursor.fetchall())

    def _assert_postgresql_scope_authority(self, integer_type):
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT conname, convalidated, condeferrable, condeferred
                FROM pg_constraint
                WHERE conname IN (
                    'peer_tag_peer_profile_fk',
                    'peer_tag_tag_profile_fk',
                    'share_peer_link_owner_fk',
                    'share_peer_peer_profile_fk',
                    'share_peer_profile_owner_fk'
                )
                ORDER BY conname
                """
            )
            constraints = cursor.fetchall()
            self.assertEqual(len(constraints), 5)
            self.assertTrue(all(row[1:] == (True, True, True) for row in constraints))
            cursor.execute(
                """
                SELECT proname, pg_get_functiondef(oid)
                FROM pg_proc
                WHERE proname IN ('api_fill_peer_tag_scope', 'api_fill_share_peer_scope')
                ORDER BY proname
                """
            )
            functions = cursor.fetchall()
        self.assertEqual(len(functions), 2)
        for _name, definition in functions:
            self.assertIn(f" {integer_type};", definition)

    @staticmethod
    def _sqlite_authority_triggers():
        with connection.cursor() as cursor:
            placeholders = ",".join("%s" for _name in SQLITE_AUTHORITY_TRIGGERS)
            cursor.execute(
                f"SELECT name FROM sqlite_master WHERE type='trigger' AND name IN ({placeholders})",  # noqa: S608
                sorted(SQLITE_AUTHORITY_TRIGGERS),
            )
            return {row[0] for row in cursor.fetchall()}


class PostgreSQLBigintBoundaryTests(TransactionTestCase):
    def setUp(self):
        super().setUp()
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL sequence-width test")

    def test_retention_and_concurrent_inserts_cross_integer_boundary(self):
        self._set_sequence("api_loginattempt", INTEGER_MAX - 1)
        first = LoginAttempt.objects.create(ip="192.0.2.30", username="before-boundary")
        LoginAttempt.objects.all().delete()
        self.assertEqual(first.pk, INTEGER_MAX)

        barrier = threading.Barrier(3)
        results = queue.Queue()

        def insert(ip):
            close_old_connections()
            try:
                barrier.wait(timeout=5)
                results.put(LoginAttempt.objects.create(ip=ip, username="concurrent-boundary").pk)
            except (DatabaseError, threading.BrokenBarrierError) as exc:  # pragma: no cover - parent asserts
                results.put(exc)
            finally:
                close_old_connections()

        workers = [
            threading.Thread(target=insert, args=("192.0.2.31",)),
            threading.Thread(target=insert, args=("192.0.2.32",)),
        ]
        for worker in workers:
            worker.start()
        barrier.wait(timeout=5)
        for worker in workers:
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())

        inserted = {results.get_nowait(), results.get_nowait()}
        self.assertEqual(inserted, {1 << 31, (1 << 31) + 1})

    def test_scope_triggers_m2m_and_serialization_accept_high_ids(self):
        high_tables = (
            "api_userprofile",
            "api_addressbookprofile",
            "api_remotepeer",
            "api_remotetag",
            "api_remotepeer_tags",
            "api_sharelink",
            "api_sharelink_peers",
            "api_userprofile_groups",
            "api_userprofile_user_permissions",
        )
        for table_name in high_tables:
            self._set_sequence(table_name, INTEGER_MAX)

        owner = UserProfile.objects.create(username="bigint-test-owner")
        profile = AddressBookProfile.objects.create(guid="bigint-test-profile", name="BigInt test", owner=owner)
        peer = RemotePeer.objects.create(profile=profile, rid="bigint-test-peer")
        tag = RemoteTag.objects.create(profile=profile, tag_name="BigInt test tag")
        peer.tags.add(tag)
        link = ShareLink.objects.create(
            creator=owner,
            shash="b" * 64,
            token_prefix="bigint-test",  # noqa: S106 - non-secret test prefix
        )
        link.peers.add(peer)
        group = Group.objects.create(name="bigint-test-group")
        permission = Permission.objects.order_by("pk").first()
        owner.groups.add(group)
        owner.user_permissions.add(permission)

        peer_tag = RemotePeer.tags.through.objects.get()
        share_peer = ShareLink.peers.through.objects.get()
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM api_userprofile_groups WHERE userprofile_id=%s", [owner.pk])
            group_edge_id = cursor.fetchone()[0]
            cursor.execute("SELECT id FROM api_userprofile_user_permissions WHERE userprofile_id=%s", [owner.pk])
            permission_edge_id = cursor.fetchone()[0]
        identifiers = (
            owner.pk,
            profile.pk,
            peer.pk,
            tag.pk,
            peer_tag.pk,
            link.pk,
            share_peer.pk,
            group_edge_id,
            permission_edge_id,
        )
        self.assertTrue(all(identifier > INTEGER_MAX for identifier in identifiers))
        self.assertEqual(peer_tag.profile_id, profile.pk)
        self.assertEqual(share_peer.profile_id, profile.pk)
        self.assertEqual(share_peer.owner_id, owner.pk)
        self.assertEqual(json.loads(serializers.serialize("json", [owner]))[0]["pk"], owner.pk)

        with self.assertRaisesRegex(RuntimeError, "cannot narrow api_userprofile_groups.id"):
            MigrationExecutor(connection).migrate([MIGRATE_FROM])

    @staticmethod
    def _set_sequence(table_name, value):
        with connection.cursor() as cursor:
            cursor.execute("SELECT setval(pg_get_serial_sequence(%s, 'id'), %s, true)", [table_name, value])
