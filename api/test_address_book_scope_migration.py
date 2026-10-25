from django.contrib.auth.hashers import make_password
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

from api.migration_test_support import restore_latest_migration_state


class AddressBookScopeMigrationTests(TransactionTestCase):
    migrate_from = ("api", "0026_username_canonical_identity")
    migrate_to = ("api", "0027_address_book_scope_authority")

    def test_pollution_is_reported_and_clean_relationships_gain_reversible_scope_authority(self):
        executor = MigrationExecutor(connection)
        try:
            executor.migrate([self.migrate_from])
            old_apps = executor.loader.project_state([self.migrate_from]).apps
            User = old_apps.get_model("api", "UserProfile")
            Profile = old_apps.get_model("api", "AddressBookProfile")
            Peer = old_apps.get_model("api", "RemotePeer")
            Tag = old_apps.get_model("api", "RemoteTag")
            Link = old_apps.get_model("api", "ShareLink")
            PeerTag = Peer.tags.through
            LinkPeer = Link.peers.through

            owner = User.objects.create(
                username="migration-owner",
                username_canonical=b"migration-owner",
                password=make_password(None),
            )
            other_owner = User.objects.create(
                username="migration-other",
                username_canonical=b"migration-other",
                password=make_password(None),
            )
            profile = Profile.objects.create(owner=owner, guid="migration-profile", name="Migration profile")
            other_profile = Profile.objects.create(
                owner=other_owner,
                guid="migration-other-profile",
                name="Migration other profile",
            )
            peer = Peer.objects.create(profile=profile, rid="migration-peer")
            other_peer = Peer.objects.create(profile=other_profile, rid="mig-other-peer")
            tag = Tag.objects.create(profile=profile, tag_name="migration-tag")
            other_tag = Tag.objects.create(profile=other_profile, tag_name="migration-other-tag")
            legal_peer_tag = PeerTag.objects.create(remotepeer=peer, remotetag=tag)
            polluted_peer_tag = PeerTag.objects.create(remotepeer=peer, remotetag=other_tag)

            link = Link.objects.create(
                creator=owner,
                shash="a" * 64,
                token_prefix=f"migration-{owner.pk}"[:12],
            )
            legal_link_peer = LinkPeer.objects.create(sharelink=link, remotepeer=peer)
            polluted_link_peer = LinkPeer.objects.create(sharelink=link, remotepeer=other_peer)

            with self.assertRaises(RuntimeError) as captured:
                MigrationExecutor(connection).migrate([self.migrate_to])
            message = str(captured.exception)
            self.assertIn(f"peer_tag_ids={polluted_peer_tag.pk}", message)
            self.assertIn(f"share_peer_ids={polluted_link_peer.pk}", message)
            self.assertNotIn(owner.username, message)
            self.assertNotIn(other_owner.username, message)
            self.assertTrue(PeerTag.objects.filter(pk=polluted_peer_tag.pk).exists())
            self.assertTrue(LinkPeer.objects.filter(pk=polluted_link_peer.pk).exists())

            PeerTag.objects.filter(pk=polluted_peer_tag.pk).delete()
            LinkPeer.objects.filter(pk=polluted_link_peer.pk).delete()
            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_to])
            current_apps = executor.loader.project_state([self.migrate_to]).apps
            ScopedPeerTag = current_apps.get_model("api", "RemotePeerTagMembership")
            ScopedLinkPeer = current_apps.get_model("api", "ShareLinkPeerMembership")
            self.assertEqual(ScopedPeerTag.objects.get(pk=legal_peer_tag.pk).profile_id, profile.pk)
            scoped_link_peer = ScopedLinkPeer.objects.get(pk=legal_link_peer.pk)
            self.assertEqual(scoped_link_peer.profile_id, profile.pk)
            self.assertEqual(scoped_link_peer.owner_id, owner.pk)
            self._assert_database_authority()

            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_from])
            restored_apps = executor.loader.project_state([self.migrate_from]).apps
            RestoredPeer = restored_apps.get_model("api", "RemotePeer")
            RestoredLink = restored_apps.get_model("api", "ShareLink")
            self.assertTrue(RestoredPeer.tags.through.objects.filter(pk=legal_peer_tag.pk).exists())
            self.assertTrue(RestoredLink.peers.through.objects.filter(pk=legal_link_peer.pk).exists())
            with connection.cursor() as cursor:
                peer_tag_columns = {
                    column.name
                    for column in connection.introspection.get_table_description(cursor, "api_remotepeer_tags")
                }
                share_peer_columns = {
                    column.name
                    for column in connection.introspection.get_table_description(cursor, "api_sharelink_peers")
                }
            self.assertNotIn("profile_id", peer_tag_columns)
            self.assertNotIn("profile_id", share_peer_columns)
            self.assertNotIn("owner_id", share_peer_columns)

            MigrationExecutor(connection).migrate([self.migrate_to])
        finally:
            restore_latest_migration_state()

    def _assert_database_authority(self):
        with connection.cursor() as cursor:
            peer_tag_constraints = connection.introspection.get_constraints(cursor, "api_remotepeer_tags")
            share_peer_constraints = connection.introspection.get_constraints(cursor, "api_sharelink_peers")
        if connection.vendor == "postgresql":
            self.assertIn("peer_tag_peer_profile_fk", peer_tag_constraints)
            self.assertIn("peer_tag_tag_profile_fk", peer_tag_constraints)
            for name in (
                "share_peer_link_owner_fk",
                "share_peer_peer_profile_fk",
                "share_peer_profile_owner_fk",
            ):
                self.assertIn(name, share_peer_constraints)
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT conname, condeferrable, condeferred, convalidated
                    FROM pg_constraint
                    WHERE conname IN (
                        'peer_tag_peer_profile_fk',
                        'peer_tag_tag_profile_fk',
                        'share_peer_link_owner_fk',
                        'share_peer_peer_profile_fk',
                        'share_peer_profile_owner_fk'
                    )
                    """
                )
                constraints = {row[0]: row[1:] for row in cursor.fetchall()}
                cursor.execute(
                    """
                    SELECT table_name, column_name, is_nullable
                    FROM information_schema.columns
                    WHERE table_schema = current_schema()
                      AND (
                        (table_name = 'api_remotepeer_tags' AND column_name = 'profile_id')
                        OR (
                            table_name = 'api_sharelink_peers'
                            AND column_name IN ('profile_id', 'owner_id')
                        )
                      )
                    """
                )
                nullability = {(row[0], row[1]): row[2] for row in cursor.fetchall()}
            self.assertEqual(len(constraints), 5)
            self.assertTrue(all(flags == (True, True, True) for flags in constraints.values()))
            self.assertEqual(
                nullability,
                {
                    ("api_remotepeer_tags", "profile_id"): "NO",
                    ("api_sharelink_peers", "profile_id"): "NO",
                    ("api_sharelink_peers", "owner_id"): "NO",
                },
            )
        else:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'trigger'
                      AND name IN (
                        'api_peer_tag_scope_insert_guard',
                        'api_peer_tag_scope_update_guard',
                        'api_share_peer_scope_insert_guard',
                        'api_share_peer_scope_update_guard',
                        'api_remotepeer_scope_update_guard',
                        'api_remotetag_scope_update_guard',
                        'api_sharelink_scope_update_guard',
                        'api_abprofile_owner_scope_update_guard'
                      )
                    """
                )
                triggers = {row[0] for row in cursor.fetchall()}
            self.assertEqual(len(triggers), 8)
