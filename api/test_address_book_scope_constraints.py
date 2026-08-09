import queue
import threading

from django.core.exceptions import ValidationError
from django.db import IntegrityError, close_old_connections, connection, models, transaction
from django.test import TestCase, TransactionTestCase

from api.models import AddressBookProfile, RemotePeer, RemoteTag, ShareLink, UserProfile
from api.views_front import _rename_tag


def _through_relation_kwargs(through_model, *instances):
    by_model = {type(instance): instance for instance in instances}
    values = {}
    for field in through_model._meta.fields:
        if not isinstance(field, models.ForeignKey):
            continue
        instance = by_model.get(field.remote_field.model)
        if instance is not None:
            values[f"{field.name}_id"] = instance.pk
    return values


def _force_deferred_constraints():
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")


class AddressBookScopeConstraintTests(TestCase):
    def setUp(self):
        self.owner = UserProfile.objects.create_user(username="scope-owner")
        self.other_owner = UserProfile.objects.create_user(username="scope-other")
        self.profile = AddressBookProfile.objects.create(
            owner=self.owner,
            guid="scope-profile",
            name="Scope profile",
        )
        self.other_profile = AddressBookProfile.objects.create(
            owner=self.other_owner,
            guid="scope-other-profile",
            name="Other scope profile",
        )
        self.peer = RemotePeer.objects.create(profile=self.profile, rid="scope-peer")
        self.other_peer = RemotePeer.objects.create(profile=self.other_profile, rid="scope-other-peer")
        self.tag = RemoteTag.objects.create(profile=self.profile, tag_name="scope-tag")
        self.other_tag = RemoteTag.objects.create(profile=self.other_profile, tag_name="scope-other-tag")

    def test_explicit_peer_tag_through_rejects_cross_profile_create(self):
        through = RemotePeer.tags.through
        with self.assertRaises((ValidationError, IntegrityError)):
            with transaction.atomic():
                through.objects.create(
                    **_through_relation_kwargs(through, self.peer, self.other_tag),
                )

    def test_explicit_share_link_through_rejects_cross_owner_create(self):
        link = ShareLink.objects.create(
            creator=self.owner,
            shash="1" * 64,
            token_prefix=f"scope-{self.owner.pk}",
        )
        through = ShareLink.peers.through
        with self.assertRaises((ValidationError, IntegrityError)):
            with transaction.atomic():
                through.objects.create(
                    **_through_relation_kwargs(through, link, self.other_peer),
                )

    def test_normal_many_to_many_writes_persist_authoritative_scope(self):
        self.peer.tags.set([self.tag])
        peer_tag = RemotePeer.tags.through.objects.get()
        self.assertEqual(peer_tag.profile_id, self.profile.pk)

        link = ShareLink.objects.create(
            creator=self.owner,
            shash="2" * 64,
            token_prefix=f"scope-{self.owner.pk}",
        )
        link.peers.set([self.peer])
        link_peer = ShareLink.peers.through.objects.get()
        self.assertEqual(link_peer.profile_id, self.profile.pk)
        self.assertEqual(link_peer.owner_id, self.owner.pk)

    def test_parent_deletes_cascade_authoritative_memberships(self):
        self.peer.tags.add(self.tag)
        link = ShareLink.objects.create(
            creator=self.owner,
            shash="9" * 64,
            token_prefix=f"scope-{self.owner.pk}",
        )
        link.peers.add(self.peer)

        self.peer.delete()

        self.assertFalse(RemotePeer.tags.through.objects.exists())
        self.assertFalse(ShareLink.peers.through.objects.exists())
        self.assertTrue(ShareLink.objects.filter(pk=link.pk).exists())

    def test_owner_transfer_invalidates_links_that_reference_the_profile(self):
        link = ShareLink.objects.create(
            creator=self.owner,
            shash="3" * 64,
            token_prefix=f"scope-{self.owner.pk}",
        )
        link.peers.add(self.peer)

        self.profile.owner = self.other_owner
        self.profile.save(update_fields=("owner", "updated_at"))

        self.assertFalse(ShareLink.objects.filter(pk=link.pk).exists())

    def test_tag_merge_preserves_the_authoritative_membership_scope(self):
        source_tag = RemoteTag.objects.create(
            profile=self.profile,
            tag_name="scope-source-tag",
        )
        self.peer.tags.add(source_tag)

        self.assertTrue(
            _rename_tag(
                self.owner,
                self.profile,
                source_tag.tag_name,
                self.tag.tag_name,
            )
        )

        self.assertFalse(RemoteTag.objects.filter(pk=source_tag.pk).exists())
        membership = RemotePeer.tags.through.objects.get(
            peer_id=self.peer.pk,
            tag_id=self.tag.pk,
        )
        self.assertEqual(membership.profile_id, self.profile.pk)

    def test_bulk_and_raw_writes_cannot_bypass_scope_authority(self):
        peer_tag_through = RemotePeer.tags.through
        valid_peer_tag_values = _through_relation_kwargs(peer_tag_through, self.peer, self.tag)
        peer_tag_through.objects.bulk_create([peer_tag_through(**valid_peer_tag_values)])
        self.assertEqual(peer_tag_through.objects.get().profile_id, self.profile.pk)

        peer_tag_values = _through_relation_kwargs(peer_tag_through, self.peer, self.other_tag)
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                peer_tag_through.objects.bulk_create([peer_tag_through(**peer_tag_values)])

        link = ShareLink.objects.create(
            creator=self.owner,
            shash="4" * 64,
            token_prefix=f"scope-{self.owner.pk}",
        )
        link_peer_through = ShareLink.peers.through
        valid_link_peer_values = _through_relation_kwargs(link_peer_through, link, self.peer)
        link_peer_through.objects.bulk_create([link_peer_through(**valid_link_peer_values)])
        valid_link_peer = link_peer_through.objects.get()
        self.assertEqual(valid_link_peer.profile_id, self.profile.pk)
        self.assertEqual(valid_link_peer.owner_id, self.owner.pk)

        link_peer_values = _through_relation_kwargs(link_peer_through, link, self.other_peer)
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                link_peer_through.objects.bulk_create([link_peer_through(**link_peer_values)])

        self.assertEqual(peer_tag_through._meta.db_table, "api_remotepeer_tags")
        with self.assertRaises(IntegrityError):
            with transaction.atomic(), connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO api_remotepeer_tags (remotepeer_id, remotetag_id) VALUES (%s, %s)",
                    [self.peer.pk, self.other_tag.pk],
                )

        self.assertEqual(link_peer_through._meta.db_table, "api_sharelink_peers")
        with self.assertRaises(IntegrityError):
            with transaction.atomic(), connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO api_sharelink_peers (sharelink_id, remotepeer_id) VALUES (%s, %s)",
                    [link.pk, self.other_peer.pk],
                )

    def test_reverse_many_to_many_writes_persist_authoritative_scope(self):
        self.tag.peers.add(self.peer)
        peer_tag = RemotePeer.tags.through.objects.get()
        self.assertEqual(peer_tag.profile_id, self.profile.pk)

        link = ShareLink.objects.create(
            creator=self.owner,
            shash="5" * 64,
            token_prefix=f"scope-{self.owner.pk}",
        )
        self.peer.share_links.add(link)
        link_peer = ShareLink.peers.through.objects.get()
        self.assertEqual(link_peer.profile_id, self.profile.pk)
        self.assertEqual(link_peer.owner_id, self.owner.pk)

    def test_parent_scope_updates_cannot_leave_stale_memberships(self):
        self.peer.tags.add(self.tag)
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                RemotePeer.objects.filter(pk=self.peer.pk).update(profile=self.other_profile)
                _force_deferred_constraints()
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                RemoteTag.objects.filter(pk=self.tag.pk).update(profile=self.other_profile)
                _force_deferred_constraints()

        link = ShareLink.objects.create(
            creator=self.owner,
            shash="6" * 64,
            token_prefix=f"scope-{self.owner.pk}",
        )
        link.peers.add(self.peer)
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ShareLink.objects.filter(pk=link.pk).update(creator=self.other_owner)
                _force_deferred_constraints()
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                AddressBookProfile.objects.filter(pk=self.profile.pk).update(owner=self.other_owner)
                _force_deferred_constraints()

    def test_peer_cannot_move_between_same_owner_profiles_with_a_share_membership(self):
        same_owner_profile = AddressBookProfile.objects.create(
            owner=self.owner,
            guid="scope-same-owner-profile",
            name="Same owner scope profile",
        )
        link = ShareLink.objects.create(
            creator=self.owner,
            shash="8" * 64,
            token_prefix=f"scope-{self.owner.pk}",
        )
        link.peers.add(self.peer)

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                RemotePeer.objects.filter(pk=self.peer.pk).update(profile=same_owner_profile)
                _force_deferred_constraints()

        membership = ShareLink.peers.through.objects.get(
            share_link_id=link.pk,
            peer_id=self.peer.pk,
        )
        self.assertEqual(membership.profile_id, self.profile.pk)
        self.assertEqual(membership.owner_id, self.owner.pk)


class AddressBookScopeConcurrencyTests(TransactionTestCase):
    def setUp(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL locking is the production concurrency authority")
        self.owner = UserProfile.objects.create_user(username="concurrent-owner")
        self.other_owner = UserProfile.objects.create_user(username="concurrent-other")
        self.profile = AddressBookProfile.objects.create(
            owner=self.owner,
            guid="concurrent-profile",
            name="Concurrent profile",
        )
        self.other_profile = AddressBookProfile.objects.create(
            owner=self.other_owner,
            guid="concurrent-other-profile",
            name="Concurrent other profile",
        )
        self.peer = RemotePeer.objects.create(profile=self.profile, rid="concurrent-peer")
        self.tag = RemoteTag.objects.create(profile=self.profile, tag_name="concurrent-tag")

    def test_owner_transfer_serializes_with_share_membership_creation(self):
        link = ShareLink.objects.create(
            creator=self.owner,
            shash="7" * 64,
            token_prefix=f"scope-{self.owner.pk}",
        )
        membership_locked = threading.Event()
        release_membership = threading.Event()
        transfer_started = threading.Event()
        failures = queue.Queue()

        def add_membership():
            close_old_connections()
            try:
                with transaction.atomic():
                    current_link = ShareLink.objects.get(pk=link.pk)
                    current_link.peers.add(RemotePeer.objects.get(pk=self.peer.pk))
                    membership_locked.set()
                    if not release_membership.wait(10):
                        raise TimeoutError("membership release timed out")
            except Exception as exc:  # noqa: BLE001
                failures.put(("membership", repr(exc)))
            finally:
                close_old_connections()

        def transfer_owner():
            close_old_connections()
            try:
                if not membership_locked.wait(10):
                    raise TimeoutError("membership lock was not acquired")
                transfer_started.set()
                profile = AddressBookProfile.objects.get(pk=self.profile.pk)
                profile.owner = UserProfile.objects.get(pk=self.other_owner.pk)
                profile.save(update_fields=("owner", "updated_at"))
            except Exception as exc:  # noqa: BLE001
                failures.put(("transfer", repr(exc)))
            finally:
                close_old_connections()

        membership_thread = threading.Thread(target=add_membership)
        transfer_thread = threading.Thread(target=transfer_owner)
        membership_thread.start()
        transfer_thread.start()
        self.assertTrue(membership_locked.wait(10), "membership transaction did not acquire the profile lock")
        self.assertTrue(transfer_started.wait(10), "owner transfer did not reach the profile lock")
        release_membership.set()
        membership_thread.join(10)
        transfer_thread.join(10)
        self.assertFalse(membership_thread.is_alive(), "membership transaction deadlocked")
        self.assertFalse(transfer_thread.is_alive(), "owner transfer deadlocked")
        self.assertTrue(failures.empty(), list(failures.queue))

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.owner_id, self.other_owner.pk)
        self.assertFalse(ShareLink.objects.filter(pk=link.pk).exists())

    def test_tag_move_racing_a_membership_insert_fails_at_the_database_boundary(self):
        membership_locked = threading.Event()
        release_membership = threading.Event()
        move_started = threading.Event()
        outcomes = queue.Queue()

        def add_membership():
            close_old_connections()
            try:
                with transaction.atomic():
                    RemotePeer.objects.get(pk=self.peer.pk).tags.add(RemoteTag.objects.get(pk=self.tag.pk))
                    membership_locked.set()
                    if not release_membership.wait(10):
                        raise TimeoutError("membership release timed out")
            except Exception as exc:  # noqa: BLE001
                outcomes.put(("membership-error", repr(exc)))
            finally:
                close_old_connections()

        def move_tag():
            close_old_connections()
            try:
                if not membership_locked.wait(10):
                    raise TimeoutError("membership lock was not acquired")
                move_started.set()
                with transaction.atomic():
                    RemoteTag.objects.filter(pk=self.tag.pk).update(profile_id=self.other_profile.pk)
                    _force_deferred_constraints()
            except IntegrityError:
                outcomes.put(("move-rejected", "integrity"))
            except Exception as exc:  # noqa: BLE001
                outcomes.put(("move-error", repr(exc)))
            finally:
                close_old_connections()

        membership_thread = threading.Thread(target=add_membership)
        move_thread = threading.Thread(target=move_tag)
        membership_thread.start()
        move_thread.start()
        self.assertTrue(membership_locked.wait(10), "membership transaction did not lock the tag")
        self.assertTrue(move_started.wait(10), "tag move did not reach the database boundary")
        release_membership.set()
        membership_thread.join(10)
        move_thread.join(10)
        self.assertFalse(membership_thread.is_alive(), "membership transaction deadlocked")
        self.assertFalse(move_thread.is_alive(), "tag move deadlocked")
        self.assertEqual(list(outcomes.queue), [("move-rejected", "integrity")])

        self.tag.refresh_from_db()
        self.assertEqual(self.tag.profile_id, self.profile.pk)
        membership = RemotePeer.tags.through.objects.get(peer_id=self.peer.pk, tag_id=self.tag.pk)
        self.assertEqual(membership.profile_id, self.profile.pk)
