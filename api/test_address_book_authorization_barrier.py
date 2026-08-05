import json
import queue
import threading
import time
from unittest.mock import patch

from django.contrib import admin
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection, transaction
from django.test import Client, RequestFactory, TestCase, TransactionTestCase, skipUnlessDBFeature

from api.address_book_authorization import bump_locked_authorization_generation, lock_profile_access
from api.admin_user import AddressBookProfileAdmin, AddressBookRuleAdmin, AddressBookShareAdmin
from api.models import (
    AddressBookProfile,
    AddressBookRule,
    AddressBookShare,
    RemoteDevice,
    RemotePeer,
    UserProfile,
)
from api.views_api import _issue_access_token
from api.views_front import _apply_rule_change


class AddressBookAuthorizationBarrierTests(TestCase):
    def setUp(self):
        self.owner = UserProfile.objects.create_user(username="owner")
        self.writer = UserProfile.objects.create_user(username="writer")
        self.new_owner = UserProfile.objects.create_user(username="new-owner")
        self.profile = AddressBookProfile.objects.create(
            guid="authorization-barrier-book",
            name="Authorization barrier",
            owner=self.owner,
            rule=3,
        )
        self.peer = RemotePeer.objects.create(
            profile=self.profile,
            rid="765432100",
            alias="before",
        )

    def _bearer_for(self, user, rid):
        device = RemoteDevice.objects.create(
            rid=rid,
            cpu="-",
            hostname="test-device",
            memory="-",
            os="linux",
            uuid=f"uuid-{rid}",
            username="",
            version="test",
            owner=user,
        )
        return _issue_access_token(user, device)[1]

    @staticmethod
    def _authorization(token):
        return {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    def test_api_rechecks_direct_grant_after_revocation_before_peer_update(self):
        share = AddressBookShare.objects.create(profile=self.profile, user=self.writer, rule=2)
        token = self._bearer_for(self.writer, "810000001")
        from api import views_api

        original = views_api._get_profile_access
        revoked = False

        def revoke_after_initial_check(user, guid):
            nonlocal revoked
            result = original(user, guid)
            if not revoked:
                AddressBookShare.objects.filter(pk=share.pk).delete()
                revoked = True
            return result

        with patch("api.views_api._get_profile_access", side_effect=revoke_after_initial_check):
            response = Client().put(
                f"/api/ab/peer/update/{self.profile.guid}",
                data=json.dumps({"id": self.peer.rid, "alias": "api-after-revoke"}),
                content_type="application/json",
                **self._authorization(token),
            )

        self.peer.refresh_from_db()
        self.assertEqual(response.status_code, 403, response.content)
        self.assertEqual(self.peer.alias, "before")
        self.assertFalse(AddressBookShare.objects.filter(pk=share.pk).exists())

    def test_web_rechecks_group_membership_after_revocation_before_peer_update(self):
        group = Group.objects.create(name="writers")
        self.writer.groups.add(group)
        AddressBookRule.objects.create(profile=self.profile, group=group, rule=2)
        from api import views_front

        original = views_front._get_profile_access_web
        revoked = False

        def revoke_after_initial_check(user, guid):
            nonlocal revoked
            result = original(user, guid)
            if not revoked:
                self.writer.groups.remove(group)
                revoked = True
            return result

        client = Client()
        client.force_login(self.writer)
        with patch("api.views_front._get_profile_access_web", side_effect=revoke_after_initial_check):
            response = client.post(
                f"/api/ab_book?guid={self.profile.guid}",
                {
                    "action": "update_peer",
                    "guid": self.profile.guid,
                    "rid": self.peer.rid,
                    "alias": "web-after-revoke",
                    "note": "",
                    "password": "",
                    "tags": "",
                },
            )

        self.peer.refresh_from_db()
        self.assertEqual(response.status_code, 302, response.content)
        self.assertEqual(self.peer.alias, "before")
        self.assertFalse(self.writer.groups.filter(pk=group.pk).exists())

    def test_api_rechecks_owner_after_transfer_before_peer_update(self):
        token = self._bearer_for(self.owner, "810000002")
        from api import views_api

        original = views_api._get_profile_access
        transferred = False

        def transfer_after_initial_check(user, guid):
            nonlocal transferred
            result = original(user, guid)
            if not transferred:
                AddressBookProfile.objects.filter(pk=self.profile.pk).update(owner=self.new_owner)
                transferred = True
            return result

        with patch("api.views_api._get_profile_access", side_effect=transfer_after_initial_check):
            response = Client().put(
                f"/api/ab/peer/update/{self.profile.guid}",
                data=json.dumps({"id": self.peer.rid, "alias": "api-after-transfer"}),
                content_type="application/json",
                **self._authorization(token),
            )

        self.peer.refresh_from_db()
        self.profile.refresh_from_db()
        self.assertEqual(response.status_code, 403, response.content)
        self.assertEqual(self.peer.alias, "before")
        self.assertEqual(self.profile.owner_id, self.new_owner.id)

    def test_stale_web_rule_instance_cannot_resurrect_a_deleted_share(self):
        share = AddressBookShare.objects.create(profile=self.profile, user=self.writer, rule=2)
        from api import views_front

        original = views_front._lock_profile_for_management
        removed = False

        def delete_before_authority_lock(user, profile):
            nonlocal removed
            if not removed:
                AddressBookShare.objects.filter(pk=share.pk).delete()
                removed = True
            return original(user, profile)

        request = RequestFactory().post("/api/ab_manage")
        request.user = self.owner
        with patch(
            "api.views_front._lock_profile_for_management",
            side_effect=delete_before_authority_lock,
        ):
            changed, _message = _apply_rule_change(
                request,
                self.owner,
                "update_rule",
                str(share.guid),
                3,
            )

        self.assertFalse(changed)
        self.assertFalse(AddressBookShare.objects.filter(pk=share.pk).exists())

    def test_group_membership_change_advances_profile_authorization_generation(self):
        group = Group.objects.create(name="generation-writers")
        self.writer.groups.add(group)
        AddressBookRule.objects.create(profile=self.profile, group=group, rule=2)
        self.profile.refresh_from_db()
        before = self.profile.authorization_generation

        self.writer.groups.remove(group)

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.authorization_generation, before + 1)
        self.assertFalse(self.writer.groups.filter(pk=group.pk).exists())

    def test_generation_exhaustion_rolls_back_group_membership_revocation(self):
        group = Group.objects.create(name="exhausted-writers")
        self.writer.groups.add(group)
        AddressBookRule.objects.create(profile=self.profile, group=group, rule=2)
        AddressBookProfile.objects.filter(pk=self.profile.pk).update(authorization_generation=(1 << 63) - 1)

        with self.assertRaises(OverflowError):
            with transaction.atomic():
                self.writer.groups.remove(group)

        self.assertTrue(self.writer.groups.filter(pk=group.pk).exists())

    def test_reverse_group_clear_advances_profile_authorization_generation(self):
        group = Group.objects.create(name="reverse-clear-writers")
        self.writer.groups.add(group)
        AddressBookRule.objects.create(profile=self.profile, group=group, rule=2)
        self.profile.refresh_from_db()
        before = self.profile.authorization_generation

        group.user_set.clear()

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.authorization_generation, before + 1)
        self.assertFalse(self.writer.groups.filter(pk=group.pk).exists())

    def test_group_add_and_forward_clear_each_advance_generation_once(self):
        first_group = Group.objects.create(name="forward-clear-writers-one")
        second_group = Group.objects.create(name="forward-clear-writers-two")
        AddressBookRule.objects.create(profile=self.profile, group=first_group, rule=2)
        AddressBookRule.objects.create(profile=self.profile, group=second_group, rule=2)

        self.writer.groups.add(first_group, second_group)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.authorization_generation, 1)

        self.writer.groups.clear()
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.authorization_generation, 2)
        self.assertFalse(self.writer.groups.exists())

    def test_group_delete_uses_profile_authority_and_advances_generation(self):
        group = Group.objects.create(name="deleted-authorization-group")
        rule = AddressBookRule.objects.create(profile=self.profile, group=group, rule=2)

        group.delete()

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.authorization_generation, 1)
        self.assertFalse(AddressBookRule.objects.filter(pk=rule.pk).exists())

    def test_acl_mutations_advance_generation_and_record_the_committed_value(self):
        token = self._bearer_for(self.owner, "810000004")
        client = Client()

        added = client.post(
            "/api/ab/rule",
            data=json.dumps({"guid": self.profile.guid, "user": self.writer.username, "rule": 2}),
            content_type="application/json",
            **self._authorization(token),
        )
        self.assertEqual(added.status_code, 200, added.content)
        rule_guid = str(added.json()["guid"])
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.authorization_generation, 1)
        self.assertEqual(
            self.profile.rule_audits.latest("pk").details["authorization_generation"],
            1,
        )

        updated = client.patch(
            "/api/ab/rule",
            data=json.dumps({"guid": rule_guid, "rule": 3}),
            content_type="application/json",
            **self._authorization(token),
        )
        self.assertEqual(updated.status_code, 200, updated.content)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.authorization_generation, 2)
        self.assertEqual(
            self.profile.rule_audits.latest("pk").details["authorization_generation"],
            2,
        )

        deleted = client.delete(
            "/api/ab/rules",
            data=json.dumps([rule_guid]),
            content_type="application/json",
            **self._authorization(token),
        )
        self.assertEqual(deleted.status_code, 200, deleted.content)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.authorization_generation, 3)
        self.assertEqual(
            self.profile.rule_audits.latest("pk").details["authorization_generation"],
            3,
        )

    def test_stale_profile_cannot_move_authorization_generation_backward(self):
        stale = AddressBookProfile.objects.get(pk=self.profile.pk)
        with transaction.atomic():
            locked = AddressBookProfile.objects.select_for_update().get(pk=self.profile.pk)
            bump_locked_authorization_generation(locked)

        stale.authorization_generation = 0
        with self.assertRaises(ValueError):
            stale.save(update_fields=("authorization_generation",))

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.authorization_generation, 1)

        stale.authorization_generation = 0
        with self.assertRaises(ValueError):
            with transaction.atomic():
                bump_locked_authorization_generation(stale)

        self.profile.refresh_from_db()
        self.assertEqual(self.profile.authorization_generation, 1)

    def test_owner_transfer_generation_exhaustion_returns_conflict_and_rolls_back(self):
        admin_user = UserProfile.objects.create_user(username="generation-admin", is_admin=True)
        token = self._bearer_for(admin_user, "810000003")
        AddressBookProfile.objects.filter(pk=self.profile.pk).update(authorization_generation=(1 << 63) - 1)

        response = Client().put(
            "/api/ab/shared/update/profile",
            data=json.dumps({"guid": self.profile.guid, "owner": self.new_owner.username}),
            content_type="application/json",
            **self._authorization(token),
        )

        self.profile.refresh_from_db()
        self.assertEqual(response.status_code, 409, response.content)
        self.assertEqual(
            response.json(),
            {"error": "Address-book authorization generation exhausted"},
        )
        self.assertEqual(self.profile.owner_id, self.owner.pk)
        self.assertEqual(self.profile.authorization_generation, (1 << 63) - 1)

    def test_admin_stale_instances_cannot_resurrect_deleted_authority_rows(self):
        request = RequestFactory().post("/admin/api/addressbookshare/")
        request.user = self.owner
        share = AddressBookShare.objects.create(profile=self.profile, user=self.writer, rule=2)
        rule = AddressBookRule.objects.create(profile=self.profile, is_everyone=True, rule=2)
        stale_profile = AddressBookProfile.objects.get(pk=self.profile.pk)
        stale_share = AddressBookShare.objects.get(pk=share.pk)
        stale_rule = AddressBookRule.objects.get(pk=rule.pk)
        AddressBookShare.objects.filter(pk=share.pk).delete()
        AddressBookRule.objects.filter(pk=rule.pk).delete()

        with self.assertRaises(ValidationError):
            AddressBookShareAdmin(AddressBookShare, admin.site).save_model(
                request,
                stale_share,
                form=None,
                change=True,
            )

        self.assertFalse(AddressBookShare.objects.filter(pk=share.pk).exists())
        with self.assertRaises(ValidationError):
            AddressBookRuleAdmin(AddressBookRule, admin.site).save_model(
                request,
                stale_rule,
                form=None,
                change=True,
            )
        self.assertFalse(AddressBookRule.objects.filter(pk=rule.pk).exists())
        AddressBookProfile.objects.filter(pk=self.profile.pk).delete()
        with self.assertRaises(ValidationError):
            AddressBookProfileAdmin(AddressBookProfile, admin.site).save_model(
                request,
                stale_profile,
                form=None,
                change=True,
            )
        self.assertFalse(AddressBookProfile.objects.filter(pk=self.profile.pk).exists())


class PostgreSQLAddressBookAuthorizationBarrierTests(TransactionTestCase):
    def setUp(self):
        self.owner = UserProfile.objects.create_user(username="pg-owner")
        self.writer = UserProfile.objects.create_user(username="pg-writer")
        self.new_owner = UserProfile.objects.create_user(username="pg-new-owner")
        self.profile = AddressBookProfile.objects.create(
            guid="postgres-authorization-barrier",
            name="PostgreSQL authorization barrier",
            owner=self.owner,
            rule=3,
        )
        self.peer = RemotePeer.objects.create(profile=self.profile, rid="765432101", alias="before")

    def _wait_until_backend_is_blocked(self, backend_pid):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT wait_event_type FROM pg_stat_activity WHERE pid = %s",
                    (backend_pid,),
                )
                row = cursor.fetchone()
            if row and row[0] == "Lock":
                return
            time.sleep(0.01)
        self.fail(f"backend {backend_pid} did not block on the profile authority lock")

    @staticmethod
    def _raise_thread_errors(errors):
        if not errors.empty():
            raise errors.get()

    @skipUnlessDBFeature("has_select_for_update")
    def test_direct_revocation_returns_only_after_an_older_writer_commits(self):
        share = AddressBookShare.objects.create(profile=self.profile, user=self.writer, rule=2)
        writer_locked = threading.Event()
        release_writer = threading.Event()
        revoker_pid = queue.Queue()
        errors = queue.Queue()

        def old_writer():
            close_old_connections()
            try:
                with transaction.atomic():
                    writer = UserProfile.objects.get(pk=self.writer.pk)
                    profile, owner, rule = lock_profile_access(writer, self.profile.pk)
                    if not profile or not owner or rule != 2:
                        raise AssertionError("writer did not obtain its pre-revocation capability")
                    writer_locked.set()
                    if not release_writer.wait(10):
                        raise TimeoutError("writer release timed out")
                    RemotePeer.objects.filter(pk=self.peer.pk).update(alias="committed-before-revoke")
            except Exception as exc:  # noqa: BLE001 - surface failures from worker threads
                errors.put(exc)
                writer_locked.set()
            finally:
                connection.close()

        def revoke():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    revoker_pid.put(cursor.fetchone()[0])
                with transaction.atomic():
                    owner = UserProfile.objects.get(pk=self.owner.pk)
                    profile, _current_owner, _rule = lock_profile_access(owner, self.profile.pk)
                    if not profile:
                        raise AssertionError("profile disappeared during revocation")
                    locked_share = AddressBookShare.objects.select_for_update().get(pk=share.pk)
                    bump_locked_authorization_generation(profile)
                    locked_share.delete()
            except Exception as exc:  # noqa: BLE001 - surface failures from worker threads
                errors.put(exc)
            finally:
                connection.close()

        writer_thread = threading.Thread(target=old_writer)
        revoke_thread = threading.Thread(target=revoke)
        writer_thread.start()
        self.assertTrue(writer_locked.wait(10), "writer did not lock the profile")
        revoke_thread.start()
        self._wait_until_backend_is_blocked(revoker_pid.get(timeout=10))
        release_writer.set()
        writer_thread.join(10)
        revoke_thread.join(10)
        self.assertFalse(writer_thread.is_alive())
        self.assertFalse(revoke_thread.is_alive())
        self._raise_thread_errors(errors)

        self.peer.refresh_from_db()
        self.assertEqual(self.peer.alias, "committed-before-revoke")
        self.assertFalse(AddressBookShare.objects.filter(pk=share.pk).exists())
        with transaction.atomic():
            profile, owner, rule = lock_profile_access(self.writer, self.profile.pk)
            self.assertIsNotNone(profile)
            self.assertIsNone(owner)
            self.assertEqual(rule, 0)

    @skipUnlessDBFeature("has_select_for_update")
    def test_group_membership_revocation_uses_the_same_profile_barrier(self):
        group = Group.objects.create(name="pg-writers")
        self.writer.groups.add(group)
        AddressBookRule.objects.create(profile=self.profile, group=group, rule=2)
        self.profile.refresh_from_db()
        before_generation = self.profile.authorization_generation
        writer_locked = threading.Event()
        release_writer = threading.Event()
        revoker_pid = queue.Queue()
        errors = queue.Queue()

        def old_writer():
            close_old_connections()
            try:
                with transaction.atomic():
                    writer = UserProfile.objects.get(pk=self.writer.pk)
                    profile, owner, rule = lock_profile_access(writer, self.profile.pk)
                    if not profile or not owner or rule != 2:
                        raise AssertionError("group writer did not obtain its current capability")
                    writer_locked.set()
                    if not release_writer.wait(10):
                        raise TimeoutError("group writer release timed out")
                    RemotePeer.objects.filter(pk=self.peer.pk).update(alias="group-write-before-revoke")
            except Exception as exc:  # noqa: BLE001 - surface failures from worker threads
                errors.put(exc)
                writer_locked.set()
            finally:
                connection.close()

        def revoke_membership():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    revoker_pid.put(cursor.fetchone()[0])
                writer = UserProfile.objects.get(pk=self.writer.pk)
                writer.groups.remove(group)
            except Exception as exc:  # noqa: BLE001 - surface failures from worker threads
                errors.put(exc)
            finally:
                connection.close()

        writer_thread = threading.Thread(target=old_writer)
        revoke_thread = threading.Thread(target=revoke_membership)
        writer_thread.start()
        self.assertTrue(writer_locked.wait(10), "group writer did not lock the profile")
        revoke_thread.start()
        self._wait_until_backend_is_blocked(revoker_pid.get(timeout=10))
        release_writer.set()
        writer_thread.join(10)
        revoke_thread.join(10)
        self.assertFalse(writer_thread.is_alive())
        self.assertFalse(revoke_thread.is_alive())
        self._raise_thread_errors(errors)

        self.peer.refresh_from_db()
        self.profile.refresh_from_db()
        self.assertEqual(self.peer.alias, "group-write-before-revoke")
        self.assertFalse(self.writer.groups.filter(pk=group.pk).exists())
        self.assertEqual(self.profile.authorization_generation, before_generation + 1)

    @skipUnlessDBFeature("has_select_for_update")
    def test_owner_transfer_commit_denies_an_older_owner_request_waiting_on_the_barrier(self):
        request_prechecked = threading.Event()
        begin_locked_check = threading.Event()
        transfer_locked = threading.Event()
        release_transfer = threading.Event()
        stale_writer_pid = queue.Queue()
        errors = queue.Queue()

        def stale_owner_writer():
            close_old_connections()
            try:
                owner = UserProfile.objects.get(pk=self.owner.pk)
                prechecked = AddressBookProfile.objects.get(pk=self.profile.pk)
                if prechecked.owner_id != owner.pk:
                    raise AssertionError("owner request did not precheck its old capability")
                request_prechecked.set()
                if not begin_locked_check.wait(10):
                    raise TimeoutError("owner writer start timed out")
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    stale_writer_pid.put(cursor.fetchone()[0])
                with transaction.atomic():
                    profile, current_owner, rule = lock_profile_access(owner, self.profile.pk)
                    if profile is None or current_owner is not None or rule != 0:
                        raise AssertionError(
                            "old owner retained capability after transfer commit: "
                            f"profile_owner={getattr(profile, 'owner_id', None)} "
                            f"current_owner={getattr(current_owner, 'pk', None)} "
                            f"request_owner={owner.pk} rule={rule} admin={owner.is_admin}"
                        )
            except Exception as exc:  # noqa: BLE001 - surface failures from worker threads
                errors.put(exc)
                request_prechecked.set()
            finally:
                connection.close()

        def transfer_owner():
            close_old_connections()
            try:
                if not request_prechecked.wait(10):
                    raise TimeoutError("owner request precheck timed out")
                with transaction.atomic():
                    profile = AddressBookProfile.objects.select_for_update().get(pk=self.profile.pk)
                    profile.owner_id = self.new_owner.pk
                    profile.save(update_fields=("owner", "updated_at"))
                    transfer_locked.set()
                    if not release_transfer.wait(10):
                        raise TimeoutError("owner transfer release timed out")
            except Exception as exc:  # noqa: BLE001 - surface failures from worker threads
                errors.put(exc)
                transfer_locked.set()
            finally:
                connection.close()

        stale_writer_thread = threading.Thread(target=stale_owner_writer)
        transfer_thread = threading.Thread(target=transfer_owner)
        stale_writer_thread.start()
        self.assertTrue(request_prechecked.wait(10), "owner request did not precheck")
        transfer_thread.start()
        self.assertTrue(transfer_locked.wait(10), "owner transfer did not lock the profile")
        begin_locked_check.set()
        self._wait_until_backend_is_blocked(stale_writer_pid.get(timeout=10))
        release_transfer.set()
        stale_writer_thread.join(10)
        transfer_thread.join(10)
        self.assertFalse(stale_writer_thread.is_alive())
        self.assertFalse(transfer_thread.is_alive())
        self._raise_thread_errors(errors)

        self.profile.refresh_from_db()
        self.peer.refresh_from_db()
        self.assertEqual(self.profile.owner_id, self.new_owner.pk)
        self.assertEqual(self.profile.authorization_generation, 1)
        self.assertEqual(self.peer.alias, "before")
