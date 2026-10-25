import concurrent.futures
import json
import threading
import uuid

from django.db import close_old_connections, connection, connections
from django.http import JsonResponse
from django.test import RequestFactory, TestCase, TransactionTestCase, override_settings, skipUnlessDBFeature

from api.management_operations import document_digest
from api.models import (
    AddressBookProfile,
    AddressBookRule,
    DeviceGroup,
    ManagementBatchOperation,
    RemoteDevice,
    RemotePeer,
    RemoteTag,
    ShareLink,
    UserProfile,
)
from api.replayable_mutations import replayable_stateless_api
from api.views_api import _issue_access_token


@override_settings(
    STORAGES={
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }
)
class State040ControlMutationTests(TestCase):
    def setUp(self):
        self.admin = UserProfile.objects.create_superuser(
            "state040-admin",
            "state040-admin-pass",  # noqa: S106 - isolated test credential
        )
        self.device = RemoteDevice.objects.create(
            rid="840040001",
            uuid="c3RhdGUwNDAwMQ==",
            owner=self.admin,
            hostname="state040-device",
            username=self.admin.username,
            is_active=True,
            cpu="-",
            memory="-",
            os="Linux",
            version="test",
        )
        _token, self.bearer = _issue_access_token(self.admin, self.device)

    def _headers(self, operation_id, *, if_match=None):
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {self.bearer}",
            "HTTP_IDEMPOTENCY_KEY": str(operation_id),
        }
        if if_match is not None:
            headers["HTTP_IF_MATCH"] = if_match
        return headers

    def _json(self, method, path, payload=None, *, operation_id=None, if_match=None):
        operation_id = operation_id or uuid.uuid4()
        headers = self._headers(operation_id, if_match=if_match)
        body = "" if payload is None else json.dumps(payload)
        return getattr(self.client, method)(
            path,
            data=body,
            content_type="application/json",
            **headers,
        )

    def test_group_create_replay_and_digest_conflict_are_durable(self):
        operation_id = uuid.uuid4()
        payload = {"name": "state040-replay-group", "note": "first"}
        first = self._json("post", "/api/device-groups", payload, operation_id=operation_id)
        self.assertEqual(first.status_code, 200, first.content)
        first_body = first.json()
        self.assertEqual(first_body["operation_id"], str(operation_id))
        self.assertEqual(first_body["applied"], {"groups": 1})
        self.assertEqual(first["ETag"], '"0"')

        replay = self._json("post", "/api/device-groups", payload, operation_id=operation_id)
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(replay.json(), first_body)
        self.assertEqual(DeviceGroup.objects.filter(name=payload["name"]).count(), 1)

        conflict = self._json(
            "post",
            "/api/device-groups",
            {**payload, "note": "different"},
            operation_id=operation_id,
        )
        self.assertEqual(conflict.status_code, 409, conflict.content)
        self.assertEqual(conflict.json()["code"], "http_409_api_device_groups")
        self.assertEqual(DeviceGroup.objects.filter(name=payload["name"]).count(), 1)

    def test_mutations_require_uuid4_operation_id_and_resource_generation(self):
        missing_key = self.client.post(
            "/api/device-groups",
            data=json.dumps({"name": "state040-missing-operation"}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.bearer}",
        )
        self.assertEqual(missing_key.status_code, 400, missing_key.content)
        self.assertFalse(DeviceGroup.objects.filter(name="state040-missing-operation").exists())

        non_random_key = self.client.post(
            "/api/device-groups",
            data=json.dumps({"name": "state040-non-random-operation"}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.bearer}",
            HTTP_IDEMPOTENCY_KEY=str(uuid.uuid1()),
        )
        self.assertEqual(non_random_key.status_code, 400, non_random_key.content)
        self.assertFalse(DeviceGroup.objects.filter(name="state040-non-random-operation").exists())

        group = DeviceGroup.objects.create(name="state040-generation-required")
        missing_generation = self._json(
            "patch",
            f"/api/device-groups/{group.guid}",
            {"note": "must-not-apply"},
        )
        self.assertEqual(missing_generation.status_code, 400, missing_generation.content)
        group.refresh_from_db()
        self.assertEqual(group.note, "")
        self.assertEqual(group.mutation_generation, 0)

        profile = AddressBookProfile.objects.create(
            guid="state040-required-profile-generation",
            name="state040-required-profile-generation",
            owner=self.admin,
            rule=3,
        )
        peer_path = f"/api/ab/peer/add/{profile.guid}"
        missing_peer_key = self.client.post(
            peer_path,
            data=json.dumps({"id": "840040077"}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.bearer}",
            HTTP_IF_MATCH='"0"',
        )
        self.assertEqual(missing_peer_key.status_code, 400, missing_peer_key.content)
        missing_peer_generation = self._json(
            "post",
            peer_path,
            {"id": "840040077"},
        )
        self.assertEqual(missing_peer_generation.status_code, 400, missing_peer_generation.content)
        self.assertFalse(RemotePeer.objects.filter(profile=profile, rid="840040077").exists())

    def test_user_create_delete_and_device_assign_are_replay_safe(self):
        create_id = uuid.uuid4()
        create_payload = {
            "name": "state040-created-user",
            "password": "R3mote!Zebra-Quartz-Password-47",
            "note": "created",
        }
        created = self._json(
            "post", "/api/users", create_payload, operation_id=create_id
        )
        self.assertEqual(created.status_code, 200, created.content)
        created_body = created.json()
        self.assertEqual(created_body["mutation_generation"], 0)
        target_id = created_body["guid"]

        replay = self._json(
            "post", "/api/users", create_payload, operation_id=create_id
        )
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(replay.json(), created_body)
        self.assertEqual(
            UserProfile.objects.filter(username="state040-created-user").count(), 1
        )

        password_conflict = self._json(
            "post",
            "/api/users",
            {**create_payload, "password": "D1fferent!Comet-Lantern-Password-48"},
            operation_id=create_id,
        )
        self.assertEqual(password_conflict.status_code, 409, password_conflict.content)

        assign_id = uuid.uuid4()
        assigned = self._json(
            "post",
            f"/api/devices/{self.device.pk}/assign",
            {"type": "note", "value": "assigned-once"},
            operation_id=assign_id,
            if_match='"0"',
        )
        self.assertEqual(assigned.status_code, 200, assigned.content)
        self.assertEqual(assigned["ETag"], '"1"')
        assigned_body = assigned.json()
        assigned_replay = self._json(
            "post",
            f"/api/devices/{self.device.pk}/assign",
            {"type": "note", "value": "assigned-once"},
            operation_id=assign_id,
            if_match='"0"',
        )
        self.assertEqual(assigned_replay.status_code, 200, assigned_replay.content)
        self.assertEqual(assigned_replay.json(), assigned_body)
        stale_assign = self._json(
            "post",
            f"/api/devices/{self.device.pk}/assign",
            {"type": "note", "value": "stale"},
            if_match='"0"',
        )
        self.assertEqual(stale_assign.status_code, 409, stale_assign.content)
        self.device.refresh_from_db()
        self.assertEqual(self.device.note, "assigned-once")
        self.assertEqual(self.device.mutation_generation, 1)

        address_book_id = uuid.uuid4()
        address_book_password = "state040-device-address-book-secret"  # noqa: S105 - isolated test credential
        address_book_value = {
            "address_book_name": "shared",
            "address_book_tag": "production",
            "address_book_alias": "desk",
            "address_book_password": address_book_password,
            "address_book_note": "note",
        }
        address_book_assign = self._json(
            "post",
            f"/api/devices/{self.device.pk}/assign",
            {"type": "ab", "value": address_book_value},
            operation_id=address_book_id,
            if_match='"1"',
        )
        self.assertEqual(address_book_assign.status_code, 200, address_book_assign.content)
        address_book_receipt = ManagementBatchOperation.objects.get(operation_id=address_book_id)
        self.assertNotIn(address_book_password, json.dumps(address_book_receipt.response))
        self.assertEqual(
            address_book_receipt.request_digest,
            document_digest(
                {
                    "operation": "device_assign",
                    "device": str(self.device.pk),
                    "type": "ab",
                    "value": {
                        "address_book_name": "shared",
                        "address_book_tag": "production",
                        "address_book_alias": "desk",
                        "address_book_note": "note",
                        "has_address_book_password": True,
                        "address_book_password_digest": document_digest(address_book_password),
                    },
                    "expected_generation": 1,
                }
            ),
        )

        delete_id = uuid.uuid4()
        deleted = self._json(
            "delete",
            f"/api/users/{target_id}",
            operation_id=delete_id,
            if_match='"0"',
        )
        self.assertEqual(deleted.status_code, 200, deleted.content)
        deleted_replay = self._json(
            "delete",
            f"/api/users/{target_id}",
            operation_id=delete_id,
            if_match='"0"',
        )
        self.assertEqual(deleted_replay.status_code, 200, deleted_replay.content)
        self.assertEqual(deleted_replay.json(), deleted.json())
        self.assertFalse(UserProfile.objects.filter(pk=target_id).exists())

    def test_group_patch_rejects_stale_generation_without_mutating(self):
        group = DeviceGroup.objects.create(name="state040-stale-group")
        first = self._json(
            "patch",
            f"/api/device-groups/{group.guid}",
            {"note": "fresh"},
            operation_id=uuid.uuid4(),
            if_match='"0"',
        )
        self.assertEqual(first.status_code, 200, first.content)
        self.assertEqual(first["ETag"], '"1"')
        group.refresh_from_db()
        self.assertEqual(group.note, "fresh")
        self.assertEqual(group.mutation_generation, 1)

        stale = self._json(
            "patch",
            f"/api/device-groups/{group.guid}",
            {"note": "stale"},
            operation_id=uuid.uuid4(),
            if_match='"0"',
        )
        self.assertEqual(stale.status_code, 409, stale.content)
        self.assertEqual(stale.json()["code"], "resource_generation_conflict")
        group.refresh_from_db()
        self.assertEqual(group.note, "fresh")
        self.assertEqual(group.mutation_generation, 1)

    def test_group_delete_replay_returns_receipt_after_row_is_gone(self):
        group = DeviceGroup.objects.create(name="state040-delete-group")
        operation_id = uuid.uuid4()
        path = f"/api/device-groups/{group.guid}"
        first = self._json("delete", path, operation_id=operation_id, if_match='"0"')
        self.assertEqual(first.status_code, 200, first.content)
        first_body = first.json()
        self.assertFalse(DeviceGroup.objects.filter(pk=group.pk).exists())

        replay = self._json("delete", path, operation_id=operation_id, if_match='"0"')
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(replay.json(), first_body)

        unknown = self._json("delete", path, operation_id=uuid.uuid4(), if_match='"0"')
        self.assertEqual(unknown.status_code, 404, unknown.content)

    def test_address_book_profile_create_replay_conflict_and_stale_update(self):
        create_id = uuid.uuid4()
        payload = {"name": "state040-address-book", "note": "initial"}
        first = self._json("post", "/api/ab/shared/add", payload, operation_id=create_id)
        self.assertEqual(first.status_code, 200, first.content)
        first_body = first.json()
        self.assertEqual(first_body["operation_id"], str(create_id))
        self.assertEqual(first["ETag"], '"0"')
        profile = AddressBookProfile.objects.get(guid=first_body["guid"])

        replay = self._json("post", "/api/ab/shared/add", payload, operation_id=create_id)
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(replay.json(), first_body)
        self.assertEqual(AddressBookProfile.objects.filter(owner=self.admin, name=payload["name"]).count(), 1)

        duplicate = self._json(
            "post",
            "/api/ab/shared/add",
            {**payload, "note": "different operation"},
        )
        self.assertEqual(duplicate.status_code, 409, duplicate.content)
        self.assertEqual(duplicate.json()["code"], "profile_name_conflict")

        update_id = uuid.uuid4()
        updated = self._json(
            "put",
            "/api/ab/shared/update/profile",
            {"guid": str(profile.guid), "note": "updated"},
            operation_id=update_id,
            if_match='"0"',
        )
        self.assertEqual(updated.status_code, 200, updated.content)
        self.assertEqual(updated["ETag"], '"1"')

        stale = self._json(
            "put",
            "/api/ab/shared/update/profile",
            {"guid": str(profile.guid), "note": "stale"},
            operation_id=uuid.uuid4(),
            if_match='"0"',
        )
        self.assertEqual(stale.status_code, 409, stale.content)
        profile.refresh_from_db()
        self.assertEqual(profile.note, "updated")
        self.assertEqual(profile.authorization_generation, 1)

        new_owner = UserProfile.objects.create_user(
            "state040-api-transfer-owner",
            "state040-api-transfer-owner-pass",  # noqa: S106 - isolated test credential
        )
        transferred = self._json(
            "put",
            "/api/ab/shared/update/profile",
            {"guid": str(profile.guid), "owner": new_owner.username},
            if_match='"1"',
        )
        self.assertEqual(transferred.status_code, 200, transferred.content)
        self.assertEqual(transferred["ETag"], '"2"')
        profile.refresh_from_db()
        self.assertEqual(profile.owner_id, new_owner.pk)
        self.assertEqual(profile.authorization_generation, 2)

    def test_address_book_peer_mutation_wrapper_replays_without_duplicate_peer(self):
        profile = AddressBookProfile.objects.create(
            guid="state040-peer-profile",
            name="state040-peer-profile",
            owner=self.admin,
            rule=3,
        )
        operation_id = uuid.uuid4()
        path = f"/api/ab/peer/add/{profile.guid}"
        payload = {"id": "state040-peer", "alias": "first"}
        first = self._json("post", path, payload, operation_id=operation_id, if_match='"0"')
        self.assertEqual(first.status_code, 200, first.content)
        first_body = first.json()
        self.assertEqual(first_body["operation_id"], str(operation_id))
        self.assertEqual(first_body["applied"], {"mutations": 1})
        self.assertEqual(first_body["mutation_generation"], 1)
        self.assertEqual(first["ETag"], '"1"')
        self.assertEqual(RemotePeer.objects.filter(profile=profile, rid="state040-peer").count(), 1)

        replay = self._json("post", path, payload, operation_id=operation_id, if_match='"0"')
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(replay.json(), first_body)
        self.assertEqual(RemotePeer.objects.filter(profile=profile, rid="state040-peer").count(), 1)

        stale = self._json(
            "put",
            f"/api/ab/peer/update/{profile.guid}",
            {"id": "state040-peer", "alias": "stale"},
            if_match='"0"',
        )
        self.assertEqual(stale.status_code, 409, stale.content)
        self.assertEqual(stale.json()["code"], "resource_generation_conflict")
        self.assertEqual(RemotePeer.objects.get(profile=profile, rid="state040-peer").alias, "first")

        fresh = self._json(
            "put",
            f"/api/ab/peer/update/{profile.guid}",
            {"id": "state040-peer", "alias": "fresh"},
            if_match='"1"',
        )
        self.assertEqual(fresh.status_code, 200, fresh.content)
        self.assertEqual(fresh["ETag"], '"2"')
        self.assertEqual(RemotePeer.objects.get(profile=profile, rid="state040-peer").alias, "fresh")

    def test_profile_password_changes_are_part_of_the_operation_digest(self):
        create_id = uuid.uuid4()
        create_password = "state040-create-secret-value"  # noqa: S105 - isolated test credential
        created = self._json(
            "post",
            "/api/ab/shared/add",
            {
                "name": "state040-password-create-profile",
                "note": "digest",
                "default_password": create_password,
            },
            operation_id=create_id,
        )
        self.assertEqual(created.status_code, 200, created.content)
        create_receipt = ManagementBatchOperation.objects.get(operation_id=create_id)
        self.assertEqual(
            create_receipt.request_digest,
            document_digest(
                {
                    "operation": "address_book_profile_create",
                    "name": "state040-password-create-profile",
                    "note": "digest",
                    "info": None,
                    "has_default_password": True,
                    "default_password_digest": document_digest(create_password),
                }
            ),
        )

        profile = AddressBookProfile.objects.create(
            guid="state040-password-profile",
            name="state040-password-profile",
            owner=self.admin,
            rule=3,
        )
        operation_id = uuid.uuid4()
        first = self._json(
            "put",
            "/api/ab/shared/update/profile",
            {"guid": profile.guid, "default_password": "first-secret-value"},
            operation_id=operation_id,
            if_match='"0"',
        )
        self.assertEqual(first.status_code, 200, first.content)
        conflict = self._json(
            "put",
            "/api/ab/shared/update/profile",
            {"guid": profile.guid, "default_password": "different-secret-value"},
            operation_id=operation_id,
            if_match='"0"',
        )
        self.assertEqual(conflict.status_code, 409, conflict.content)
        profile.refresh_from_db()
        self.assertEqual(profile.default_password, "first-secret-value")
        receipt = ManagementBatchOperation.objects.get(operation_id=operation_id)
        self.assertNotIn("first-secret-value", receipt.request_digest)
        self.assertNotIn("different-secret-value", receipt.request_digest)

    def test_unrecordable_5xx_rolls_back_mutation_and_receipt(self):
        profile = AddressBookProfile.objects.create(
            guid="state040-transient-profile",
            name="state040-transient-profile",
            owner=self.admin,
            rule=3,
        )
        operation_id = uuid.uuid4()

        def failing_view(_request, guid):
            RemotePeer.objects.create(profile=profile, rid="state040-transient-peer")
            return JsonResponse({"error": "temporary"}, status=503)

        wrapped = replayable_stateless_api(
            failing_view,
            "address_book_peer_add",
            "POST",
        )
        request = RequestFactory().post(
            f"/api/ab/peer/add/{profile.guid}",
            data=json.dumps({"id": "state040-transient-peer"}),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.bearer}",
            HTTP_IDEMPOTENCY_KEY=str(operation_id),
            HTTP_IF_MATCH='"0"',
        )
        response = wrapped(request, guid=profile.guid)
        self.assertEqual(response.status_code, 503, response.content)
        self.assertFalse(RemotePeer.objects.filter(profile=profile, rid="state040-transient-peer").exists())
        self.assertFalse(ManagementBatchOperation.objects.filter(operation_id=operation_id).exists())

    def test_share_create_and_accept_recover_the_first_result(self):
        profile = AddressBookProfile.objects.create(
            guid=f"personal-{self.admin.pk}",
            name="state040-share-profile",
            owner=self.admin,
            rule=3,
        )
        peer = RemotePeer.objects.create(profile=profile, rid="840040099", alias="state040-share-peer")
        self.client.force_login(self.admin)
        create_id = uuid.uuid4()
        create_payload = json.dumps([{"value": str(peer.pk), "title": "state040-share-peer"}])
        first = self.client.post(
            "/api/share",
            {"data": create_payload},
            HTTP_IDEMPOTENCY_KEY=str(create_id),
        )
        self.assertEqual(first.status_code, 200, first.content)
        first_body = first.json()
        raw_token = first_body["token"]
        replay = self.client.post(
            "/api/share",
            {"data": create_payload},
            HTTP_IDEMPOTENCY_KEY=str(create_id),
        )
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(replay.json(), first_body)
        self.assertEqual(ShareLink.objects.count(), 1)

        receipt = ManagementBatchOperation.objects.get(operation_id=create_id)
        self.assertEqual(receipt.response["sensitive_response"], True)
        self.assertNotIn(raw_token, json.dumps(receipt.response))
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT secret_response FROM api_managementbatchoperation WHERE operation_id = %s",
                [str(create_id).replace("-", "") if connection.vendor == "sqlite" else create_id],
            )
            encrypted_response = cursor.fetchone()[0]
        self.assertTrue(encrypted_response.startswith("secretbox:v3:"))
        self.assertNotIn(raw_token, encrypted_response)

        recipient = UserProfile.objects.create_user("state040-recipient", "state040-recipient-pass")
        self.client.force_login(recipient)
        accept_id = uuid.uuid4()
        path = f"/api/share/{raw_token}"
        accepted = self.client.post(path, {"idempotency_key": str(accept_id)})
        self.assertEqual(accepted.status_code, 200, accepted.content)
        self.assertContains(accepted, "已获取 1 台设备")
        accepted_replay = self.client.post(path, {"idempotency_key": str(accept_id)})
        self.assertEqual(accepted_replay.status_code, 200, accepted_replay.content)
        self.assertContains(accepted_replay, "已获取 1 台设备")
        self.assertEqual(RemotePeer.objects.filter(profile__owner=recipient, rid=peer.rid).count(), 1)
        recipient_profile = AddressBookProfile.objects.get(
            guid=f"personal-{recipient.pk}",
        )
        self.assertEqual(recipient_profile.authorization_generation, 1)
        self.assertEqual(ManagementBatchOperation.objects.filter(operation_id=accept_id).count(), 1)

        different_operation = self.client.post(path, {"idempotency_key": str(uuid.uuid4())})
        self.assertEqual(different_operation.status_code, 404, different_operation.content)

    def test_browser_profile_forms_replay_and_reject_stale_generation(self):
        self.client.force_login(self.admin)
        page = self.client.get("/api/ab_books")
        self.assertEqual(page.status_code, 200, page.content)
        self.assertContains(page, 'name="idempotency_key"')

        create_id = uuid.uuid4()
        create_form = {
            "action": "create_book",
            "name": "state040-browser-book",
            "note": "initial",
            "idempotency_key": str(create_id),
        }
        first = self.client.post("/api/ab_books", create_form)
        replay = self.client.post("/api/ab_books", create_form)
        self.assertEqual(first.status_code, 302, first.content)
        self.assertEqual(replay.status_code, 302, replay.content)
        profile = AddressBookProfile.objects.get(
            owner=self.admin, name="state040-browser-book"
        )
        self.assertEqual(
            AddressBookProfile.objects.filter(
                owner=self.admin, name="state040-browser-book"
            ).count(),
            1,
        )

        update_id = uuid.uuid4()
        update_form = {
            "action": "update_book",
            "guid": profile.guid,
            "name": profile.name,
            "note": "updated",
            "idempotency_key": str(update_id),
            "expected_generation": "0",
        }
        updated = self.client.post("/api/ab_books", update_form)
        updated_replay = self.client.post("/api/ab_books", update_form)
        self.assertEqual(updated.status_code, 302, updated.content)
        self.assertEqual(updated_replay.status_code, 302, updated_replay.content)
        profile.refresh_from_db()
        self.assertEqual(profile.note, "updated")
        self.assertEqual(profile.authorization_generation, 1)

        transfer_owner = UserProfile.objects.create_user(
            "state040-browser-transfer-owner",
            "state040-browser-transfer-owner-pass",  # noqa: S106 - isolated test credential
        )
        transfer_id = uuid.uuid4()
        transfer_form = {
            "action": "transfer_book",
            "guid": profile.guid,
            "owner": transfer_owner.username,
            "idempotency_key": str(transfer_id),
            "expected_generation": "1",
        }
        transferred = self.client.post("/api/ab_books", transfer_form)
        transferred_replay = self.client.post("/api/ab_books", transfer_form)
        self.assertEqual(transferred.status_code, 302, transferred.content)
        self.assertEqual(transferred_replay.status_code, 302, transferred_replay.content)
        profile.refresh_from_db()
        self.assertEqual(profile.owner_id, transfer_owner.pk)
        self.assertEqual(profile.authorization_generation, 2)

        stale = self.client.post(
            "/api/ab_books",
            {
                **update_form,
                "idempotency_key": str(uuid.uuid4()),
                "note": "stale",
            },
        )
        self.assertEqual(stale.status_code, 302, stale.content)
        profile.refresh_from_db()
        self.assertEqual(profile.note, "updated")
        self.assertEqual(profile.authorization_generation, 2)

        delete_id = uuid.uuid4()
        delete_form = {
            "action": "delete_book",
            "guid": profile.guid,
            "idempotency_key": str(delete_id),
            "expected_generation": "2",
        }
        deleted = self.client.post("/api/ab_books", delete_form)
        deleted_replay = self.client.post("/api/ab_books", delete_form)
        self.assertEqual(deleted.status_code, 302, deleted.content)
        self.assertEqual(deleted_replay.status_code, 302, deleted_replay.content)
        self.assertFalse(AddressBookProfile.objects.filter(pk=profile.pk).exists())

    def test_browser_content_tag_and_rule_forms_are_replay_safe(self):
        profile = AddressBookProfile.objects.create(
            guid="state040-browser-content",
            name="state040-browser-content",
            owner=self.admin,
            rule=3,
        )
        self.client.force_login(self.admin)

        content_page = self.client.get(f"/api/ab_book?guid={profile.guid}")
        self.assertContains(content_page, "data-replayable-address-book")
        self.assertContains(content_page, 'data-expected-generation="0"')

        add_id = uuid.uuid4()
        add_form = {
            "action": "add_peer",
            "guid": profile.guid,
            "rid": "840040088",
            "alias": "browser-peer",
            "note": "created",
            "password": "State040-Browser-Secret-48",
            "tags": "production",
            "expected_generation": "0",
            "idempotency_key": str(add_id),
        }
        added = self.client.post("/api/ab_book", add_form)
        replay = self.client.post("/api/ab_book", add_form)
        self.assertEqual(added.status_code, 302, added.content)
        self.assertEqual(replay.status_code, 302, replay.content)
        self.assertEqual(
            RemotePeer.objects.filter(profile=profile, rid="840040088").count(),
            1,
        )
        profile.refresh_from_db()
        self.assertEqual(profile.authorization_generation, 1)
        add_receipt = ManagementBatchOperation.objects.get(operation_id=add_id)
        self.assertEqual(add_receipt.operation, "browser_ab_book_add_peer")
        self.assertEqual(add_receipt.response["applied"], {"mutations": 1})
        self.assertNotIn("State040-Browser-Secret-48", json.dumps(add_receipt.response))

        conflict = self.client.post(
            "/api/ab_book",
            {**add_form, "alias": "conflicting-alias"},
        )
        self.assertEqual(conflict.status_code, 302, conflict.content)
        peer = RemotePeer.objects.get(profile=profile, rid="840040088")
        self.assertEqual(peer.alias, "browser-peer")

        stale_id = uuid.uuid4()
        stale = self.client.post(
            "/api/ab_book",
            {
                **add_form,
                "action": "update_peer",
                "alias": "stale-alias",
                "password": "",
                "idempotency_key": str(stale_id),
            },
        )
        self.assertEqual(stale.status_code, 302, stale.content)
        peer.refresh_from_db()
        profile.refresh_from_db()
        self.assertEqual(peer.alias, "browser-peer")
        self.assertEqual(profile.authorization_generation, 1)
        stale_receipt = ManagementBatchOperation.objects.get(operation_id=stale_id)
        self.assertEqual(stale_receipt.status_code, 409)
        self.assertEqual(stale_receipt.response["applied"], {"mutations": 0})

        delete_id = uuid.uuid4()
        delete_form = {
            "action": "delete_peer",
            "guid": profile.guid,
            "rid": peer.rid,
            "expected_generation": "1",
            "idempotency_key": str(delete_id),
        }
        deleted = self.client.post("/api/ab_book", delete_form)
        deleted_replay = self.client.post("/api/ab_book", delete_form)
        self.assertEqual(deleted.status_code, 302, deleted.content)
        self.assertEqual(deleted_replay.status_code, 302, deleted_replay.content)
        self.assertFalse(RemotePeer.objects.filter(pk=peer.pk).exists())
        profile.refresh_from_db()
        self.assertEqual(profile.authorization_generation, 2)

        tag_id = uuid.uuid4()
        tag_form = {
            "action": "add_tag",
            "profile_guid": profile.guid,
            "name": "operations",
            "color": "#397bff",
            "expected_generation": "2",
            "idempotency_key": str(tag_id),
        }
        tagged = self.client.post("/api/tag_manage", tag_form)
        tagged_replay = self.client.post("/api/tag_manage", tag_form)
        self.assertEqual(tagged.status_code, 302, tagged.content)
        self.assertEqual(tagged_replay.status_code, 302, tagged_replay.content)
        self.assertEqual(RemoteTag.objects.filter(profile=profile, tag_name="operations").count(), 1)
        profile.refresh_from_db()
        self.assertEqual(profile.authorization_generation, 3)

        rule_id = uuid.uuid4()
        rule_form = {
            "action": "add_everyone_rule",
            "profile_guid": profile.guid,
            "rule": "1",
            "expected_generation": "3",
            "idempotency_key": str(rule_id),
        }
        ruled = self.client.post("/api/ab_manage", rule_form)
        ruled_replay = self.client.post("/api/ab_manage", rule_form)
        self.assertEqual(ruled.status_code, 302, ruled.content)
        self.assertEqual(ruled_replay.status_code, 302, ruled_replay.content)
        self.assertEqual(AddressBookRule.objects.filter(profile=profile, is_everyone=True).count(), 1)
        profile.refresh_from_db()
        self.assertEqual(profile.authorization_generation, 4)

        tag_page = self.client.get("/api/tag_manage")
        self.assertContains(tag_page, "data-generation-select")
        rules_page = self.client.get("/api/ab_manage")
        self.assertContains(rules_page, 'data-address-book-generation="4"')

        everyone_rule = AddressBookRule.objects.get(profile=profile, is_everyone=True)
        global_rules_page = self.client.get("/api/ab_rules")
        self.assertContains(
            global_rules_page,
            f'data-profile-guid="{profile.guid}"',
        )
        invalid_bulk_id = uuid.uuid4()
        invalid_bulk = self.client.post(
            "/api/ab_rules",
            {
                "action": "bulk_update",
                "selected": [str(everyone_rule.guid)],
                "rule": "2",
                "expected_generations": json.dumps(
                    {
                        str(profile.guid): 4,
                        "state040-unselected-profile": 0,
                    }
                ),
                "idempotency_key": str(invalid_bulk_id),
            },
        )
        self.assertEqual(invalid_bulk.status_code, 302, invalid_bulk.content)
        everyone_rule.refresh_from_db()
        profile.refresh_from_db()
        self.assertEqual(everyone_rule.rule, 1)
        self.assertEqual(profile.authorization_generation, 4)
        invalid_receipt = ManagementBatchOperation.objects.get(operation_id=invalid_bulk_id)
        self.assertEqual(invalid_receipt.status_code, 400)
        self.assertEqual(invalid_receipt.response["applied"], {"mutations": 0})

        valid_bulk_id = uuid.uuid4()
        valid_bulk = self.client.post(
            "/api/ab_rules",
            {
                "action": "bulk_update",
                "selected": [str(everyone_rule.guid)],
                "rule": "2",
                "expected_generations": json.dumps({str(profile.guid): 4}),
                "idempotency_key": str(valid_bulk_id),
            },
        )
        self.assertEqual(valid_bulk.status_code, 302, valid_bulk.content)
        everyone_rule.refresh_from_db()
        profile.refresh_from_db()
        self.assertEqual(everyone_rule.rule, 2)
        self.assertEqual(profile.authorization_generation, 5)


@override_settings(
    STORAGES={
        "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
        "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
    }
)
class State040ConcurrencyTests(TransactionTestCase):
    @skipUnlessDBFeature("has_select_for_update")
    def test_32_identical_creates_commit_one_mutation_and_one_receipt(self):
        admin = UserProfile.objects.create_superuser(
            "state040-concurrency-admin",
            "state040-concurrency-admin-pass",  # noqa: S106 - isolated test credential
        )
        device = RemoteDevice.objects.create(
            rid="840040032",
            uuid="c3RhdGUwNDAzMg==",
            owner=admin,
            hostname="state040-concurrency-device",
            username=admin.username,
            is_active=True,
            cpu="-",
            memory="-",
            os="Linux",
            version="test",
        )
        _token, bearer = _issue_access_token(admin, device)
        operation_id = str(uuid.uuid4())
        payload = json.dumps({"name": "state040-concurrent-group", "note": "once"})
        barrier = threading.Barrier(33)

        def create_group():
            close_old_connections()
            try:
                barrier.wait(timeout=30)
                return self.client_class(raise_request_exception=False).post(
                    "/api/device-groups",
                    data=payload,
                    content_type="application/json",
                    HTTP_AUTHORIZATION=f"Bearer {bearer}",
                    HTTP_IDEMPOTENCY_KEY=operation_id,
                )
            finally:
                connections.close_all()

        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
            futures = [executor.submit(create_group) for _index in range(32)]
            barrier.wait(timeout=30)
            responses = [future.result(timeout=120) for future in futures]

        self.assertTrue(all(response.status_code == 200 for response in responses))
        first_body = responses[0].json()
        self.assertTrue(all(response.json() == first_body for response in responses))
        self.assertEqual(DeviceGroup.objects.filter(name="state040-concurrent-group").count(), 1)
        self.assertEqual(ManagementBatchOperation.objects.filter(operation_id=operation_id).count(), 1)
