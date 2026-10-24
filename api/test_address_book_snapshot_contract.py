"""Read snapshots required by the mandatory Native/CLI mutation protocol."""

import hashlib
import json
import uuid
from pathlib import Path
from unittest.mock import patch

from django.db import transaction
from django.test import SimpleTestCase, TestCase

from api.address_book_authorization import bump_locked_authorization_generation
from api.management_operations import document_digest
from api.models import AddressBookProfile, ManagementBatchOperation, RemoteDevice, RemotePeer, RemoteTag, UserProfile
from api.views_api import _issue_access_token


class AddressBookMutationDigestCorpusTests(SimpleTestCase):
    def test_shared_native_digest_corpus_matches_provider_canonical_document(self):
        corpus = json.loads(
            (Path(__file__).parent / "fixtures" / "address_book_mutations_v1.json").read_text(encoding="utf-8")
        )
        self.assertEqual(corpus["version"], 1)
        self.assertEqual(len(corpus["vectors"]), 7)
        for vector in corpus["vectors"]:
            with self.subTest(name=vector["name"]):
                document = {
                    "operation": vector["operation"],
                    "method": vector["method"],
                    "path": vector["path"],
                    "args": {},
                    "body_sha256": hashlib.sha256(vector["body"].encode("utf-8")).hexdigest(),
                    "expected_generation": vector["expected_generation"],
                }
                self.assertEqual(document_digest(document), vector["request_digest"])


class AddressBookSnapshotContractTests(TestCase):
    def setUp(self):
        self.user = UserProfile.objects.create_superuser("snapshot-admin", "isolated-snapshot-test-password")
        device = RemoteDevice.objects.create(
            rid="840044001",
            uuid="snapshot-auth-device",
            owner=self.user,
            hostname="snapshot-host",
            username=self.user.username,
            is_active=True,
            cpu="-",
            memory="-",
            os="test",
            version="test",
        )
        _, self.token = _issue_access_token(self.user, device)
        self.personal = self.profile(f"personal-{self.user.pk}", "Snapshot personal")
        self.shared = self.profile(str(uuid.uuid4()), "Snapshot shared")
        for index in range(2):
            RemotePeer.objects.create(profile=self.shared, rid=f"84004410{index}", alias=f"snapshot-peer-{index}")
        RemoteTag.objects.create(profile=self.shared, tag_name="snapshot-tag", tag_color="1")

    def profile(self, guid, name):
        profile = AddressBookProfile.objects.create(guid=guid, name=name, owner=self.user, rule=3)
        with transaction.atomic():
            locked = AddressBookProfile.objects.select_for_update().get(pk=profile.pk)
            for _ in range(2):
                bump_locked_authorization_generation(locked)
        profile.refresh_from_db()
        return profile

    def post(self, path, body="{}"):
        return self.client.generic(
            "POST",
            path,
            data=body,
            content_type="application/json",
            CONTENT_TYPE="application/json",
            CONTENT_LENGTH=str(len(body.encode("utf-8"))),
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

    def assert_snapshot(self, response, profile):
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertIsInstance(body, dict)
        self.assertEqual(body.get("address_book_snapshot_version"), 1)
        self.assertEqual(body.get("guid"), profile.guid)
        self.assertEqual(body.get("authorization_generation"), profile.authorization_generation)
        return body

    def test_personal_and_catalog_expose_the_observed_generation_not_a_default_zero(self):
        self.assert_snapshot(self.post("/api/ab/personal"), self.personal)
        response = self.post("/api/ab/shared/profiles?current=1&pageSize=1")
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertEqual(body.get("address_book_snapshot_version"), 1)
        self.assertEqual(body["data"][0]["guid"], self.shared.guid)
        self.assertEqual(body["data"][0].get("authorization_generation"), self.shared.authorization_generation)

    def test_content_pages_and_tags_are_bound_to_the_same_profile_and_generation(self):
        for current in (1, 2):
            body = self.assert_snapshot(
                self.post(f"/api/ab/peers?ab={self.shared.guid}&current={current}&pageSize=1"), self.shared
            )
            self.assertEqual(len(body["data"]), 1)
            self.assertEqual(body["total"], 2)
        tags = self.assert_snapshot(self.post(f"/api/ab/tags/{self.shared.guid}"), self.shared)
        self.assertEqual(tags["data"], [{"name": "snapshot-tag", "color": 1}])
        self.assertEqual(tags["total"], 1)
        self.assertEqual(ManagementBatchOperation.objects.count(), 0)

    def test_read_contract_stays_post_query_and_rejects_ignored_json_selectors(self):
        for path in (
            "/api/ab/personal",
            "/api/ab/shared/profiles",
            "/api/ab/peers",
            f"/api/ab/tags/{self.shared.guid}",
        ):
            with self.subTest(path=path):
                denied = self.client.get(path, HTTP_AUTHORIZATION=f"Bearer {self.token}")
                self.assertEqual(denied.status_code, 405)
                rejected = self.post(path, '{"ab":"do-not-ignore-a-body-selector"}')
                self.assertEqual(rejected.status_code, 400, rejected.content)
        self.assertEqual(ManagementBatchOperation.objects.count(), 0)

    def test_empty_wire_body_is_accepted_but_malformed_or_oversized_bodies_are_not(self):
        for path in (
            "/api/ab/personal",
            "/api/ab/shared/profiles",
            "/api/ab/peers",
            f"/api/ab/tags/{self.shared.guid}",
        ):
            with self.subTest(path=path, body="empty"):
                self.assertEqual(self.post(path, "").status_code, 200)
            for body in ("[]", "null", "{", '{"x":1,"x":2}', '"' + "x" * 4096 + '"'):
                with self.subTest(path=path, body=body[:20]):
                    self.assertIn(self.post(path, body).status_code, (400, 413))

    def test_content_reads_recheck_authorization_under_the_profile_lock(self):
        for path in (f"/api/ab/peers?ab={self.shared.guid}", f"/api/ab/tags/{self.shared.guid}"):
            with (
                self.subTest(path=path),
                patch("api.views_api.lock_profile_access", return_value=(self.shared, None, 0)) as locked,
            ):
                self.assertEqual(self.post(path).status_code, 403)
                locked.assert_called_once_with(self.user, self.shared.pk)

    def test_read_generation_comes_from_locked_authority_not_prelock_profile(self):
        old = AddressBookProfile.objects.get(pk=self.shared.pk)
        with transaction.atomic():
            locked = AddressBookProfile.objects.select_for_update().get(pk=self.shared.pk)
            bump_locked_authorization_generation(locked)
        self.shared.refresh_from_db()
        for path in (f"/api/ab/peers?ab={self.shared.guid}", f"/api/ab/tags/{self.shared.guid}"):
            with self.subTest(path=path), patch("api.views_api._get_profile_access", return_value=(old, self.user, 3)):
                self.assert_snapshot(self.post(path), self.shared)

    def test_flutter_shaped_unguarded_writes_remain_rejected_without_mutation(self):
        for path, body in (
            (f"/api/ab/peer/add/{self.shared.guid}", '{"id":"840044999","alias":"Native peer"}'),
            (f"/api/ab/tag/add/{self.shared.guid}", '{"name":"Native tag","color":1}'),
        ):
            with self.subTest(path=path):
                response = self.post(path, body)
                self.assertEqual(response.status_code, 400)
                self.assertIn("Idempotency-Key", response.json()["message"])
        self.assertEqual(RemotePeer.objects.filter(profile=self.shared).count(), 2)
        self.assertEqual(RemoteTag.objects.filter(profile=self.shared).count(), 1)
        self.assertEqual(ManagementBatchOperation.objects.count(), 0)

    def test_observed_snapshot_authorizes_one_write_then_immutable_replay_and_readonly_recovery(self):
        for operation, method, path, body in (
            (
                "address_book_peer_add",
                "post",
                f"/api/ab/peer/add/{self.shared.guid}",
                '{"id":"840044999","alias":"原生😀"}',
            ),
            (
                "address_book_peer_update",
                "put",
                f"/api/ab/peer/update/{self.shared.guid}",
                '{"id":"840044999","alias":"更改😀","note":"native note"}',
            ),
            ("address_book_tag_add", "post", f"/api/ab/tag/add/{self.shared.guid}", '{"name":"原生😀","color":1}'),
            (
                "address_book_tag_rename",
                "put",
                f"/api/ab/tag/rename/{self.shared.guid}",
                '{"old":"原生😀","new":"更改😀"}',
            ),
            (
                "address_book_tag_update",
                "put",
                f"/api/ab/tag/update/{self.shared.guid}",
                '{"name":"更改😀","color":4281558681}',
            ),
            ("address_book_peer_delete", "delete", f"/api/ab/peer/{self.shared.guid}", '["840044999"]'),
            ("address_book_tag_delete", "delete", f"/api/ab/tag/{self.shared.guid}", '["更改😀"]'),
        ):
            with self.subTest(operation=operation):
                observed = self.post(f"/api/ab/peers?ab={self.shared.guid}").json()["authorization_generation"]
                operation_id = str(uuid.uuid4())
                headers = {
                    "HTTP_AUTHORIZATION": f"Bearer {self.token}",
                    "HTTP_IDEMPOTENCY_KEY": operation_id,
                    "HTTP_IF_MATCH": f'"{observed}"',
                }
                write = getattr(self.client, method)
                response = write(path, data=body, content_type="application/json", **headers)
                self.assertEqual(response.status_code, 200, response.content)
                receipt = response.json()
                expected_document = {
                    "operation": operation,
                    "method": method.upper(),
                    "path": path,
                    "args": {},
                    "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
                    "expected_generation": observed,
                }
                self.assertEqual(receipt["request_digest"], document_digest(expected_document))
                self.assertEqual(receipt["operation_id"], operation_id)
                self.assertEqual(receipt["applied"], {"mutations": 1})
                self.assertEqual(receipt["mutation_generations"], {self.shared.guid: observed + 1})
                replay = write(path, data=body, content_type="application/json", **headers)
                self.assertEqual(replay.json(), receipt)
                recovered = self.client.get(
                    f"/api/management-operations/{operation_id}", HTTP_AUTHORIZATION=f"Bearer {self.token}"
                )
                self.assertEqual(recovered.status_code, 200, recovered.content)
                self.assertEqual(recovered.json()["receipt"], receipt)
                stale = write(
                    path,
                    data=body,
                    content_type="application/json",
                    **{**headers, "HTTP_IDEMPOTENCY_KEY": str(uuid.uuid4())},
                )
                self.assertEqual(stale.status_code, 409)
                self.assertEqual(stale.json()["applied"], {"mutations": 0})
                self.shared.refresh_from_db()
                self.assertEqual(self.shared.authorization_generation, observed + 1)
                if operation == "address_book_peer_update":
                    peer = RemotePeer.objects.get(profile=self.shared, rid="840044999")
                    self.assertEqual(peer.alias, "更改😀")
                    self.assertEqual(peer.note, "native note")
                elif operation == "address_book_tag_update":
                    tag = RemoteTag.objects.get(profile=self.shared, tag_name="更改😀")
                    self.assertEqual(int(tag.tag_color), 4281558681)
        self.assertFalse(RemotePeer.objects.filter(profile=self.shared, rid="840044999").exists())
        self.assertFalse(RemoteTag.objects.filter(profile=self.shared, tag_name="更改😀").exists())
        self.assertEqual(ManagementBatchOperation.objects.count(), 14)  # seven writes and seven stale rejections
