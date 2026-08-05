import datetime
import hashlib
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from unittest.mock import patch
from urllib.parse import urlencode

from django.db import DatabaseError, close_old_connections, connection
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from api.models import RecordingUpload, RecordingUploadChunk, RemoteDevice, RemoteToken, UserProfile

PROTOCOL_VERSION = "2"


class RecordingUploadStateMachineTests(TestCase):
    def setUp(self):
        self.user = UserProfile.objects.create_user(
            username="recording-owner",
            password="recording-owner-password",  # noqa: S106 - isolated test credential
        )
        self.device = RemoteDevice.objects.create(
            rid="123456789",
            cpu="-",
            hostname="recorder",
            memory="-",
            os="linux",
            uuid="recording-device-uuid",
            public_key_hash=hashlib.sha256(b"recording-public-key").hexdigest(),
            username="recorder",
            version="test",
            owner=self.user,
        )
        self.raw_token = "recording-device-token"  # noqa: S105 - isolated test token
        RemoteToken.objects.create(
            device=self.device,
            subject_user=self.user,
            access_token=hashlib.sha256(self.raw_token.encode()).hexdigest(),
            credential_hash=self.user.get_session_auth_hash(),
            expires_at=timezone.now() + datetime.timedelta(hours=1),
        )
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {self.raw_token}"}
        self.upload_root = tempfile.TemporaryDirectory()
        self.settings_override = override_settings(
            RECORD_UPLOAD_ROOT=Path(self.upload_root.name),
            RECORD_UPLOAD_MAX_CHUNK_BYTES=1024,
            RECORD_UPLOAD_MAX_FILE_BYTES=4096,
            DATA_UPLOAD_MAX_MEMORY_SIZE=1024,
        )
        self.settings_override.enable()

    def tearDown(self):
        self.settings_override.disable()
        self.upload_root.cleanup()

    def _request(self, operation, body=b"", **params):
        query = {
            "version": PROTOCOL_VERSION,
            "type": operation,
            **{key: str(value) for key, value in params.items()},
        }
        return self.client.post(
            f"/api/record?{urlencode(query)}",
            data=body,
            content_type="application/octet-stream",
            **self.headers,
        )

    def _create(self, *, create_id="11111111-1111-4111-8111-111111111111", filename="session.webm"):
        response = self._request("new", file=filename, create_id=create_id)
        self.assertEqual(response.status_code, 201, response.content)
        state = response.json()
        self.assertEqual(state["protocol"], 2)
        self.assertEqual(state["state"], "active")
        self.assertEqual(state["offset"], 0)
        self.assertEqual(state["revision"], 0)
        self.assertFalse(state["finalized"])
        return state

    def _part(self, state, data, *, chunk_id="22222222-2222-4222-8222-222222222222", **overrides):
        params = {
            "upload_id": state["upload_id"],
            "offset": state["offset"],
            "revision": state["revision"],
            "length": len(data),
            "digest": hashlib.sha256(data).hexdigest(),
            "chunk_id": chunk_id,
            **overrides,
        }
        return self._request("part", body=data, **params)

    def test_v1_operations_are_explicitly_rejected_without_creating_files(self):
        response = self.client.post(
            "/api/record?type=new&file=legacy.webm",
            data=b"",
            content_type="application/octet-stream",
            **self.headers,
        )

        self.assertEqual(response.status_code, 426, response.content)
        self.assertEqual(response.json()["required_protocol"], 2)
        self.assertEqual(list(Path(self.upload_root.name).rglob("legacy.webm")), [])

    def test_create_and_committed_chunk_are_idempotent_after_response_loss(self):
        state = self._create()
        replayed_create = self._request(
            "new",
            file="session.webm",
            create_id="11111111-1111-4111-8111-111111111111",
        )
        self.assertEqual(replayed_create.status_code, 200, replayed_create.content)
        self.assertEqual(replayed_create.json(), state)

        committed = self._part(state, b"data")
        self.assertEqual(committed.status_code, 200, committed.content)
        committed_state = committed.json()
        self.assertEqual(committed_state["offset"], 4)
        self.assertEqual(committed_state["revision"], 1)

        replayed_chunk = self._part(state, b"data")
        self.assertEqual(replayed_chunk.status_code, 200, replayed_chunk.content)
        self.assertEqual(replayed_chunk.json(), committed_state)

        conflicting_replay = self._part(state, b"evil")
        self.assertEqual(conflicting_replay.status_code, 409, conflicting_replay.content)
        out_of_order = self._part(
            state,
            b"next",
            chunk_id="55555555-5555-4555-8555-555555555555",
            offset=1,
        )
        self.assertEqual(out_of_order.status_code, 409, out_of_order.content)
        status = self._request("status", upload_id=state["upload_id"])
        self.assertEqual(status.status_code, 200, status.content)
        self.assertEqual(status.json(), committed_state)

        exact_receipt = self._request(
            "status",
            upload_id=state["upload_id"],
            chunk_id="22222222-2222-4222-8222-222222222222",
            offset=0,
            revision=0,
            length=4,
            digest=hashlib.sha256(b"data").hexdigest(),
        )
        self.assertEqual(exact_receipt.status_code, 200, exact_receipt.content)
        self.assertTrue(exact_receipt.json()["queried_chunk_committed"])
        competing_identity = self._request(
            "status",
            upload_id=state["upload_id"],
            chunk_id="77777777-7777-4777-8777-777777777777",
            offset=0,
            revision=0,
            length=4,
            digest=hashlib.sha256(b"data").hexdigest(),
        )
        self.assertEqual(competing_identity.status_code, 200, competing_identity.content)
        self.assertFalse(competing_identity.json()["queried_chunk_committed"])
        conflicting_identity = self._request(
            "status",
            upload_id=state["upload_id"],
            chunk_id="22222222-2222-4222-8222-222222222222",
            offset=0,
            revision=0,
            length=4,
            digest=hashlib.sha256(b"evil").hexdigest(),
        )
        self.assertEqual(conflicting_identity.status_code, 409, conflicting_identity.content)

    def test_create_row_without_initial_staging_file_is_recovered_only_at_zero_revision(self):
        state = self._create(filename="create-recovery.webm")
        staging = next(Path(self.upload_root.name).glob("*/.uploads/*.part"))
        staging.unlink()

        status = self._request("status", upload_id=state["upload_id"])
        self.assertEqual(status.status_code, 200, status.content)
        self.assertEqual(status.json(), state)
        self.assertTrue(staging.exists())

        committed = self._part(state, b"recover")
        self.assertEqual(committed.status_code, 200, committed.content)
        staging.unlink()
        missing_after_commit = self._request("status", upload_id=state["upload_id"])
        self.assertEqual(missing_after_commit.status_code, 500, missing_after_commit.content)

    def test_zero_byte_finalize_and_abort_recover_missing_initial_staging(self):
        finalized = self._create(filename="empty-finalize-recovery.webm")
        staging = next(Path(self.upload_root.name).glob("*/.uploads/*.part"))
        staging.unlink()
        digest = hashlib.sha256(b"").hexdigest()
        finalized_response = self._request(
            "finalize",
            upload_id=finalized["upload_id"],
            revision=0,
            final_size=0,
            final_digest=digest,
        )
        self.assertEqual(finalized_response.status_code, 200, finalized_response.content)
        self.assertTrue((staging.parent.parent / "empty-finalize-recovery.webm").exists())

        aborted = self._create(
            create_id="66666666-6666-4666-8666-666666666666",
            filename="empty-abort-recovery.webm",
        )
        abort_staging = next(path for path in Path(self.upload_root.name).glob("*/.uploads/*.part") if path != staging)
        abort_staging.unlink()
        aborted_response = self._request("abort", upload_id=aborted["upload_id"])
        self.assertEqual(aborted_response.status_code, 200, aborted_response.content)
        self.assertEqual(aborted_response.json()["state"], "aborted")

    def test_partial_write_is_truncated_to_last_committed_revision(self):
        state = self._create(filename="partial.webm")

        def fail_after_partial_write(fd, data):
            self.assertEqual(data, b"durable")
            self.assertEqual(os.write(fd, data[:2]), 2)
            raise OSError("injected short filesystem write")

        with patch("api.recording_uploads._write_all", side_effect=fail_after_partial_write):
            failed = self._part(state, b"durable")
        self.assertEqual(failed.status_code, 500, failed.content)

        status = self._request("status", upload_id=state["upload_id"])
        self.assertEqual(status.status_code, 200, status.content)
        self.assertEqual(status.json()["offset"], 0)
        self.assertEqual(status.json()["revision"], 0)
        partials = list(Path(self.upload_root.name).rglob("*.part"))
        self.assertEqual(len(partials), 1)
        self.assertEqual(partials[0].read_bytes(), b"")

        retried = self._part(state, b"durable")
        self.assertEqual(retried.status_code, 200, retried.content)
        self.assertEqual(retried.json()["offset"], 7)

    def test_database_failure_rolls_file_mutations_back_before_retry(self):
        state = self._create(filename="database-rollback.webm")
        original_save = RecordingUpload.save

        def fail_chunk_commit(instance, *args, **kwargs):
            if "committed_offset" in (kwargs.get("update_fields") or ()):
                raise DatabaseError("injected recording state commit failure")
            return original_save(instance, *args, **kwargs)

        with patch.object(RecordingUpload, "save", fail_chunk_commit):
            failed_chunk = self._part(state, b"rollback")
        self.assertEqual(failed_chunk.status_code, 500, failed_chunk.content)
        upload = RecordingUpload.objects.get(upload_id=state["upload_id"])
        self.assertEqual(upload.committed_offset, 0)
        self.assertEqual(upload.revision, 0)
        self.assertFalse(RecordingUploadChunk.objects.filter(upload=upload).exists())
        staging = next(Path(self.upload_root.name).glob("*/.uploads/*.part"))
        self.assertEqual(staging.read_bytes(), b"rollback")
        reconciled = self._request("status", upload_id=state["upload_id"])
        self.assertEqual(reconciled.status_code, 200, reconciled.content)
        self.assertEqual(staging.read_bytes(), b"")

        committed = self._part(state, b"rollback")
        self.assertEqual(committed.status_code, 200, committed.content)
        committed_state = committed.json()
        digest = hashlib.sha256(b"rollback").hexdigest()

        def fail_finalize_commit(instance, *args, **kwargs):
            if "state" in (kwargs.get("update_fields") or ()):
                raise DatabaseError("injected finalize state commit failure")
            return original_save(instance, *args, **kwargs)

        with patch.object(RecordingUpload, "save", fail_finalize_commit):
            failed_finalize = self._request(
                "finalize",
                upload_id=state["upload_id"],
                revision=committed_state["revision"],
                final_size=committed_state["offset"],
                final_digest=digest,
            )
        self.assertEqual(failed_finalize.status_code, 500, failed_finalize.content)
        upload.refresh_from_db()
        self.assertEqual(upload.state, RecordingUpload.STATE_ACTIVE)
        published = staging.parent.parent / "database-rollback.webm"
        self.assertFalse(staging.exists())
        self.assertEqual(published.read_bytes(), b"rollback")

        finalized = self._request(
            "finalize",
            upload_id=state["upload_id"],
            revision=committed_state["revision"],
            final_size=committed_state["offset"],
            final_digest=digest,
        )
        self.assertEqual(finalized.status_code, 200, finalized.content)

    def test_status_fails_closed_after_device_authority_generation_changes(self):
        state = self._create(filename="stale-authority.webm")
        RemoteDevice.objects.filter(pk=self.device.pk).update(deployment_generation=1)

        stale = self._request("status", upload_id=state["upload_id"])

        self.assertEqual(stale.status_code, 409, stale.content)
        self.assertEqual(stale.json()["code"], "upload_authority_changed")
        upload = RecordingUpload.objects.get(upload_id=state["upload_id"])
        self.assertEqual(upload.state, RecordingUpload.STATE_ACTIVE)
        self.assertEqual(upload.committed_offset, 0)

    def test_finalize_publishes_only_verified_bytes_and_freezes_upload(self):
        state = self._create(filename="finished.webm")
        committed = self._part(state, b"complete-recording")
        self.assertEqual(committed.status_code, 200, committed.content)
        committed_state = committed.json()
        digest = hashlib.sha256(b"complete-recording").hexdigest()

        wrong_digest = self._request(
            "finalize",
            upload_id=state["upload_id"],
            revision=committed_state["revision"],
            final_size=committed_state["offset"],
            final_digest="0" * 64,
        )
        self.assertEqual(wrong_digest.status_code, 409, wrong_digest.content)
        self.assertEqual(list(Path(self.upload_root.name).rglob("finished.webm")), [])

        finalized = self._request(
            "finalize",
            upload_id=state["upload_id"],
            revision=committed_state["revision"],
            final_size=committed_state["offset"],
            final_digest=digest,
        )
        self.assertEqual(finalized.status_code, 200, finalized.content)
        final_state = finalized.json()
        self.assertEqual(final_state["state"], "finalized")
        self.assertTrue(final_state["finalized"])
        self.assertEqual(final_state["final_size"], len(b"complete-recording"))
        self.assertEqual(final_state["final_digest"], digest)
        published = list(Path(self.upload_root.name).glob("*/finished.webm"))
        self.assertEqual(len(published), 1)
        self.assertEqual(published[0].read_bytes(), b"complete-recording")
        self.assertEqual(list(Path(self.upload_root.name).rglob("*.part")), [])

        replayed_finalize = self._request(
            "finalize",
            upload_id=state["upload_id"],
            revision=committed_state["revision"],
            final_size=committed_state["offset"],
            final_digest=digest,
        )
        self.assertEqual(replayed_finalize.status_code, 200, replayed_finalize.content)
        self.assertEqual(replayed_finalize.json(), final_state)

        post_finalize_part = self._part(
            committed_state,
            b"extra",
            chunk_id="33333333-3333-4333-8333-333333333333",
        )
        self.assertEqual(post_finalize_part.status_code, 409, post_finalize_part.content)
        self.assertEqual(published[0].read_bytes(), b"complete-recording")

    def test_finalize_recovers_rename_that_preceded_database_commit(self):
        state = self._create(filename="rename-recovery.webm")
        committed = self._part(state, b"rename-recovery").json()
        digest = hashlib.sha256(b"rename-recovery").hexdigest()
        staging = next(Path(self.upload_root.name).glob("*/.uploads/*.part"))
        published = staging.parent.parent / "rename-recovery.webm"
        staging.rename(published)

        recovered = self._request(
            "finalize",
            upload_id=state["upload_id"],
            revision=committed["revision"],
            final_size=committed["offset"],
            final_digest=digest,
        )

        self.assertEqual(recovered.status_code, 200, recovered.content)
        self.assertEqual(recovered.json()["state"], "finalized")
        self.assertEqual(published.read_bytes(), b"rename-recovery")

    def test_abort_recovers_tomb_that_preceded_database_commit(self):
        state = self._create(filename="abort-recovery.webm")
        staging = next(Path(self.upload_root.name).glob("*/.uploads/*.part"))
        tomb = staging.with_suffix(".aborted")
        staging.rename(tomb)

        recovered = self._request("abort", upload_id=state["upload_id"])

        self.assertEqual(recovered.status_code, 200, recovered.content)
        self.assertEqual(recovered.json()["state"], "aborted")
        self.assertFalse(tomb.exists())
        replayed = self._request("abort", upload_id=state["upload_id"])
        self.assertEqual(replayed.status_code, 200, replayed.content)

    def test_abort_database_failure_restores_staging_before_retry(self):
        state = self._create(filename="abort-database-rollback.webm")
        staging = next(Path(self.upload_root.name).glob("*/.uploads/*.part"))
        original_save = RecordingUpload.save

        def fail_abort_commit(instance, *args, **kwargs):
            if "state" in (kwargs.get("update_fields") or ()):
                raise DatabaseError("injected abort state commit failure")
            return original_save(instance, *args, **kwargs)

        with patch.object(RecordingUpload, "save", fail_abort_commit):
            failed = self._request("abort", upload_id=state["upload_id"])
        self.assertEqual(failed.status_code, 500, failed.content)
        upload = RecordingUpload.objects.get(upload_id=state["upload_id"])
        self.assertEqual(upload.state, RecordingUpload.STATE_ACTIVE)
        tombs = list(Path(self.upload_root.name).rglob("*.aborted"))
        self.assertFalse(staging.exists())
        self.assertEqual(len(tombs), 1)

        retried = self._request("abort", upload_id=state["upload_id"])
        self.assertEqual(retried.status_code, 200, retried.content)
        self.assertEqual(retried.json()["state"], "aborted")
        self.assertEqual(list(Path(self.upload_root.name).rglob("*.aborted")), [])

    def test_abort_is_idempotent_but_cannot_remove_a_finalized_recording(self):
        active = self._create(filename="aborted.webm")
        committed = self._part(active, b"discard-me")
        self.assertEqual(committed.status_code, 200, committed.content)

        aborted = self._request("abort", upload_id=active["upload_id"])
        self.assertEqual(aborted.status_code, 200, aborted.content)
        self.assertEqual(aborted.json()["state"], "aborted")
        replayed_abort = self._request("abort", upload_id=active["upload_id"])
        self.assertEqual(replayed_abort.status_code, 200, replayed_abort.content)
        self.assertEqual(replayed_abort.json(), aborted.json())
        self.assertEqual(list(Path(self.upload_root.name).rglob("*.part")), [])

        finalized = self._create(
            create_id="44444444-4444-4444-8444-444444444444",
            filename="retained.webm",
        )
        digest = hashlib.sha256(b"").hexdigest()
        response = self._request(
            "finalize",
            upload_id=finalized["upload_id"],
            revision=0,
            final_size=0,
            final_digest=digest,
        )
        self.assertEqual(response.status_code, 200, response.content)
        rejected = self._request("abort", upload_id=finalized["upload_id"])
        self.assertEqual(rejected.status_code, 409, rejected.content)
        self.assertEqual(len(list(Path(self.upload_root.name).glob("*/retained.webm"))), 1)


class RecordingUploadConcurrencyTests(TransactionTestCase):
    def setUp(self):
        if connection.vendor != "postgresql":
            self.skipTest("recording upload concurrency requires PostgreSQL row locks")
        self.user = UserProfile.objects.create_user(
            username="recording-concurrency-owner",
            password="recording-concurrency-password",  # noqa: S106 - isolated test credential
        )
        self.device = RemoteDevice.objects.create(
            rid="987654321",
            cpu="-",
            hostname="concurrent-recorder",
            memory="-",
            os="linux",
            uuid="recording-concurrency-device-uuid",
            public_key_hash=hashlib.sha256(b"recording-concurrency-public-key").hexdigest(),
            username="recorder",
            version="test",
            owner=self.user,
        )
        self.raw_token = "recording-concurrency-device-token"  # noqa: S105 - isolated test token
        RemoteToken.objects.create(
            device=self.device,
            subject_user=self.user,
            access_token=hashlib.sha256(self.raw_token.encode()).hexdigest(),
            credential_hash=self.user.get_session_auth_hash(),
            expires_at=timezone.now() + datetime.timedelta(hours=1),
        )
        self.upload_root = tempfile.TemporaryDirectory()
        self.settings_override = override_settings(
            RECORD_UPLOAD_ROOT=Path(self.upload_root.name),
            RECORD_UPLOAD_MAX_CHUNK_BYTES=1024,
            RECORD_UPLOAD_MAX_FILE_BYTES=4096,
            DATA_UPLOAD_MAX_MEMORY_SIZE=1024,
        )
        self.settings_override.enable()

    def tearDown(self):
        if hasattr(self, "settings_override"):
            self.settings_override.disable()
        if hasattr(self, "upload_root"):
            self.upload_root.cleanup()

    def _create(self, filename):
        response = self.client.post(
            "/api/record?"
            + urlencode(
                {
                    "version": PROTOCOL_VERSION,
                    "type": "new",
                    "file": filename,
                    "create_id": "88888888-8888-4888-8888-888888888888",
                }
            ),
            data=b"",
            content_type="application/octet-stream",
            HTTP_AUTHORIZATION=f"Bearer {self.raw_token}",
        )
        self.assertEqual(response.status_code, 201, response.content)
        return response.json()

    def _concurrent_parts(self, state, chunk_ids):
        body = b"concurrent"
        barrier = Barrier(len(chunk_ids))

        def send(chunk_id):
            close_old_connections()
            client = Client()
            barrier.wait(timeout=5)
            try:
                response = client.post(
                    "/api/record?"
                    + urlencode(
                        {
                            "version": PROTOCOL_VERSION,
                            "type": "part",
                            "upload_id": state["upload_id"],
                            "chunk_id": chunk_id,
                            "offset": 0,
                            "revision": 0,
                            "length": len(body),
                            "digest": hashlib.sha256(body).hexdigest(),
                        }
                    ),
                    data=body,
                    content_type="application/octet-stream",
                    HTTP_AUTHORIZATION=f"Bearer {self.raw_token}",
                )
                return response.status_code, response.json()
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=len(chunk_ids)) as executor:
            return list(executor.map(send, chunk_ids))

    def test_concurrent_duplicate_chunk_commits_once_and_acknowledges_both(self):
        state = self._create("concurrent-duplicate.webm")
        chunk_id = "99999999-9999-4999-8999-999999999999"

        responses = self._concurrent_parts(state, [chunk_id, chunk_id])

        self.assertEqual([status for status, _payload in responses], [200, 200])
        self.assertEqual(responses[0][1], responses[1][1])
        self.assertEqual(RecordingUploadChunk.objects.count(), 1)
        staging = next(Path(self.upload_root.name).glob("*/.uploads/*.part"))
        self.assertEqual(staging.read_bytes(), b"concurrent")

    def test_concurrent_distinct_chunk_ids_allow_only_one_revision_winner(self):
        state = self._create("concurrent-conflict.webm")

        responses = self._concurrent_parts(
            state,
            [
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            ],
        )

        self.assertEqual(sorted(status for status, _payload in responses), [200, 409])
        self.assertEqual(RecordingUploadChunk.objects.count(), 1)
        staging = next(Path(self.upload_root.name).glob("*/.uploads/*.part"))
        self.assertEqual(staging.read_bytes(), b"concurrent")
