import datetime
import hashlib
import json
import os
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO, StringIO
from pathlib import Path
from threading import Barrier, Event
from types import SimpleNamespace
from unittest.mock import PropertyMock, patch
from urllib.parse import urlencode

from django.core.handlers.wsgi import WSGIRequest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError, close_old_connections, connection, connections, transaction
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from api import ingestion_governance, recording_crypto, recording_inventory
from api.models import (
    PersistentIngestionUsage,
    RecordingBackupControl,
    RecordingBackupEpoch,
    RecordingBackupObject,
    RecordingUpload,
    RecordingUploadChunk,
    RemoteDevice,
    RemoteToken,
    UserProfile,
)

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
            RECORD_UPLOAD_REQUIRE_MOUNT=False,
            RECORD_UPLOAD_VOLUME_RESERVE_BYTES=0,
            RECORD_UPLOAD_VOLUME_RESERVE_INODES=0,
            RECORD_UPLOAD_CAPABILITY_CACHE_SECONDS=0,
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

    def _assert_authenticated_recording(self, upload_id, path, expected):
        upload = RecordingUpload.objects.get(upload_id=upload_id)
        fd = os.open(path, os.O_RDONLY)
        try:
            actual_size, actual_digest = recording_crypto.verify_recording_fd(
                fd,
                upload_id=upload.upload_id,
                data_key=recording_crypto.decode_data_key(upload.encrypted_data_key),
                receipts=upload.chunks.order_by("revision"),
                expected_revision=upload.revision,
                expected_storage_offset=upload.storage_offset,
                max_chunk_bytes=1024,
            )
        finally:
            os.close(fd)
        self.assertEqual(actual_size, len(expected))
        self.assertEqual(actual_digest, hashlib.sha256(expected).hexdigest())

    def _object_paths(self, upload_id):
        upload = RecordingUpload.objects.get(upload_id=upload_id)
        base = Path(self.upload_root.name) / upload.storage_namespace
        return (
            base / ".uploads" / f"{upload.storage_object_id}.part",
            base / f"{upload.storage_object_id}.recording",
        )

    @override_settings(
        RECORD_UPLOAD_MAX_ACTIVE_PER_DEVICE=1,
        RECORD_UPLOAD_MAX_ACTIVE_PER_OWNER=1,
        RECORD_UPLOAD_MAX_ACTIVE_GLOBAL=1,
        RECORD_UPLOAD_MAX_FILES_PER_DEVICE=1,
        RECORD_UPLOAD_MAX_FILES_PER_OWNER=1,
        RECORD_UPLOAD_MAX_FILES_GLOBAL=1,
    )
    def test_create_reserves_hard_aggregate_file_and_active_upload_quota(self):
        self._create(filename="first.webm")

        denied = self._request(
            "new",
            file="second.webm",
            create_id="99999999-9999-4999-8999-999999999999",
        )

        self.assertEqual(denied.status_code, 507, denied.content)
        self.assertEqual(denied.json()["code"], "recording_quota_exceeded")
        self.assertEqual(RecordingUpload.objects.count(), 1)

    @override_settings(
        RECORD_UPLOAD_MAX_BYTES_PER_DEVICE=3,
        RECORD_UPLOAD_MAX_BYTES_PER_OWNER=3,
        RECORD_UPLOAD_MAX_BYTES_GLOBAL=3,
    )
    def test_chunk_reserves_hard_aggregate_committed_byte_quota(self):
        state = self._create(filename="bytes.webm")

        denied = self._part(state, b"four")

        self.assertEqual(denied.status_code, 507, denied.content)
        self.assertEqual(denied.json()["code"], "recording_quota_exceeded")
        upload = RecordingUpload.objects.get()
        self.assertEqual(upload.committed_offset, 0)
        self.assertEqual(RecordingUploadChunk.objects.count(), 0)

    def test_unavailable_storage_rejects_before_request_body_materialization(self):
        storage_error = ingestion_governance.RecordingStorageUnavailable("Recording storage is unavailable")
        with (
            patch.object(WSGIRequest, "body", new_callable=PropertyMock, create=True) as request_body,
            patch.object(
                ingestion_governance,
                "check_recording_storage_capability",
                side_effect=storage_error,
            ),
        ):
            request_body.side_effect = AssertionError("request body was materialized before storage admission")
            response = self._request(
                "part",
                body=b"must-not-be-read",
                upload_id="11111111-1111-4111-8111-111111111111",
                chunk_id="22222222-2222-4222-8222-222222222222",
                offset=0,
                revision=0,
                length=16,
                digest=hashlib.sha256(b"must-not-be-read").hexdigest(),
            )

        self.assertEqual(response.status_code, 503, response.content)
        self.assertEqual(response.json()["code"], "recording_storage_unavailable")
        request_body.assert_not_called()

    def test_published_recording_is_authenticated_ciphertext_at_rest(self):
        canary = b"FULL-SESSION-PLAINTEXT-CANARY"
        state = self._create(filename="encrypted.webm")
        committed = self._part(state, canary).json()

        finalized = self._request(
            "finalize",
            upload_id=state["upload_id"],
            revision=committed["revision"],
            final_size=len(canary),
            final_digest=hashlib.sha256(canary).hexdigest(),
        )

        self.assertEqual(finalized.status_code, 200, finalized.content)
        _staging, published = self._object_paths(state["upload_id"])
        self.assertTrue(published.is_file())
        stored = published.read_bytes()
        self.assertNotIn(canary, stored)
        self.assertNotEqual(stored, canary)

    def test_deleted_device_identity_cannot_reenter_an_old_recording_object_namespace(self):
        old_state = self._create(filename="generation-isolated.webm")
        old_committed = self._part(old_state, b"old-generation").json()
        old_finalized = self._request(
            "finalize",
            upload_id=old_state["upload_id"],
            revision=old_committed["revision"],
            final_size=len(b"old-generation"),
            final_digest=hashlib.sha256(b"old-generation").hexdigest(),
        )
        self.assertEqual(old_finalized.status_code, 200, old_finalized.content)
        old_upload = RecordingUpload.objects.get(pk=old_state["upload_id"])
        old_namespace = old_upload.storage_namespace
        old_object = (
            Path(self.upload_root.name) / old_upload.storage_namespace / f"{old_upload.storage_object_id}.recording"
        )

        self.device.delete()
        replacement = RemoteDevice.objects.create(
            rid="123456789",
            cpu="-",
            hostname="replacement-recorder",
            memory="-",
            os="linux",
            uuid="recording-device-uuid",
            public_key_hash=hashlib.sha256(b"replacement-recording-public-key").hexdigest(),
            username="recorder",
            version="test",
            owner=self.user,
        )
        RemoteToken.objects.create(
            device=replacement,
            subject_user=self.user,
            access_token=hashlib.sha256(self.raw_token.encode()).hexdigest(),
            credential_hash=self.user.get_session_auth_hash(),
            expires_at=timezone.now() + datetime.timedelta(hours=1),
        )

        new_state = self._create(
            create_id="99999999-9999-4999-8999-999999999999",
            filename="generation-isolated.webm",
        )
        new_upload = RecordingUpload.objects.get(pk=new_state["upload_id"])

        self.assertNotEqual(new_upload.storage_namespace, old_namespace)
        self.assertNotEqual(new_upload.storage_object_id, old_upload.storage_object_id)
        self.assertTrue(old_object.exists())
        new_committed = self._part(new_state, b"new-generation").json()
        new_finalized = self._request(
            "finalize",
            upload_id=new_state["upload_id"],
            revision=new_committed["revision"],
            final_size=len(b"new-generation"),
            final_digest=hashlib.sha256(b"new-generation").hexdigest(),
        )
        self.assertEqual(new_finalized.status_code, 200, new_finalized.content)
        self.assertTrue(old_object.exists())

    def test_backup_epoch_blocks_mutation_and_round_trips_authoritative_ciphertext_inventory(self):
        plaintext = b"backup-recording-ciphertext"
        state = self._create(filename="backup.webm")
        committed = self._part(state, plaintext).json()
        finalized = self._request(
            "finalize",
            upload_id=state["upload_id"],
            revision=committed["revision"],
            final_size=len(plaintext),
            final_digest=hashlib.sha256(plaintext).hexdigest(),
        )
        self.assertEqual(finalized.status_code, 200, finalized.content)
        _staging, published = self._object_paths(state["upload_id"])

        epoch = recording_inventory.begin_backup(
            "0123456789abcdef0123456789abcdef",
            "20260806T001500Z",
        )

        self.assertEqual((epoch.inventory_count, epoch.object_count), (1, 1))
        snapshot = RecordingBackupObject.objects.get(epoch=epoch)
        upload = RecordingUpload.objects.get(pk=state["upload_id"])
        self.assertEqual(snapshot.storage_object_id, upload.storage_object_id)
        self.assertEqual(snapshot.deployment_generation, upload.deployment_generation)
        self.assertEqual(snapshot.ciphertext_digest, upload.ciphertext_digest)
        self.assertEqual(snapshot.plaintext_digest, hashlib.sha256(plaintext).hexdigest())
        blocked = self._request("status", upload_id=state["upload_id"])
        self.assertEqual(blocked.status_code, 503, blocked.content)
        self.assertEqual(blocked.json()["code"], "recording_backup_in_progress")

        bundle = BytesIO()
        recording_inventory.export_backup(epoch.backup_id, bundle)
        published.unlink()
        recording_uploads_dir = published.parent
        recording_inventory.restore_backup(
            epoch.backup_id,
            str(epoch.epoch_id),
            epoch.inventory_digest,
            BytesIO(bundle.getvalue()),
        )

        self.assertTrue(published.is_file())
        self._assert_authenticated_recording(state["upload_id"], published, plaintext)
        self.assertIsNone(RecordingBackupControl.objects.get(singleton=1).active_epoch_id)
        self.assertEqual(recording_uploads_dir.stat().st_mode & 0o077, 0)

    def test_backup_epoch_rejects_missing_extra_and_corrupt_recording_objects(self):
        scenarios = ("missing", "extra", "corrupt")
        for index, scenario in enumerate(scenarios, start=1):
            with self.subTest(scenario=scenario):
                state = self._create(
                    create_id=str(uuid.uuid4()),
                    filename=f"{scenario}.webm",
                )
                committed = self._part(state, scenario.encode(), chunk_id=str(uuid.uuid4())).json()
                finalized = self._request(
                    "finalize",
                    upload_id=state["upload_id"],
                    revision=committed["revision"],
                    final_size=len(scenario),
                    final_digest=hashlib.sha256(scenario.encode()).hexdigest(),
                )
                self.assertEqual(finalized.status_code, 200, finalized.content)
                _staging, published = self._object_paths(state["upload_id"])
                if scenario == "missing":
                    published.unlink()
                elif scenario == "extra":
                    namespace = Path(self.upload_root.name) / ("f" * 64)
                    namespace.mkdir()
                    (namespace / f"{uuid.uuid4()}.recording").write_bytes(b"extra")
                else:
                    corrupted = bytearray(published.read_bytes())
                    corrupted[-1] ^= 1
                    published.write_bytes(corrupted)

                with self.assertRaises(recording_inventory.RecordingInventoryError):
                    recording_inventory.begin_backup(
                        f"{index:032x}",
                        f"20260806T00150{index}Z",
                    )
                self.assertIsNone(RecordingBackupControl.objects.get(singleton=1).active_epoch_id)

                RecordingUpload.objects.all().delete()
                for child in Path(self.upload_root.name).iterdir():
                    if child.is_dir():
                        for path in sorted(child.rglob("*"), reverse=True):
                            if path.is_file() or path.is_symlink():
                                path.unlink()
                            elif path.is_dir():
                                path.rmdir()
                        child.rmdir()

    def test_zero_byte_recording_has_an_authenticated_nonempty_header(self):
        state = self._create(filename="empty-encrypted.webm")
        staging = next(Path(self.upload_root.name).glob("*/.uploads/*.part"))
        self.assertEqual(staging.stat().st_size, recording_crypto.HEADER_SIZE)
        self.assertNotEqual(staging.read_bytes(), b"")
        digest = hashlib.sha256(b"").hexdigest()

        finalized = self._request(
            "finalize",
            upload_id=state["upload_id"],
            revision=0,
            final_size=0,
            final_digest=digest,
        )

        self.assertEqual(finalized.status_code, 200, finalized.content)
        _staging, published = self._object_paths(state["upload_id"])
        self._assert_authenticated_recording(state["upload_id"], published, b"")
        corrupted = bytearray(published.read_bytes())
        corrupted[-1] ^= 1
        published.write_bytes(corrupted)
        replay = self._request(
            "finalize",
            upload_id=state["upload_id"],
            revision=0,
            final_size=0,
            final_digest=digest,
        )
        self.assertEqual(replay.status_code, 500, replay.content)
        self.assertEqual(replay.json()["code"], "storage_failed")

    def test_multi_chunk_recording_is_streamed_as_authenticated_ciphertext(self):
        first_canary = b"FIRST-RECORDING-CHUNK-CANARY"
        second_canary = b"SECOND-RECORDING-CHUNK-CANARY"
        plaintext = first_canary + second_canary
        state = self._create(filename="multi-encrypted.webm")
        first = self._part(state, first_canary).json()
        second = self._part(
            first,
            second_canary,
            chunk_id="33333333-3333-4333-8333-333333333333",
        ).json()
        staging = next(Path(self.upload_root.name).glob("*/.uploads/*.part"))
        ciphertext = staging.read_bytes()
        self.assertNotIn(first_canary, ciphertext)
        self.assertNotIn(second_canary, ciphertext)
        upload = RecordingUpload.objects.get(pk=state["upload_id"])
        self.assertEqual(
            upload.storage_offset,
            recording_crypto.HEADER_SIZE
            + recording_crypto.chunk_record_size(len(first_canary))
            + recording_crypto.chunk_record_size(len(second_canary)),
        )

        finalized = self._request(
            "finalize",
            upload_id=state["upload_id"],
            revision=second["revision"],
            final_size=len(plaintext),
            final_digest=hashlib.sha256(plaintext).hexdigest(),
        )

        self.assertEqual(finalized.status_code, 200, finalized.content)
        _staging, published = self._object_paths(state["upload_id"])
        self._assert_authenticated_recording(state["upload_id"], published, plaintext)

    def test_chunk_bit_flip_fails_closed_without_publishing_plaintext(self):
        plaintext = b"AUTHENTICATED-CHUNK-BIT-FLIP-CANARY"
        state = self._create(filename="bit-flip.webm")
        committed = self._part(state, plaintext).json()
        staging = next(Path(self.upload_root.name).glob("*/.uploads/*.part"))
        corrupted = bytearray(staging.read_bytes())
        corrupted[-1] ^= 1
        staging.write_bytes(corrupted)

        rejected = self._request(
            "finalize",
            upload_id=state["upload_id"],
            revision=committed["revision"],
            final_size=len(plaintext),
            final_digest=hashlib.sha256(plaintext).hexdigest(),
        )

        self.assertEqual(rejected.status_code, 500, rejected.content)
        self.assertEqual(rejected.json()["code"], "storage_failed")
        self.assertTrue(staging.exists())
        self.assertFalse(self._object_paths(state["upload_id"])[1].exists())
        self.assertEqual(
            RecordingUpload.objects.get(pk=state["upload_id"]).state,
            RecordingUpload.STATE_ACTIVE,
        )

    def test_wrong_data_key_and_unavailable_wrapping_key_id_fail_closed(self):
        plaintext = b"WRONG-KEY-CANARY"
        state = self._create(filename="wrong-data-key.webm")
        committed = self._part(state, plaintext).json()
        RecordingUpload.objects.filter(pk=state["upload_id"]).update(
            encrypted_data_key=recording_crypto.encode_data_key(recording_crypto.generate_data_key())
        )

        wrong_data_key = self._request(
            "finalize",
            upload_id=state["upload_id"],
            revision=committed["revision"],
            final_size=len(plaintext),
            final_digest=hashlib.sha256(plaintext).hexdigest(),
        )
        self.assertEqual(wrong_data_key.status_code, 500, wrong_data_key.content)
        self.assertEqual(wrong_data_key.json()["code"], "storage_failed")

        other = self._create(
            create_id="99999999-9999-4999-8999-999999999999",
            filename="missing-wrapping-key.webm",
        )
        database_upload_id = RecordingUpload._meta.pk.get_db_prep_value(
            uuid.UUID(other["upload_id"]),
            connection,
        )
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT encrypted_data_key FROM api_recordingupload WHERE upload_id = %s",
                [database_upload_id],
            )
            envelope = cursor.fetchone()[0]
            encoded = envelope.rsplit(":", 1)[1]
            cursor.execute(
                "UPDATE api_recordingupload SET encrypted_data_key = %s WHERE upload_id = %s",
                [f"secretbox:v2:missing-key:{encoded}", database_upload_id],
            )

        missing_key = self._request("status", upload_id=other["upload_id"])
        self.assertEqual(missing_key.status_code, 500, missing_key.content)
        self.assertEqual(missing_key.json()["code"], "storage_failed")

    def test_truncated_header_record_and_tag_fail_closed(self):
        empty = self._create(filename="truncated-header.webm")
        empty_staging = next(Path(self.upload_root.name).glob("*/.uploads/*.part"))
        empty_staging.write_bytes(empty_staging.read_bytes()[:-1])
        header_rejected = self._request("status", upload_id=empty["upload_id"])
        self.assertEqual(header_rejected.status_code, 500, header_rejected.content)

        state = self._create(
            create_id="77777777-7777-4777-8777-777777777777",
            filename="truncated-record.webm",
        )
        plaintext = b"TRUNCATED-RECORD-CANARY"
        committed = self._part(state, plaintext).json()
        staging = next(path for path in Path(self.upload_root.name).glob("*/.uploads/*.part") if path != empty_staging)
        staging.write_bytes(staging.read_bytes()[:-1])
        record_rejected = self._request(
            "finalize",
            upload_id=state["upload_id"],
            revision=committed["revision"],
            final_size=len(plaintext),
            final_digest=hashlib.sha256(plaintext).hexdigest(),
        )
        self.assertEqual(record_rejected.status_code, 500, record_rejected.content)
        self.assertFalse(self._object_paths(state["upload_id"])[1].exists())

    def test_reordered_and_duplicated_chunk_records_fail_closed(self):
        def corrupt_two_chunk_recording(create_id, filename, mutation):
            first_plaintext = b"FIRST-EQUAL-SIZE-CHUNK"
            second_plaintext = b"OTHER-EQUAL-SIZE-CHUNK"
            self.assertEqual(len(first_plaintext), len(second_plaintext))
            state = self._create(create_id=create_id, filename=filename)
            first = self._part(state, first_plaintext).json()
            second = self._part(
                first,
                second_plaintext,
                chunk_id=str(uuid.uuid4()),
            ).json()
            staging, published = self._object_paths(state["upload_id"])
            raw = staging.read_bytes()
            record_size = recording_crypto.chunk_record_size(len(first_plaintext))
            header = raw[: recording_crypto.HEADER_SIZE]
            first_record = raw[recording_crypto.HEADER_SIZE : recording_crypto.HEADER_SIZE + record_size]
            second_record = raw[recording_crypto.HEADER_SIZE + record_size :]
            self.assertEqual(len(first_record), len(second_record))
            staging.write_bytes(header + mutation(first_record, second_record))
            plaintext = first_plaintext + second_plaintext
            rejected = self._request(
                "finalize",
                upload_id=state["upload_id"],
                revision=second["revision"],
                final_size=len(plaintext),
                final_digest=hashlib.sha256(plaintext).hexdigest(),
            )
            self.assertEqual(rejected.status_code, 500, rejected.content)
            self.assertFalse(published.exists())

        corrupt_two_chunk_recording(
            "44444444-4444-4444-8444-444444444444",
            "reordered.webm",
            lambda first, second: second + first,
        )
        corrupt_two_chunk_recording(
            "55555555-5555-4555-8555-555555555555",
            "duplicated.webm",
            lambda first, _second: first + first,
        )

    @override_settings(
        RECORD_UPLOAD_RETENTION_DAYS=1,
        RECORD_UPLOAD_ABORTED_RETENTION_DAYS=1,
    )
    def test_finalized_retention_releases_ledger_and_deletes_bytes_but_hold_blocks_it(self):
        state = self._create(filename="retained.webm")
        committed = self._part(state, b"data").json()
        finalized = self._request(
            "finalize",
            upload_id=state["upload_id"],
            revision=committed["revision"],
            final_size=committed["offset"],
            final_digest=hashlib.sha256(b"data").hexdigest(),
        )
        self.assertEqual(finalized.status_code, 200, finalized.content)
        upload = RecordingUpload.objects.get()
        old = timezone.now() - datetime.timedelta(days=2)
        RecordingUpload.objects.filter(pk=upload.pk).update(
            finalized_at=old,
            retention_hold=True,
            retention_hold_reason="test hold",
            retention_hold_at=timezone.now(),
        )

        call_command("purge_expired_state", batch_size=10, stdout=StringIO())
        self.assertTrue(RecordingUpload.objects.filter(pk=upload.pk).exists())
        published = self._object_paths(state["upload_id"])[1]
        self.assertTrue(published.exists())

        RecordingUpload.objects.filter(pk=upload.pk).update(retention_hold=False)
        with override_settings(
            DATA_ENCRYPTION_KEY_BYTES=b"x" * 32,
            DATA_ENCRYPTION_KEYS={"unavailable-test-key": b"x" * 32},
            DATA_ENCRYPTION_PRIMARY_KEY_ID="unavailable-test-key",
            DATA_ENCRYPTION_V1_KEY_ID="unavailable-test-key",
        ):
            call_command("purge_expired_state", batch_size=10, stdout=StringIO())

        self.assertFalse(RecordingUpload.objects.filter(pk=upload.pk).exists())
        self.assertFalse(published.exists())
        recording_usage = PersistentIngestionUsage.objects.filter(kind="recording")
        self.assertTrue(recording_usage.exists())
        for usage in recording_usage:
            self.assertEqual((usage.items, usage.active_items, usage.committed_bytes), (0, 0, 0))

    @override_settings(
        RECORD_UPLOAD_ACTIVE_TIMEOUT_MINUTES=5,
        RECORD_UPLOAD_ABORTED_RETENTION_DAYS=1,
    )
    def test_stale_partial_is_aborted_then_bounded_cleanup_removes_its_row(self):
        state = self._create(filename="stale.webm")
        committed = self._part(state, b"partial").json()
        upload = RecordingUpload.objects.get(pk=state["upload_id"])
        RecordingUpload.objects.filter(pk=upload.pk).update(
            heartbeat_at=timezone.now() - datetime.timedelta(minutes=10),
        )

        call_command("purge_expired_state", batch_size=1, stdout=StringIO())
        upload.refresh_from_db()
        self.assertEqual(upload.state, RecordingUpload.STATE_ABORTED)
        self.assertFalse(list(Path(self.upload_root.name).glob("*/.uploads/*.part")))
        self.assertEqual(committed["offset"], 7)

        RecordingUpload.objects.filter(pk=upload.pk).update(
            aborted_at=timezone.now() - datetime.timedelta(days=2),
        )
        call_command("purge_expired_state", batch_size=1, stdout=StringIO())
        self.assertFalse(RecordingUpload.objects.filter(pk=upload.pk).exists())

    @override_settings(RECORD_UPLOAD_ACTIVE_TIMEOUT_MINUTES=5)
    def test_device_delete_keeps_storage_snapshot_until_quota_releasing_cleanup(self):
        state = self._create(filename="deleted-device.webm")
        self.assertEqual(self._part(state, b"retained").status_code, 200)
        upload = RecordingUpload.objects.get(pk=state["upload_id"])
        namespace = upload.storage_namespace
        device_id = self.device.pk

        self.device.delete()

        upload.refresh_from_db()
        self.assertIsNone(upload.device_id)
        self.assertEqual(upload.device_id_at_create, device_id)
        self.assertEqual(upload.storage_namespace, namespace)
        RecordingUpload.objects.filter(pk=upload.pk).update(
            heartbeat_at=timezone.now() - datetime.timedelta(minutes=10),
        )
        call_command("purge_expired_state", batch_size=1, stdout=StringIO())
        upload.refresh_from_db()
        self.assertEqual(upload.state, RecordingUpload.STATE_ABORTED)
        for usage in PersistentIngestionUsage.objects.filter(kind="recording"):
            self.assertEqual((usage.items, usage.active_items, usage.committed_bytes), (0, 0, 0))

    def test_retention_hold_command_requires_an_admin_and_records_explicit_state(self):
        state = self._create(filename="held.webm")
        self.user.is_admin = True
        self.user.save(update_fields=("is_admin",))
        output = StringIO()

        with override_settings(
            DATA_ENCRYPTION_KEY_BYTES=b"x" * 32,
            DATA_ENCRYPTION_KEYS={"unavailable-test-key": b"x" * 32},
            DATA_ENCRYPTION_PRIMARY_KEY_ID="unavailable-test-key",
            DATA_ENCRYPTION_V1_KEY_ID="unavailable-test-key",
        ):
            call_command(
                "set_ingestion_hold",
                "recording",
                state["upload_id"],
                actor=self.user.username,
                reason="litigation request 42",
                hold=True,
                stdout=output,
            )

        upload = RecordingUpload.objects.get(pk=state["upload_id"])
        self.assertTrue(upload.retention_hold)
        self.assertIn("litigation request 42", upload.retention_hold_reason)
        self.assertIsNotNone(upload.retention_hold_at)

        with self.assertRaises(CommandError):
            call_command(
                "set_ingestion_hold",
                "recording",
                state["upload_id"],
                actor=self.user.username,
                reason="é" * 256,
                release=True,
                stdout=StringIO(),
            )

    def test_abort_moves_and_deletes_ciphertext_without_unwrapping_its_data_key(self):
        state = self._create(filename="abort-without-key.webm")
        self.assertEqual(self._part(state, b"opaque-abort").status_code, 200)

        with override_settings(
            DATA_ENCRYPTION_KEY_BYTES=b"x" * 32,
            DATA_ENCRYPTION_KEYS={"unavailable-test-key": b"x" * 32},
            DATA_ENCRYPTION_PRIMARY_KEY_ID="unavailable-test-key",
            DATA_ENCRYPTION_V1_KEY_ID="unavailable-test-key",
        ):
            aborted = self._request("abort", upload_id=state["upload_id"])

        self.assertEqual(aborted.status_code, 200, aborted.content)
        self.assertEqual(aborted.json()["state"], "aborted")
        self.assertFalse(list(Path(self.upload_root.name).rglob("*.part")))
        self.assertFalse(list(Path(self.upload_root.name).rglob("*.aborted")))

    @override_settings(RECORD_UPLOAD_ACTIVE_TIMEOUT_MINUTES=5, RECORD_UPLOAD_ORPHAN_QUARANTINE_DAYS=1)
    def test_orphan_tomb_cleanup_is_dry_run_safe_and_bounded(self):
        upload_dir = Path(self.upload_root.name) / ("a" * 64) / ".uploads"
        upload_dir.mkdir(parents=True)
        old_timestamp = (timezone.now() - datetime.timedelta(minutes=10)).timestamp()
        paths = []
        for suffix in (".part", ".aborted", ".deleting"):
            path = upload_dir / f"{uuid.uuid4()}{suffix}"
            path.write_bytes(b"orphan")
            os.utime(path, (old_timestamp, old_timestamp))
            paths.append(path)

        output = StringIO()
        call_command("purge_expired_state", dry_run=True, batch_size=2, stdout=output)
        self.assertEqual(json.loads(output.getvalue())["recording_orphans_quarantined"], 2)
        self.assertEqual(sum(path.exists() for path in paths), 3)

        output = StringIO()
        call_command("purge_expired_state", batch_size=2, stdout=output)
        self.assertEqual(json.loads(output.getvalue())["recording_orphans_quarantined"], 2)
        self.assertEqual(sum(path.exists() for path in paths), 1)
        quarantine = Path(self.upload_root.name) / ".quarantine"
        self.assertEqual(len(list(quarantine.glob("*.quarantined"))), 2)

        output = StringIO()
        call_command("purge_expired_state", batch_size=2, stdout=output)
        self.assertEqual(json.loads(output.getvalue())["recording_orphans_quarantined"], 1)
        self.assertFalse(any(path.exists() for path in paths))
        quarantined = list(quarantine.glob("*.quarantined"))
        self.assertEqual(len(quarantined), 3)

        expired = (timezone.now() - datetime.timedelta(days=2)).timestamp()
        for path in quarantined:
            os.utime(path, (expired, expired))
        output = StringIO()
        call_command("purge_expired_state", batch_size=2, stdout=output)
        self.assertEqual(json.loads(output.getvalue())["recording_quarantine_purged"], 2)
        self.assertEqual(len(list(quarantine.glob("*.quarantined"))), 1)

        output = StringIO()
        call_command("purge_expired_state", batch_size=2, stdout=output)
        self.assertEqual(json.loads(output.getvalue())["recording_quarantine_purged"], 1)
        self.assertFalse(list(quarantine.glob("*.quarantined")))

    def test_orphan_cleanup_rejects_a_symlinked_staging_directory(self):
        namespace = Path(self.upload_root.name) / ("b" * 64)
        namespace.mkdir()
        with tempfile.TemporaryDirectory() as external:
            (namespace / ".uploads").symlink_to(external, target_is_directory=True)
            with self.assertRaises(OSError):
                call_command("purge_expired_state", batch_size=1, stdout=StringIO())

    def test_cleanup_batch_size_is_strictly_bounded(self):
        for invalid in (0, 1001):
            with self.subTest(batch_size=invalid), self.assertRaises(CommandError):
                call_command("purge_expired_state", batch_size=invalid, stdout=StringIO())

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
        self.assertTrue(self._object_paths(finalized["upload_id"])[1].exists())

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
            self.assertTrue(data.startswith(recording_crypto.RECORD_MAGIC))
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
        upload = RecordingUpload.objects.get(upload_id=state["upload_id"])
        self.assertEqual(partials[0].stat().st_size, recording_crypto.HEADER_SIZE)
        self.assertEqual(upload.storage_offset, recording_crypto.HEADER_SIZE)
        self._assert_authenticated_recording(state["upload_id"], partials[0], b"")

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
        self.assertGreater(staging.stat().st_size, upload.storage_offset)
        self.assertNotIn(b"rollback", staging.read_bytes())
        reconciled = self._request("status", upload_id=state["upload_id"])
        self.assertEqual(reconciled.status_code, 200, reconciled.content)
        self.assertEqual(staging.stat().st_size, recording_crypto.HEADER_SIZE)
        self._assert_authenticated_recording(state["upload_id"], staging, b"")

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
        _expected_staging, published = self._object_paths(state["upload_id"])
        self.assertFalse(staging.exists())
        self.assertNotIn(b"rollback", published.read_bytes())
        self._assert_authenticated_recording(state["upload_id"], published, b"rollback")

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
        self.assertFalse(self._object_paths(state["upload_id"])[1].exists())

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
        _staging, published = self._object_paths(state["upload_id"])
        self.assertTrue(published.is_file())
        self.assertNotIn(b"complete-recording", published.read_bytes())
        self._assert_authenticated_recording(state["upload_id"], published, b"complete-recording")
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
        self._assert_authenticated_recording(state["upload_id"], published, b"complete-recording")

    def test_finalize_recovers_rename_that_preceded_database_commit(self):
        state = self._create(filename="rename-recovery.webm")
        committed = self._part(state, b"rename-recovery").json()
        digest = hashlib.sha256(b"rename-recovery").hexdigest()
        staging = next(Path(self.upload_root.name).glob("*/.uploads/*.part"))
        _expected_staging, published = self._object_paths(state["upload_id"])
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
        self._assert_authenticated_recording(state["upload_id"], published, b"rename-recovery")

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
        self.assertTrue(self._object_paths(finalized["upload_id"])[1].is_file())


class RecordingStorageCapabilityTests(TestCase):
    def setUp(self):
        ingestion_governance.reset_recording_storage_capability_cache()

    def tearDown(self):
        ingestion_governance.reset_recording_storage_capability_cache()

    @staticmethod
    def _settings(root, **overrides):
        values = {
            "RECORD_UPLOAD_ROOT": Path(root),
            "RECORD_UPLOAD_REQUIRE_MOUNT": False,
            "RECORD_UPLOAD_VOLUME_RESERVE_BYTES": 0,
            "RECORD_UPLOAD_VOLUME_RESERVE_INODES": 0,
            "RECORD_UPLOAD_CAPABILITY_CACHE_SECONDS": 0,
        }
        values.update(overrides)
        return override_settings(**values)

    def test_missing_symlinked_and_non_mount_roots_are_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            parent_path = Path(parent)
            missing = parent_path / "missing"
            with self._settings(missing), self.assertRaises(ingestion_governance.RecordingStorageUnavailable):
                ingestion_governance.check_recording_storage_capability()

            real_root = parent_path / "real"
            real_root.mkdir()
            symlink_root = parent_path / "symlink"
            symlink_root.symlink_to(real_root, target_is_directory=True)
            with self._settings(symlink_root), self.assertRaises(ingestion_governance.RecordingStorageUnavailable):
                ingestion_governance.check_recording_storage_capability()

            with (
                self._settings(real_root, RECORD_UPLOAD_REQUIRE_MOUNT=True),
                patch.object(ingestion_governance, "_mount_identity", return_value=None),
                self.assertRaises(ingestion_governance.RecordingStorageUnavailable),
            ):
                ingestion_governance.check_recording_storage_capability()

    def test_write_probe_and_byte_and_inode_reserves_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            with (
                self._settings(root),
                patch.object(ingestion_governance.os, "open", side_effect=PermissionError("read only")),
                self.assertRaises(ingestion_governance.RecordingStorageUnavailable) as write_error,
            ):
                ingestion_governance.check_recording_storage_capability()
            self.assertEqual(write_error.exception.status, 503)

            byte_stat = SimpleNamespace(f_bavail=100, f_frsize=1, f_favail=100)
            with (
                self._settings(root, RECORD_UPLOAD_VOLUME_RESERVE_BYTES=50),
                patch.object(ingestion_governance.os, "statvfs", return_value=byte_stat),
                self.assertRaises(ingestion_governance.RecordingStorageUnavailable) as byte_error,
            ):
                ingestion_governance.check_recording_storage_capability(51)
            self.assertEqual((byte_error.exception.status, byte_error.exception.code), (507, "recording_volume_full"))

            inode_stat = SimpleNamespace(f_bavail=100, f_frsize=1, f_favail=4)
            with (
                self._settings(root, RECORD_UPLOAD_VOLUME_RESERVE_INODES=5),
                patch.object(ingestion_governance.os, "statvfs", return_value=inode_stat),
                self.assertRaises(ingestion_governance.RecordingStorageUnavailable) as inode_error,
            ):
                ingestion_governance.check_recording_storage_capability()
            self.assertEqual(
                (inode_error.exception.status, inode_error.exception.code),
                (507, "recording_volume_inodes_exhausted"),
            )

    def test_runtime_mount_identity_change_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            with (
                self._settings(root, RECORD_UPLOAD_REQUIRE_MOUNT=True),
                patch.object(
                    ingestion_governance,
                    "_mount_identity",
                    side_effect=[("1:1", "/", "ext4", "/dev/a"), ("2:2", "/", "ext4", "/dev/b")],
                ),
            ):
                ingestion_governance.check_recording_storage_capability()
                with self.assertRaises(ingestion_governance.RecordingStorageUnavailable):
                    ingestion_governance.check_recording_storage_capability()

    def test_cache_is_scoped_by_root_and_force_or_reset_rechecks_capability(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "root"
            root.mkdir()
            missing = Path(parent) / "other-missing-root"
            with self._settings(root, RECORD_UPLOAD_CAPABILITY_CACHE_SECONDS=60):
                ingestion_governance.check_recording_storage_capability()

            with (
                self._settings(missing, RECORD_UPLOAD_CAPABILITY_CACHE_SECONDS=60),
                self.assertRaises(ingestion_governance.RecordingStorageUnavailable),
            ):
                ingestion_governance.check_recording_storage_capability()

            root.rmdir()
            with self._settings(root, RECORD_UPLOAD_CAPABILITY_CACHE_SECONDS=60):
                ingestion_governance.check_recording_storage_capability()
                with self.assertRaises(ingestion_governance.RecordingStorageUnavailable):
                    ingestion_governance.check_recording_storage_capability(force=True)
                ingestion_governance.reset_recording_storage_capability_cache()
                with self.assertRaises(ingestion_governance.RecordingStorageUnavailable):
                    ingestion_governance.check_recording_storage_capability()


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
            RECORD_UPLOAD_REQUIRE_MOUNT=False,
            RECORD_UPLOAD_VOLUME_RESERVE_BYTES=0,
            RECORD_UPLOAD_VOLUME_RESERVE_INODES=0,
            RECORD_UPLOAD_CAPABILITY_CACHE_SECONDS=0,
            DATA_UPLOAD_MAX_MEMORY_SIZE=1024,
        )
        self.settings_override.enable()

    def tearDown(self):
        if hasattr(self, "settings_override"):
            self.settings_override.disable()
        if hasattr(self, "upload_root"):
            self.upload_root.cleanup()

    def _create(self, filename, create_id="88888888-8888-4888-8888-888888888888"):
        response = self.client.post(
            "/api/record?"
            + urlencode(
                {
                    "version": PROTOCOL_VERSION,
                    "type": "new",
                    "file": filename,
                    "create_id": create_id,
                }
            ),
            data=b"",
            content_type="application/octet-stream",
            HTTP_AUTHORIZATION=f"Bearer {self.raw_token}",
        )
        self.assertEqual(response.status_code, 201, response.content)
        return response.json()

    def _concurrent_creates(self, requests):
        barrier = Barrier(len(requests))

        def send(request):
            filename, create_id = request
            close_old_connections()
            client = Client()
            barrier.wait(timeout=5)
            try:
                response = client.post(
                    "/api/record?"
                    + urlencode(
                        {
                            "version": PROTOCOL_VERSION,
                            "type": "new",
                            "file": filename,
                            "create_id": create_id,
                        }
                    ),
                    data=b"",
                    content_type="application/octet-stream",
                    HTTP_AUTHORIZATION=f"Bearer {self.raw_token}",
                )
                return response.status_code, response.json()
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=len(requests)) as executor:
            return list(executor.map(send, requests))

    def _concurrent_parts_for_uploads(self, states):
        body = b"last-bytes"
        barrier = Barrier(len(states))

        def send(index_and_state):
            index, state = index_and_state
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
                            "chunk_id": f"{index + 1:08x}-1111-4111-8111-111111111111",
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
                connections.close_all()

        with ThreadPoolExecutor(max_workers=len(states)) as executor:
            return list(executor.map(send, enumerate(states)))

    def test_backup_checkpoint_waits_for_an_inflight_recording_mutation_lock(self):
        mutation_locked = Event()
        release_mutation = Event()
        backup_attempted = Event()

        def hold_mutation_lock():
            close_old_connections()
            try:
                with transaction.atomic():
                    recording_inventory.lock_recording_mutation()
                    mutation_locked.set()
                    if not release_mutation.wait(10):
                        raise TimeoutError("recording mutation release timed out")
            finally:
                close_old_connections()

        def begin_checkpoint():
            close_old_connections()
            backup_attempted.set()
            try:
                return recording_inventory.begin_backup(
                    "abcdef0123456789abcdef0123456789",
                    "20260806T004500Z",
                )
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as executor:
            mutation = executor.submit(hold_mutation_lock)
            self.assertTrue(mutation_locked.wait(10), "recording mutation did not acquire backup control")
            checkpoint = executor.submit(begin_checkpoint)
            self.assertTrue(backup_attempted.wait(10), "backup checkpoint did not start")
            self.assertFalse(checkpoint.done(), "backup checkpoint bypassed an in-flight mutation lock")
            release_mutation.set()
            mutation.result(timeout=10)
            epoch = checkpoint.result(timeout=10)

        self.assertEqual(epoch.state, RecordingBackupEpoch.STATE_READY)
        recording_inventory.abort_backup(epoch.backup_id)

    @override_settings(
        RECORD_UPLOAD_MAX_ACTIVE_PER_DEVICE=1,
        RECORD_UPLOAD_MAX_ACTIVE_PER_OWNER=1,
        RECORD_UPLOAD_MAX_ACTIVE_GLOBAL=1,
        RECORD_UPLOAD_MAX_FILES_PER_DEVICE=1,
        RECORD_UPLOAD_MAX_FILES_PER_OWNER=1,
        RECORD_UPLOAD_MAX_FILES_GLOBAL=1,
    )
    def test_concurrent_distinct_creates_cannot_oversell_the_last_file_slot(self):
        responses = self._concurrent_creates(
            [
                ("quota-a.webm", "11111111-1111-4111-8111-111111111111"),
                ("quota-b.webm", "22222222-2222-4222-8222-222222222222"),
            ]
        )

        self.assertEqual(sorted(status for status, _payload in responses), [201, 507])
        self.assertEqual(RecordingUpload.objects.count(), 1)
        usage = PersistentIngestionUsage.objects.get(kind="recording", scope="global")
        self.assertEqual((usage.items, usage.active_items), (1, 1))

    @override_settings(
        RECORD_UPLOAD_MAX_ACTIVE_PER_DEVICE=1,
        RECORD_UPLOAD_MAX_ACTIVE_PER_OWNER=1,
        RECORD_UPLOAD_MAX_ACTIVE_GLOBAL=1,
        RECORD_UPLOAD_MAX_FILES_PER_DEVICE=1,
        RECORD_UPLOAD_MAX_FILES_PER_OWNER=1,
        RECORD_UPLOAD_MAX_FILES_GLOBAL=1,
    )
    def test_concurrent_create_replay_reserves_exactly_once(self):
        request = ("replay.webm", "33333333-3333-4333-8333-333333333333")

        responses = self._concurrent_creates([request, request])

        self.assertEqual(sorted(status for status, _payload in responses), [200, 201])
        self.assertEqual(responses[0][1], responses[1][1])
        self.assertEqual(RecordingUpload.objects.count(), 1)
        usage = PersistentIngestionUsage.objects.get(kind="recording", scope="global")
        self.assertEqual((usage.items, usage.active_items, usage.committed_bytes), (1, 1, 0))

    @override_settings(
        RECORD_UPLOAD_MAX_BYTES_PER_DEVICE=10,
        RECORD_UPLOAD_MAX_BYTES_PER_OWNER=10,
        RECORD_UPLOAD_MAX_BYTES_GLOBAL=10,
    )
    def test_concurrent_uploads_cannot_oversell_the_last_global_byte_quota(self):
        states = [
            self._create("bytes-a.webm", "44444444-4444-4444-8444-444444444444"),
            self._create("bytes-b.webm", "55555555-5555-4555-8555-555555555555"),
        ]

        responses = self._concurrent_parts_for_uploads(states)

        self.assertEqual(sorted(status for status, _payload in responses), [200, 507])
        self.assertEqual(RecordingUploadChunk.objects.count(), 1)
        self.assertEqual(sum(RecordingUpload.objects.values_list("committed_offset", flat=True)), 10)
        usage = PersistentIngestionUsage.objects.get(kind="recording", scope="global")
        self.assertEqual(usage.committed_bytes, 10)

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
                connections.close_all()

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
        self.assertNotIn(b"concurrent", staging.read_bytes())
        self.assertEqual(staging.stat().st_size, RecordingUpload.objects.get().storage_offset)

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
        self.assertNotIn(b"concurrent", staging.read_bytes())
        self.assertEqual(staging.stat().st_size, RecordingUpload.objects.get().storage_offset)
