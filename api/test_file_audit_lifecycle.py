import datetime
import uuid

from django.db import IntegrityError, transaction
from django.test import TestCase, override_settings
from django.utils import timezone

from api import ingestion_retention
from api.models import ConnectionAuditEvent, ConnLog, FileLog, UserProfile
from api.tests import ApiTestMixin, device_uuid

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


class FileAuditLifecycleTests(ApiTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.host_uuid = device_uuid("file-audit-host")
        self._device(owner=self.user, rid="111111111", uuid=self.host_uuid)
        self.host_token = self._login(
            "alice",
            "alice-pass",
            rid="111111111",
            uuid=self.host_uuid,
        )
        controller_password = uuid.uuid4().hex
        controller = UserProfile.objects.create_user(
            username="file-controller",
            password=controller_password,
        )
        controller_uuid = device_uuid("file-audit-controller")
        self._device(owner=controller, rid="222222222", uuid=controller_uuid)
        controller_token = self._login(
            "file-controller",
            controller_password,
            rid="222222222",
            uuid=controller_uuid,
        )
        opened = self._connection_event(
            "new",
            ip="192.0.2.10",
            type=0,
        )
        self.assertEqual(opened.status_code, 201, opened.content)
        self.audit_session_id = opened.json()["audit_session_id"]
        authorized = self._connection_event(
            "update",
            audit_session_id=self.audit_session_id,
            peer=["222222222", "controller"],
            type=0,
        )
        self.assertEqual(authorized.status_code, 200, authorized.content)
        bound = self.client.get(
            f"/api/audit/conn/active?version=3&event_id={uuid.uuid4()}&id=111111111&session_id=99&conn_type=0",
            **self._auth_headers(controller_token),
        )
        self.assertEqual(bound.status_code, 200, bound.content)

    def _connection_event(self, action, **overrides):
        payload = {
            "version": 3,
            "event_id": str(uuid.uuid4()),
            "action": action,
            "id": "111111111",
            "uuid": self.host_uuid,
            "conn_id": 7,
            "session_id": 99,
        }
        payload.update(overrides)
        return self._post_json("/api/audit/conn", payload, token=self.host_token)

    def _file_payload(
        self,
        *,
        transfer_id,
        revision,
        state,
        event_id=None,
        transferred_bytes=0,
        terminal_reason="",
        planned_file_count=100,
        planned_bytes=100,
        sample_files=None,
    ):
        if sample_files is None:
            sample_files = [{"path": f"sample-{index}.bin", "size": 1} for index in range(10)]
        return {
            "version": 4,
            "event_id": event_id or str(uuid.uuid4()),
            "audit_session_id": self.audit_session_id,
            "transfer_id": transfer_id,
            "transfer_revision": revision,
            "state": state,
            "id": "111111111",
            "uuid": self.host_uuid,
            "peer_id": "222222222",
            "conn_id": 7,
            "direction": 0,
            "path": "/documents",
            "is_file": False,
            "planned_file_count": planned_file_count,
            "planned_bytes": planned_bytes,
            "transferred_bytes": transferred_bytes,
            "sample_files": sample_files,
            "source_kind": "file_transfer",
            "terminal_reason": terminal_reason,
        }

    def _post_file(self, payload):
        return self._post_json("/api/audit/file", payload, token=self.host_token)

    def test_legacy_v3_file_payload_is_rejected_with_required_version_four(self):
        response = self._post_file(
            {
                "version": 3,
                "event_id": str(uuid.uuid4()),
                "audit_session_id": self.audit_session_id,
                "id": "111111111",
                "uuid": self.host_uuid,
                "peer_id": "222222222",
                "conn_id": 7,
                "type": 0,
                "path": "/documents",
                "is_file": False,
                "info": {
                    "ip": "192.0.2.10",
                    "files": [[f"file-{index}.bin", 1] for index in range(10)],
                    "num": 100,
                },
            }
        )

        self.assertEqual(response.status_code, 426, response.content)
        self.assertEqual(response.json()["required_version"], 4)
        self.assertEqual(FileLog.objects.count(), 0)

    def test_full_planned_totals_are_independent_from_ten_file_sample(self):
        transfer_id = str(uuid.uuid4())
        started = self._post_file(
            self._file_payload(
                transfer_id=transfer_id,
                revision=1,
                state="started",
            )
        )

        self.assertEqual(started.status_code, 200, started.content)
        self.assertEqual(
            started.json(),
            {
                "version": 4,
                "audit_session_id": self.audit_session_id,
                "acknowledged_event_id": started.json()["acknowledged_event_id"],
                "transfer_id": transfer_id,
                "transfer_revision": 1,
                "transfer_state": "started",
                "transferred_bytes": 0,
            },
        )
        file_log = FileLog.objects.get()
        self.assertEqual(file_log.planned_file_count, 100)
        self.assertEqual(file_log.planned_bytes, 100)
        self.assertEqual(file_log.transferred_bytes, 0)
        self.assertEqual(file_log.state, "started")
        self.assertEqual(len(file_log.sample_files), 10)
        self.assertEqual(sum(item["size"] for item in file_log.sample_files), 10)

        progress = self._post_file(
            self._file_payload(
                transfer_id=transfer_id,
                revision=2,
                state="progress",
                transferred_bytes=40,
            )
        )
        completed = self._post_file(
            self._file_payload(
                transfer_id=transfer_id,
                revision=3,
                state="completed",
                transferred_bytes=90,
            )
        )
        self.assertEqual(progress.status_code, 200, progress.content)
        self.assertEqual(completed.status_code, 200, completed.content)
        file_log.refresh_from_db()
        self.assertEqual(file_log.state, "completed")
        self.assertEqual(file_log.transferred_bytes, 90)
        self.assertIsNotNone(file_log.terminal_at)
        self.assertEqual(
            list(file_log.transfer_events.values_list("revision", "state", "transferred_bytes")),
            [(1, "started", 0), (2, "progress", 40), (3, "completed", 90)],
        )
        self.assertEqual(
            ConnectionAuditEvent.objects.filter(kind=ConnectionAuditEvent.KIND_FILE).count(),
            3,
        )

    def test_replays_conflicts_out_of_order_and_terminal_resurrection(self):
        transfer_id = str(uuid.uuid4())
        event_id = str(uuid.uuid4())
        started_payload = self._file_payload(
            transfer_id=transfer_id,
            revision=1,
            state="started",
            event_id=event_id,
        )
        started = self._post_file(started_payload)
        replayed = self._post_file(started_payload)
        self.assertEqual(started.status_code, 200, started.content)
        self.assertEqual(replayed.status_code, 200, replayed.content)
        self.assertEqual(started.json(), replayed.json())

        conflicting_event = self._post_file(
            self._file_payload(
                transfer_id=transfer_id,
                revision=1,
                state="started",
                event_id=event_id,
                planned_bytes=101,
            )
        )
        duplicate_revision = self._post_file(
            self._file_payload(
                transfer_id=transfer_id,
                revision=1,
                state="started",
            )
        )
        skipped_revision = self._post_file(
            self._file_payload(
                transfer_id=transfer_id,
                revision=3,
                state="progress",
                transferred_bytes=50,
            )
        )
        for response in (conflicting_event, duplicate_revision, skipped_revision):
            self.assertEqual(response.status_code, 409, response.content)

        progress = self._post_file(
            self._file_payload(
                transfer_id=transfer_id,
                revision=2,
                state="progress",
                transferred_bytes=50,
            )
        )
        regressed = self._post_file(
            self._file_payload(
                transfer_id=transfer_id,
                revision=3,
                state="progress",
                transferred_bytes=49,
            )
        )
        completed = self._post_file(
            self._file_payload(
                transfer_id=transfer_id,
                revision=3,
                state="completed",
                transferred_bytes=50,
            )
        )
        resurrected = self._post_file(
            self._file_payload(
                transfer_id=transfer_id,
                revision=4,
                state="progress",
                transferred_bytes=60,
            )
        )
        self.assertEqual(progress.status_code, 200, progress.content)
        self.assertEqual(regressed.status_code, 409, regressed.content)
        self.assertEqual(completed.status_code, 200, completed.content)
        self.assertEqual(resurrected.status_code, 409, resurrected.content)
        self.assertEqual(FileLog.objects.get().transfer_events.count(), 3)

    def test_failed_cancelled_and_unknown_are_distinct_terminal_states(self):
        for index, terminal_state in enumerate(("failed", "cancelled", "unknown"), start=1):
            with self.subTest(state=terminal_state):
                transfer_id = str(uuid.uuid4())
                started = self._post_file(
                    self._file_payload(
                        transfer_id=transfer_id,
                        revision=1,
                        state="started",
                        planned_file_count=1,
                        planned_bytes=10,
                        sample_files=[{"path": f"terminal-{index}.bin", "size": 10}],
                    )
                )
                terminal = self._post_file(
                    self._file_payload(
                        transfer_id=transfer_id,
                        revision=2,
                        state=terminal_state,
                        transferred_bytes=index,
                        terminal_reason=f"test_{terminal_state}",
                        planned_file_count=1,
                        planned_bytes=10,
                        sample_files=[{"path": f"terminal-{index}.bin", "size": 10}],
                    )
                )
                self.assertEqual(started.status_code, 200, started.content)
                self.assertEqual(terminal.status_code, 200, terminal.content)
                file_log = FileLog.objects.get(transfer_id=transfer_id)
                self.assertEqual(file_log.state, terminal_state)
                self.assertEqual(file_log.terminal_reason, f"test_{terminal_state}")
                self.assertIsNotNone(file_log.terminal_at)

    def test_host_close_reconciles_open_transfer_to_unknown_without_changing_replay_ack(self):
        transfer_id = str(uuid.uuid4())
        started_payload = self._file_payload(
            transfer_id=transfer_id,
            revision=1,
            state="started",
        )
        started = self._post_file(started_payload)
        closed = self._connection_event("close", audit_session_id=self.audit_session_id)
        self.assertEqual(started.status_code, 200, started.content)
        self.assertEqual(closed.status_code, 200, closed.content)

        file_log = FileLog.objects.get()
        self.assertEqual(file_log.state, "unknown")
        self.assertEqual(file_log.transfer_revision, 2)
        self.assertEqual(file_log.terminal_reason, "connection_host_close")
        reconciled = file_log.transfer_events.get(revision=2)
        self.assertEqual(reconciled.connection_event.kind, ConnectionAuditEvent.KIND_CLOSED)

        replayed = self._post_file(started_payload)
        late = self._post_file(
            self._file_payload(
                transfer_id=transfer_id,
                revision=2,
                state="completed",
                transferred_bytes=100,
            )
        )
        self.assertEqual(replayed.status_code, 200, replayed.content)
        self.assertEqual(replayed.json(), started.json())
        self.assertEqual(late.status_code, 409, late.content)

    @override_settings(AUDIT_RETENTION_DAYS=30)
    def test_expired_connection_reconciles_open_transfer_to_unknown(self):
        transfer_id = str(uuid.uuid4())
        started = self._post_file(
            self._file_payload(
                transfer_id=transfer_id,
                revision=1,
                state="started",
            )
        )
        self.assertEqual(started.status_code, 200, started.content)
        progress = self._post_file(
            self._file_payload(
                transfer_id=transfer_id,
                revision=2,
                state="progress",
                transferred_bytes=5,
            )
        )
        self.assertEqual(progress.status_code, 200, progress.content)
        stale = timezone.now() - datetime.timedelta(seconds=1)
        ConnLog.objects.filter(guid=self.audit_session_id).update(
            last_seen_at=stale - datetime.timedelta(seconds=90),
            lease_expires_at=stale,
        )

        result = ingestion_retention.purge_audit_retention(
            timezone.now(),
            batch_size=10,
        )
        self.assertEqual(result["audit_connections_expired"], 1)

        file_log = FileLog.objects.get()
        self.assertEqual(file_log.state, "unknown")
        self.assertEqual(file_log.transferred_bytes, 5)
        self.assertEqual(file_log.terminal_reason, "connection_telemetry_lost")
        self.assertEqual(
            file_log.transfer_events.get(revision=3).connection_event.kind,
            ConnectionAuditEvent.KIND_EXPIRED,
        )

    @override_settings(STORAGES=TEST_STORAGES)
    def test_file_log_page_labels_planned_actual_and_state(self):
        transfer_id = str(uuid.uuid4())
        started = self._post_file(
            self._file_payload(
                transfer_id=transfer_id,
                revision=1,
                state="started",
                planned_file_count=1,
                planned_bytes=2048,
                sample_files=[{"path": "report.bin", "size": 2048}],
            )
        )
        failed = self._post_file(
            self._file_payload(
                transfer_id=transfer_id,
                revision=2,
                state="failed",
                transferred_bytes=1024,
                terminal_reason="remote_io_error",
                planned_file_count=1,
                planned_bytes=2048,
                sample_files=[{"path": "report.bin", "size": 2048}],
            )
        )
        self.assertEqual(started.status_code, 200, started.content)
        self.assertEqual(failed.status_code, 200, failed.content)

        self.client.force_login(self.admin)
        page = self.client.get("/api/file_log")

        self.assertEqual(page.status_code, 200, page.content)
        self.assertContains(page, "Planned")
        self.assertContains(page, "Actual")
        self.assertContains(page, "State")
        self.assertContains(page, "2 KiB")
        self.assertContains(page, "1 KiB")
        self.assertContains(page, "failed")

    def test_database_rejects_invalid_aggregate_and_duplicate_revision(self):
        transfer_id = str(uuid.uuid4())
        started = self._post_file(
            self._file_payload(
                transfer_id=transfer_id,
                revision=1,
                state="started",
            )
        )
        self.assertEqual(started.status_code, 200, started.content)
        file_log = FileLog.objects.get()

        with self.assertRaises(IntegrityError), transaction.atomic():
            FileLog.objects.filter(pk=file_log.pk).update(transferred_bytes=101)
        with self.assertRaises(IntegrityError), transaction.atomic():
            FileLog.objects.filter(pk=file_log.pk).update(state="completed")
        first_event = file_log.transfer_events.get(revision=1)
        with self.assertRaises(IntegrityError), transaction.atomic():
            file_log.transfer_events.create(
                connection_event=first_event.connection_event,
                revision=1,
                state="started",
                transferred_bytes=0,
                source_kind="file_transfer",
            )
