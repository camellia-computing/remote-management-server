import datetime
import json
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from io import StringIO
from pathlib import Path
from threading import Barrier

from django.contrib import admin
from django.core.management import call_command
from django.db import IntegrityError, close_old_connections, connection, connections, transaction
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from api import admin_user  # noqa: F401 - importing registers the admin models
from api.models import (
    AlarmLog,
    ConnectionAuditEvent,
    ConnLog,
    FileLog,
    PersistentIngestionUsage,
    RemoteDevice,
    UserProfile,
)
from api.tests import ApiTestMixin, device_uuid


class AuditSessionStateMachineTests(ApiTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.host_uuid = device_uuid("audit-host")
        self.host_device = self._device(owner=self.user, rid="111111111", uuid=self.host_uuid)
        self.host_token = self._login(
            "alice",
            "alice-pass",
            rid="111111111",
            uuid=self.host_uuid,
        )

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

    def _open_connection(self):
        response = self._connection_event(
            "new",
            ip="192.0.2.10",
            type=0,
            conn_audit_ref="initial-ref",
        )
        self.assertEqual(response.status_code, 201, response.content)
        audit_session_id = response.json()["audit_session_id"]
        updated = self._connection_event(
            "update",
            audit_session_id=audit_session_id,
            peer=["222222222", "controller"],
            type=0,
            primary_auth=3,
            two_factor=1,
        )
        self.assertEqual(updated.status_code, 200, updated.content)
        return ConnLog.objects.get(), audit_session_id

    @override_settings(
        AUDIT_MAX_EVENTS_PER_CONNECTION=3,
        AUDIT_MAX_EVENTS_PER_DEVICE=3,
        AUDIT_MAX_EVENTS_PER_OWNER=3,
        AUDIT_MAX_EVENTS_GLOBAL=3,
    )
    def test_append_only_event_quota_reserves_the_close_event(self):
        connection, audit_session_id = self._open_connection()
        self.assertEqual(connection.event_revision, 2)

        denied = self._connection_event(
            "update",
            audit_session_id=audit_session_id,
        )

        self.assertEqual(denied.status_code, 507, denied.content)
        self.assertEqual(denied.json()["code"], "audit_quota_exceeded")
        connection.refresh_from_db()
        self.assertEqual(connection.event_revision, 2)
        self.assertEqual(connection.events.count(), 2)

        # A deployment may tighten the configured per-connection limit below
        # an already-active session's revision. Its migration-backfilled close
        # reservation must still let that historical session terminate.
        with override_settings(AUDIT_MAX_EVENTS_PER_CONNECTION=2):
            closed = self._connection_event("close", audit_session_id=audit_session_id)

        self.assertEqual(closed.status_code, 200, closed.content)
        connection.refresh_from_db()
        self.assertIsNotNone(connection.conn_end)
        self.assertEqual(connection.event_revision, 3)
        self.assertEqual(connection.events.count(), 3)
        usage = PersistentIngestionUsage.objects.get(kind="audit", scope="global")
        self.assertEqual((usage.items, usage.events), (1, 3))

    @override_settings(AUDIT_RETENTION_DAYS=1)
    def test_closed_session_retention_releases_event_ledger_and_respects_hold(self):
        connection, audit_session_id = self._open_connection()
        closed = self._connection_event("close", audit_session_id=audit_session_id)
        self.assertEqual(closed.status_code, 200, closed.content)
        old = timezone.now() - datetime.timedelta(days=2)
        ConnLog.objects.filter(pk=connection.pk).update(
            conn_start=old - datetime.timedelta(hours=1),
            conn_end=old,
            last_seen_at=old,
            lease_expires_at=old,
            terminal_at=old,
            retention_hold=True,
            retention_hold_reason="test hold",
            retention_hold_at=timezone.now(),
        )

        with (
            tempfile.TemporaryDirectory() as recording_root,
            override_settings(
                RECORD_UPLOAD_ROOT=Path(recording_root),
                RECORD_UPLOAD_REQUIRE_MOUNT=False,
            ),
        ):
            call_command("purge_expired_state", batch_size=10, stdout=StringIO())
            self.assertTrue(ConnLog.objects.filter(pk=connection.pk).exists())

            ConnLog.objects.filter(pk=connection.pk).update(retention_hold=False)
            call_command("purge_expired_state", batch_size=10, stdout=StringIO())

        self.assertFalse(ConnLog.objects.filter(pk=connection.pk).exists())
        self.assertEqual(ConnectionAuditEvent.objects.count(), 0)
        for usage in PersistentIngestionUsage.objects.filter(kind="audit"):
            self.assertEqual((usage.items, usage.events), (0, 0))

    def test_legacy_audit_protocol_is_rejected(self):
        response = self._post_json(
            "/api/audit/conn",
            {
                "version": 2,
                "action": "new",
                "id": "111111111",
                "uuid": self.host_uuid,
                "conn_id": 7,
                "session_id": 99,
                "ip": "192.0.2.10",
                "type": 0,
            },
            token=self.host_token,
        )

        self.assertEqual(response.status_code, 426, response.content)
        self.assertEqual(response.json()["required_version"], 3)

    def test_closed_connection_facts_cannot_be_rewritten(self):
        connection, audit_session_id = self._open_connection()
        self.assertEqual(
            self._connection_event("close", audit_session_id=audit_session_id).status_code,
            200,
        )

        replayed_open = self._connection_event(
            "new",
            event_id=str(connection.create_id),
            ip="192.0.2.10",
            type=0,
            conn_audit_ref="initial-ref",
        )
        authorized_event = connection.events.get(kind=ConnectionAuditEvent.KIND_AUTHORIZED)
        replayed_authorization = self._connection_event(
            "update",
            event_id=str(authorized_event.event_id),
            audit_session_id=audit_session_id,
            peer=["222222222", "controller"],
            type=0,
            primary_auth=3,
            two_factor=1,
        )
        self.assertEqual(replayed_open.status_code, 200, replayed_open.content)
        self.assertEqual(replayed_open.json()["state"], ConnLog.STATE_CLOSED)
        self.assertEqual(replayed_authorization.status_code, 409, replayed_authorization.content)

        rewritten = self._connection_event(
            "update",
            audit_session_id=audit_session_id,
            peer=["333333333", "forged"],
            type=1,
            primary_auth=1,
            two_factor=2,
            conn_audit_ref="rewritten-ref",
        )

        self.assertEqual(rewritten.status_code, 409, rewritten.content)
        connection.refresh_from_db()
        self.assertEqual(connection.from_id, "222222222")
        self.assertEqual(connection.conn_type, 0)
        self.assertEqual(connection.primary_auth, 3)
        self.assertEqual(connection.two_factor, 1)
        self.assertEqual(connection.audit_ref, "initial-ref")
        self.assertEqual(connection.note, "")

    @override_settings(AUDIT_CONNECTION_LEASE_SECONDS=60)
    def test_heartbeat_is_monotonic_idempotent_and_cannot_revive_an_expired_session(self):
        connection, audit_session_id = self._open_connection()
        heartbeat_id = str(uuid.uuid4())
        payload = {
            "event_id": heartbeat_id,
            "heartbeat_revision": 1,
            "audit_session_id": audit_session_id,
        }
        heartbeat = self._connection_event("heartbeat", **payload)
        self.assertEqual(heartbeat.status_code, 200, heartbeat.content)
        self.assertEqual(heartbeat.json()["heartbeat_revision"], 1)
        self.assertEqual(heartbeat.json()["state"], ConnLog.STATE_ACTIVE)
        connection.refresh_from_db()
        first_deadline = connection.lease_expires_at

        replay = self._connection_event("heartbeat", **payload)
        conflict = self._connection_event(
            "heartbeat",
            event_id=str(uuid.uuid4()),
            heartbeat_revision=1,
            audit_session_id=audit_session_id,
        )
        self.assertEqual(replay.status_code, 200, replay.content)
        self.assertEqual(conflict.status_code, 409, conflict.content)
        connection.refresh_from_db()
        self.assertEqual(connection.lease_expires_at, first_deadline)
        self.assertEqual(connection.event_revision, 2)

        stale = timezone.now() - datetime.timedelta(seconds=1)
        ConnLog.objects.filter(pk=connection.pk).update(
            last_seen_at=stale - datetime.timedelta(seconds=60),
            lease_expires_at=stale,
        )
        late = self._connection_event(
            "heartbeat",
            event_id=str(uuid.uuid4()),
            heartbeat_revision=2,
            audit_session_id=audit_session_id,
        )
        self.assertEqual(late.status_code, 409, late.content)
        connection.refresh_from_db()
        self.assertEqual(connection.state, ConnLog.STATE_EXPIRED)
        self.assertIsNone(connection.conn_end)
        self.assertEqual(connection.terminal_reason, "telemetry_lost")
        self.assertEqual(connection.events.order_by("sequence").last().kind, ConnectionAuditEvent.KIND_EXPIRED)

    @override_settings(AUDIT_CONNECTION_LEASE_SECONDS=60, AUDIT_RETENTION_DAYS=1)
    def test_cleanup_reconciles_a_crashed_host_without_forging_a_normal_close(self):
        opened = self._connection_event(
            "new",
            ip="192.0.2.10",
            type=0,
            conn_audit_ref="crash-ref",
        )
        self.assertEqual(opened.status_code, 201, opened.content)
        connection = ConnLog.objects.get()
        stale = timezone.now() - datetime.timedelta(seconds=1)
        ConnLog.objects.filter(pk=connection.pk).update(
            last_seen_at=stale - datetime.timedelta(seconds=60),
            lease_expires_at=stale,
        )

        output = StringIO()
        with (
            tempfile.TemporaryDirectory() as recording_root,
            override_settings(RECORD_UPLOAD_ROOT=Path(recording_root), RECORD_UPLOAD_REQUIRE_MOUNT=False),
        ):
            call_command("purge_expired_state", batch_size=10, stdout=output)

        result = json.loads(output.getvalue())
        self.assertEqual(result["audit_connections_expired"], 1)
        connection.refresh_from_db()
        self.assertEqual(connection.state, ConnLog.STATE_EXPIRED)
        self.assertEqual(connection.terminal_source, "cleanup_reconciler")
        self.assertIsNone(connection.conn_end)
        self.assertEqual(connection.events.count(), 2)
        usage = PersistentIngestionUsage.objects.get(kind="audit", scope="global")
        self.assertEqual((usage.items, usage.events), (1, 2))

        old_terminal = timezone.now() - datetime.timedelta(days=2)
        ConnLog.objects.filter(pk=connection.pk).update(terminal_at=old_terminal)
        with (
            tempfile.TemporaryDirectory() as recording_root,
            override_settings(RECORD_UPLOAD_ROOT=Path(recording_root), RECORD_UPLOAD_REQUIRE_MOUNT=False),
        ):
            call_command("purge_expired_state", batch_size=10, stdout=StringIO())

        self.assertFalse(ConnLog.objects.filter(pk=connection.pk).exists())
        self.assertEqual(ConnectionAuditEvent.objects.count(), 0)
        for usage in PersistentIngestionUsage.objects.filter(kind="audit"):
            self.assertEqual((usage.items, usage.events), (0, 0))

    def test_close_distinguishes_normal_and_pre_authorization_terminal_states(self):
        opened = self._connection_event("new", ip="192.0.2.10", type=0)
        self.assertEqual(opened.status_code, 201, opened.content)
        aborted = self._connection_event("close", audit_session_id=opened.json()["audit_session_id"])
        self.assertEqual(aborted.status_code, 200, aborted.content)
        self.assertEqual(aborted.json()["state"], ConnLog.STATE_ABORTED)
        connection = ConnLog.objects.get()
        self.assertEqual(connection.events.order_by("sequence").last().kind, ConnectionAuditEvent.KIND_ABORTED)
        self.assertIsNotNone(connection.conn_end)

    def test_heartbeat_then_close_is_terminal_and_rejects_a_late_heartbeat(self):
        connection, audit_session_id = self._open_connection()
        heartbeat = self._connection_event(
            "heartbeat",
            heartbeat_revision=1,
            audit_session_id=audit_session_id,
        )
        self.assertEqual(heartbeat.status_code, 200, heartbeat.content)

        closed = self._connection_event("close", audit_session_id=audit_session_id)
        self.assertEqual(closed.status_code, 200, closed.content)
        self.assertEqual(closed.json()["state"], ConnLog.STATE_CLOSED)
        self.assertEqual(closed.json()["heartbeat_revision"], 1)
        self.assertEqual(closed.json()["lease_remaining_seconds"], 0)

        late_heartbeat = self._connection_event(
            "heartbeat",
            heartbeat_revision=2,
            audit_session_id=audit_session_id,
        )
        self.assertEqual(late_heartbeat.status_code, 409, late_heartbeat.content)
        self.assertEqual(late_heartbeat.json()["state"], ConnLog.STATE_CLOSED)
        connection.refresh_from_db()
        self.assertEqual(connection.state, ConnLog.STATE_CLOSED)
        self.assertEqual(connection.heartbeat_revision, 1)
        self.assertEqual(connection.events.order_by("sequence").last().kind, ConnectionAuditEvent.KIND_CLOSED)

    def test_controller_cannot_bind_a_session_after_its_host_lease_expires(self):
        connection, _audit_session_id = self._open_connection()
        stale = timezone.now() - datetime.timedelta(seconds=1)
        ConnLog.objects.filter(pk=connection.pk).update(
            last_seen_at=stale - datetime.timedelta(seconds=90),
            lease_expires_at=stale,
        )
        controller_password = uuid.uuid4().hex
        controller = UserProfile.objects.create_user(username="expired-controller", password=controller_password)
        controller_uuid = device_uuid("audit-expired-controller")
        self._device(owner=controller, rid="222222222", uuid=controller_uuid)
        controller_token = self._login(
            "expired-controller",
            controller_password,
            rid="222222222",
            uuid=controller_uuid,
        )

        active = self.client.get(
            f"/api/audit/conn/active?version=3&event_id={uuid.uuid4()}&id=111111111&session_id=99&conn_type=0",
            **self._auth_headers(controller_token),
        )

        self.assertEqual(active.status_code, 409, active.content)
        self.assertEqual(active.json()["state"], ConnLog.STATE_EXPIRED)
        connection.refresh_from_db()
        self.assertEqual(connection.state, ConnLog.STATE_EXPIRED)
        self.assertIsNone(connection.actor_id)
        self.assertIsNone(connection.conn_end)

    def test_file_and_alarm_require_an_existing_active_connection(self):
        nonexistent_session_id = str(uuid.uuid4())
        file_response = self._post_json(
            "/api/audit/file",
            {
                "version": 3,
                "event_id": str(uuid.uuid4()),
                "audit_session_id": nonexistent_session_id,
                "id": "111111111",
                "uuid": self.host_uuid,
                "peer_id": "222222222",
                "conn_id": 2_147_483_647,
                "type": 0,
                "path": "/documents",
                "is_file": False,
                "info": json.dumps(
                    {
                        "ip": "192.0.2.10",
                        "files": [["report.pdf", 4096]],
                    }
                ),
            },
            token=self.host_token,
        )
        alarm_response = self._post_json(
            "/api/audit/alarm",
            {
                "version": 3,
                "event_id": str(uuid.uuid4()),
                "audit_session_id": nonexistent_session_id,
                "id": "111111111",
                "uuid": self.host_uuid,
                "typ": AlarmLog.TYPE_SESSION_SCOPE_VIOLATION,
                "conn_id": 2_147_483_647,
                "info": json.dumps({"message": "forged"}),
            },
            token=self.host_token,
        )

        self.assertEqual(file_response.status_code, 404, file_response.content)
        self.assertEqual(alarm_response.status_code, 404, alarm_response.content)
        self.assertEqual(FileLog.objects.count(), 0)
        self.assertEqual(AlarmLog.objects.count(), 0)

        _connection, unbound_session_id = self._open_connection()
        unbound_file = self._post_json(
            "/api/audit/file",
            {
                "version": 3,
                "event_id": str(uuid.uuid4()),
                "audit_session_id": unbound_session_id,
                "id": "111111111",
                "uuid": self.host_uuid,
                "peer_id": "222222222",
                "conn_id": 7,
                "type": 0,
                "path": "/documents",
                "is_file": False,
                "info": json.dumps({"ip": "192.0.2.10", "files": [["report.pdf", 4096]]}),
            },
            token=self.host_token,
        )
        unbound_alarm = self._post_json(
            "/api/audit/alarm",
            {
                "version": 3,
                "event_id": str(uuid.uuid4()),
                "audit_session_id": unbound_session_id,
                "id": "111111111",
                "uuid": self.host_uuid,
                "typ": AlarmLog.TYPE_SESSION_SCOPE_VIOLATION,
                "conn_id": 7,
                "info": json.dumps({"message": "unbound"}),
            },
            token=self.host_token,
        )
        self.assertEqual(unbound_file.status_code, 403, unbound_file.content)
        self.assertEqual(unbound_alarm.status_code, 403, unbound_alarm.content)
        self.assertEqual(FileLog.objects.count(), 0)
        self.assertEqual(AlarmLog.objects.count(), 0)

    def test_controller_cannot_claim_or_rewrite_a_closed_session(self):
        _connection, audit_session_id = self._open_connection()
        self.assertEqual(
            self._connection_event("close", audit_session_id=audit_session_id).status_code,
            200,
        )
        controller_password = uuid.uuid4().hex
        controller = UserProfile.objects.create_user(
            username="controller",
            password=controller_password,
        )
        controller_uuid = device_uuid("audit-controller")
        self._device(owner=controller, rid="222222222", uuid=controller_uuid)
        controller_token = self._login(
            "controller",
            controller_password,
            rid="222222222",
            uuid=controller_uuid,
        )

        active = self.client.get(
            f"/api/audit/conn/active?version=3&event_id={uuid.uuid4()}&id=111111111&session_id=99&conn_type=0",
            **self._auth_headers(controller_token),
        )
        note = self._post_json(
            "/api/audit/conn",
            {
                "version": 3,
                "event_id": str(uuid.uuid4()),
                "audit_session_id": audit_session_id,
                "note": "after close",
            },
            token=controller_token,
        )

        self.assertEqual(active.status_code, 409, active.content)
        self.assertEqual(note.status_code, 404, note.content)
        connection = ConnLog.objects.get()
        self.assertIsNone(connection.actor_id)
        self.assertEqual(connection.note, "")

    def test_audit_admin_models_are_read_only(self):
        request = self.client.request().wsgi_request
        request.user = self.admin
        registered = (
            admin.site._registry[ConnLog],
            admin.site._registry[ConnectionAuditEvent],
            admin.site._registry[FileLog],
            admin.site._registry[AlarmLog],
        )

        for model_admin in registered:
            with self.subTest(model=model_admin.model.__name__):
                self.assertFalse(model_admin.has_add_permission(request))
                self.assertFalse(model_admin.has_change_permission(request))
                self.assertFalse(model_admin.has_delete_permission(request))

    def test_events_are_monotonic_idempotent_and_children_are_bound(self):
        connection, audit_session_id = self._open_connection()
        controller_password = uuid.uuid4().hex
        controller = UserProfile.objects.create_user(
            username="controller",
            password=controller_password,
        )
        controller_uuid = device_uuid("audit-controller-live")
        self._device(owner=controller, rid="222222222", uuid=controller_uuid)
        controller_token = self._login(
            "controller",
            controller_password,
            rid="222222222",
            uuid=controller_uuid,
        )
        bind_event_id = str(uuid.uuid4())
        active = self.client.get(
            f"/api/audit/conn/active?version=3&event_id={bind_event_id}&id=111111111&session_id=99&conn_type=0",
            **self._auth_headers(controller_token),
        )
        self.assertEqual(active.status_code, 200, active.content)
        self.assertEqual(active.json()["audit_session_id"], audit_session_id)
        self.assertEqual(active.json()["acknowledged_event_id"], bind_event_id)
        self.assertEqual(active.json()["version"], 3)
        self.assertEqual(active.json()["state"], ConnLog.STATE_ACTIVE)
        self.assertGreater(active.json()["lease_remaining_seconds"], 0)

        note_event_id = str(uuid.uuid4())
        note_payload = {
            "version": 3,
            "event_id": note_event_id,
            "audit_session_id": audit_session_id,
            "note": "approved",
        }
        note = self._post_json("/api/audit/conn", note_payload, token=controller_token)
        replayed_note = self._post_json("/api/audit/conn", note_payload, token=controller_token)
        self.assertEqual(note.status_code, 200, note.content)
        self.assertEqual(replayed_note.status_code, 200, replayed_note.content)
        self.assertEqual(note.json()["acknowledged_event_id"], note_event_id)
        self.assertEqual(note.json()["state"], ConnLog.STATE_ACTIVE)
        self.assertGreater(note.json()["lease_remaining_seconds"], 0)
        self.assertEqual(note.json()["event_revision"], replayed_note.json()["event_revision"])
        revised_note = self._post_json(
            "/api/audit/conn",
            {
                "version": 3,
                "event_id": str(uuid.uuid4()),
                "audit_session_id": audit_session_id,
                "note": "revised",
            },
            token=controller_token,
        )
        self.assertEqual(revised_note.status_code, 200, revised_note.content)

        file_event_id = str(uuid.uuid4())
        file_payload = {
            "version": 3,
            "event_id": file_event_id,
            "audit_session_id": audit_session_id,
            "id": "111111111",
            "uuid": self.host_uuid,
            "peer_id": "222222222",
            "conn_id": 7,
            "type": 0,
            "path": "/documents",
            "is_file": False,
            "info": json.dumps(
                {
                    "ip": "192.0.2.10",
                    "files": [["report.pdf", 4096]],
                }
            ),
        }
        file_response = self._post_json("/api/audit/file", file_payload, token=self.host_token)
        self.assertEqual(file_response.status_code, 200, file_response.content)
        alarm_event_id = str(uuid.uuid4())
        alarm_payload = {
            "version": 3,
            "event_id": alarm_event_id,
            "audit_session_id": audit_session_id,
            "id": "111111111",
            "uuid": self.host_uuid,
            "typ": AlarmLog.TYPE_SESSION_SCOPE_VIOLATION,
            "conn_id": 7,
            "conn_audit_ref": "initial-ref",
            "info": json.dumps({"message": "scope mismatch"}),
        }
        alarm_response = self._post_json("/api/audit/alarm", alarm_payload, token=self.host_token)
        self.assertEqual(alarm_response.status_code, 200, alarm_response.content)
        closed = self._connection_event("close", audit_session_id=audit_session_id)
        self.assertEqual(closed.status_code, 200, closed.content)

        replayed_bind = self.client.get(
            f"/api/audit/conn/active?version=3&event_id={bind_event_id}&id=111111111&session_id=99&conn_type=0",
            **self._auth_headers(controller_token),
        )
        replayed_note_after_close = self._post_json(
            "/api/audit/conn",
            note_payload,
            token=controller_token,
        )
        replayed_file_after_close = self._post_json(
            "/api/audit/file",
            file_payload,
            token=self.host_token,
        )
        replayed_alarm_after_close = self._post_json(
            "/api/audit/alarm",
            alarm_payload,
            token=self.host_token,
        )
        self.assertEqual(replayed_bind.status_code, 409, replayed_bind.content)
        for replayed in (replayed_note_after_close, replayed_file_after_close, replayed_alarm_after_close):
            self.assertEqual(replayed.status_code, 200, replayed.content)

        connection.refresh_from_db()
        events = list(connection.events.order_by("sequence"))
        self.assertEqual(
            [event.kind for event in events],
            [
                ConnectionAuditEvent.KIND_OPENED,
                ConnectionAuditEvent.KIND_AUTHORIZED,
                ConnectionAuditEvent.KIND_CONTROLLER_BOUND,
                ConnectionAuditEvent.KIND_NOTE,
                ConnectionAuditEvent.KIND_NOTE,
                ConnectionAuditEvent.KIND_FILE,
                ConnectionAuditEvent.KIND_ALARM,
                ConnectionAuditEvent.KIND_CLOSED,
            ],
        )
        self.assertEqual([event.sequence for event in events], list(range(1, 9)))
        self.assertEqual(connection.event_revision, 8)
        self.assertEqual(connection.note, "revised")
        note_events = [event for event in events if event.kind == ConnectionAuditEvent.KIND_NOTE]
        self.assertEqual(
            [event.details for event in note_events],
            [
                {"previous_note": "", "note": "approved"},
                {"previous_note": "approved", "note": "revised"},
            ],
        )
        file_log = FileLog.objects.get()
        alarm_log = AlarmLog.objects.get()
        self.assertEqual(file_log.connection, connection)
        self.assertEqual(file_log.event.event_id, uuid.UUID(file_event_id))
        self.assertEqual(alarm_log.connection, connection)
        self.assertEqual(alarm_log.event.event_id, uuid.UUID(alarm_event_id))

        after_close = self._post_json(
            "/api/audit/alarm",
            {
                "version": 3,
                "event_id": str(uuid.uuid4()),
                "audit_session_id": audit_session_id,
                "id": "111111111",
                "uuid": self.host_uuid,
                "typ": AlarmLog.TYPE_SESSION_SCOPE_VIOLATION,
                "conn_id": 7,
                "info": json.dumps({"message": "late"}),
            },
            token=self.host_token,
        )
        self.assertEqual(after_close.status_code, 409, after_close.content)
        self.assertEqual(AlarmLog.objects.count(), 1)

    def test_event_identity_conflict_and_device_generation_change_fail_closed(self):
        connection, audit_session_id = self._open_connection()
        authorized_event = connection.events.get(kind=ConnectionAuditEvent.KIND_AUTHORIZED)
        conflict = self._post_json(
            "/api/audit/conn",
            {
                "version": 3,
                "event_id": str(authorized_event.event_id),
                "audit_session_id": audit_session_id,
                "action": "update",
                "id": "111111111",
                "uuid": self.host_uuid,
                "conn_id": 7,
                "session_id": 99,
                "peer": ["222222222", "controller"],
            },
            token=self.host_token,
        )
        self.assertEqual(conflict.status_code, 409, conflict.content)
        self.assertEqual(AlarmLog.objects.count(), 0)

        RemoteDevice.objects.filter(pk=connection.host_device_id).update(
            deployment_generation=connection.host_device_generation + 1,
        )
        revoked = self._connection_event("close", audit_session_id=audit_session_id)
        self.assertEqual(revoked.status_code, 403, revoked.content)
        connection.refresh_from_db()
        self.assertIsNone(connection.conn_end)

    def test_deleted_controller_owner_cannot_remain_authoritative(self):
        connection, audit_session_id = self._open_connection()
        controller_password = uuid.uuid4().hex
        controller = UserProfile.objects.create_user(
            username="deleted-controller",
            password=controller_password,
        )
        controller_id = controller.id
        controller_uuid = device_uuid("audit-controller-deleted-owner")
        controller_device = self._device(
            owner=controller,
            rid="222222222",
            uuid=controller_uuid,
        )
        controller_token = self._login(
            "deleted-controller",
            controller_password,
            rid="222222222",
            uuid=controller_uuid,
        )
        active = self.client.get(
            f"/api/audit/conn/active?version=3&event_id={uuid.uuid4()}&id=111111111&session_id=99&conn_type=0",
            **self._auth_headers(controller_token),
        )
        self.assertEqual(active.status_code, 200, active.content)

        controller.delete()

        connection.refresh_from_db()
        controller_device.refresh_from_db()
        self.assertIsNone(connection.actor_id)
        self.assertIsNone(controller_device.owner_id)
        self.assertEqual(connection.controller_owner_id_at_bind, controller_id)
        self.assertEqual(
            connection.events.get(kind=ConnectionAuditEvent.KIND_CONTROLLER_BOUND).actor_id_at_event,
            controller_id,
        )
        rejected = self._post_json(
            "/api/audit/file",
            {
                "version": 3,
                "event_id": str(uuid.uuid4()),
                "audit_session_id": audit_session_id,
                "id": "111111111",
                "uuid": self.host_uuid,
                "peer_id": "222222222",
                "conn_id": 7,
                "type": 0,
                "path": "/documents",
                "is_file": False,
                "info": json.dumps(
                    {
                        "ip": "192.0.2.10",
                        "files": [["after-owner-delete.txt", 42]],
                    }
                ),
            },
            token=self.host_token,
        )
        self.assertEqual(rejected.status_code, 403, rejected.content)
        self.assertEqual(FileLog.objects.count(), 0)

    def test_device_deletion_preserves_identity_snapshots_and_event_history(self):
        connection, audit_session_id = self._open_connection()
        controller_password = uuid.uuid4().hex
        controller = UserProfile.objects.create_user(
            username="deleted-device-controller",
            password=controller_password,
        )
        controller_uuid = device_uuid("audit-deleted-controller-device")
        controller_device = self._device(
            owner=controller,
            rid="222222222",
            uuid=controller_uuid,
        )
        controller_token = self._login(
            "deleted-device-controller",
            controller_password,
            rid="222222222",
            uuid=controller_uuid,
        )
        active = self.client.get(
            f"/api/audit/conn/active?version=3&event_id={uuid.uuid4()}&id=111111111&session_id=99&conn_type=0",
            **self._auth_headers(controller_token),
        )
        self.assertEqual(active.status_code, 200, active.content)
        host_device_id = self.host_device.id
        controller_device_id = controller_device.id

        controller_device.delete()
        self.host_device.delete()

        connection.refresh_from_db()
        self.assertIsNone(connection.host_device_id)
        self.assertIsNone(connection.controller_device_id)
        self.assertEqual(connection.host_device_id_at_create, host_device_id)
        self.assertEqual(connection.controller_device_id_at_bind, controller_device_id)
        self.assertEqual(connection.owner_id_at_create, self.user.id)
        self.assertEqual(connection.controller_owner_id_at_bind, controller.id)
        self.assertEqual(connection.events.count(), 3)
        rejected = self._connection_event(
            "close",
            audit_session_id=audit_session_id,
        )
        self.assertEqual(rejected.status_code, 401, rejected.content)

    def test_database_rejects_unbound_v3_children_and_duplicate_sequences(self):
        connection, _audit_session_id = self._open_connection()
        for create in (
            lambda: FileLog.objects.create(
                audit_version=3,
                file="/forged",
                user_ip="192.0.2.10",
            ),
            lambda: AlarmLog.objects.create(
                audit_version=3,
                typ=AlarmLog.TYPE_SESSION_SCOPE_VIOLATION,
                reporter_device_id="111111111",
            ),
            lambda: ConnectionAuditEvent.objects.create(
                event_id=uuid.uuid4(),
                connection=connection,
                sequence=1,
                kind=ConnectionAuditEvent.KIND_ALARM,
                actor_id_at_event=self.user.id,
            ),
        ):
            with self.subTest(create=create), self.assertRaises(IntegrityError), transaction.atomic():
                create()


class AuditSessionConcurrencyTests(ApiTestMixin, TransactionTestCase):
    def setUp(self):
        if connection.vendor != "postgresql":
            self.skipTest("audit concurrency requires PostgreSQL row locks")
        super().setUp()
        self.host_uuid = device_uuid("audit-concurrent-host")
        self._device(owner=self.user, rid="111111111", uuid=self.host_uuid)
        self.host_token = self._login(
            "alice",
            "alice-pass",
            rid="111111111",
            uuid=self.host_uuid,
        )
        opened = self._host_event(
            "new",
            ip="192.0.2.10",
            type=0,
            conn_audit_ref="concurrent-ref",
        )
        self.assertEqual(opened.status_code, 201, opened.content)
        self.audit_session_id = opened.json()["audit_session_id"]

    def _host_event(self, action, **overrides):
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

    def _authorize_and_bind_controller(self):
        authorized = self._host_event(
            "update",
            audit_session_id=self.audit_session_id,
            peer=["222222222", "controller"],
            type=0,
            primary_auth=3,
            two_factor=1,
        )
        self.assertEqual(authorized.status_code, 200, authorized.content)
        controller_password = uuid.uuid4().hex
        controller = UserProfile.objects.create_user(
            username="concurrent-controller",
            password=controller_password,
        )
        controller_uuid = device_uuid("audit-concurrent-controller")
        self._device(owner=controller, rid="222222222", uuid=controller_uuid)
        controller_token = self._login(
            "concurrent-controller",
            controller_password,
            rid="222222222",
            uuid=controller_uuid,
        )
        active = self.client.get(
            f"/api/audit/conn/active?version=3&event_id={uuid.uuid4()}&id=111111111&session_id=99&conn_type=0",
            **self._auth_headers(controller_token),
        )
        self.assertEqual(active.status_code, 200, active.content)

    def _post_concurrently(self, requests):
        barrier = Barrier(len(requests))

        def send(path, payload):
            close_old_connections()
            client = Client()
            barrier.wait(timeout=5)
            try:
                response = client.post(
                    path,
                    data=json.dumps(payload),
                    content_type="application/json",
                    **self._auth_headers(self.host_token),
                )
                return response.status_code, response.json()
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=len(requests)) as executor:
            futures = [executor.submit(send, path, payload) for path, payload in requests]
            return [future.result(timeout=20) for future in futures]

    def _file_payload(self, event_id):
        return {
            "version": 3,
            "event_id": event_id,
            "audit_session_id": self.audit_session_id,
            "id": "111111111",
            "uuid": self.host_uuid,
            "peer_id": "222222222",
            "conn_id": 7,
            "type": 0,
            "path": "/documents",
            "is_file": False,
            "info": json.dumps(
                {
                    "ip": "192.0.2.10",
                    "files": [["concurrent.txt", 42]],
                }
            ),
        }

    def _alarm_payload(self, event_id):
        return {
            "version": 3,
            "event_id": event_id,
            "audit_session_id": self.audit_session_id,
            "id": "111111111",
            "uuid": self.host_uuid,
            "typ": AlarmLog.TYPE_SESSION_SCOPE_VIOLATION,
            "conn_id": 7,
            "conn_audit_ref": "concurrent-ref",
            "info": json.dumps({"message": "concurrent alarm"}),
        }

    def test_duplicate_file_event_is_acknowledged_once_without_duplicate_evidence(self):
        self._authorize_and_bind_controller()
        event_id = str(uuid.uuid4())
        responses = self._post_concurrently(
            [
                ("/api/audit/file", self._file_payload(event_id)),
                ("/api/audit/file", self._file_payload(event_id)),
            ]
        )

        self.assertEqual([status for status, _payload in responses], [200, 200])
        self.assertEqual(responses[0][1], responses[1][1])
        self.assertEqual(FileLog.objects.count(), 1)
        self.assertEqual(
            ConnectionAuditEvent.objects.filter(kind=ConnectionAuditEvent.KIND_FILE).count(),
            1,
        )

    def test_concurrent_file_and_alarm_have_unique_contiguous_sequences(self):
        self._authorize_and_bind_controller()
        responses = self._post_concurrently(
            [
                ("/api/audit/file", self._file_payload(str(uuid.uuid4()))),
                ("/api/audit/alarm", self._alarm_payload(str(uuid.uuid4()))),
            ]
        )

        self.assertEqual([status for status, _payload in responses], [200, 200])
        connection_log = ConnLog.objects.get()
        events = list(connection_log.events.order_by("sequence"))
        self.assertEqual([event.sequence for event in events], list(range(1, 6)))
        self.assertEqual(
            {event.kind for event in events[-2:]},
            {ConnectionAuditEvent.KIND_FILE, ConnectionAuditEvent.KIND_ALARM},
        )
        self.assertEqual(FileLog.objects.count(), 1)
        self.assertEqual(AlarmLog.objects.count(), 1)

    def test_concurrent_heartbeat_and_close_have_only_valid_serializations(self):
        self._authorize_and_bind_controller()
        heartbeat_event_id = str(uuid.uuid4())
        close_event_id = str(uuid.uuid4())
        responses = self._post_concurrently(
            [
                (
                    "/api/audit/conn",
                    {
                        "version": 3,
                        "event_id": heartbeat_event_id,
                        "action": "heartbeat",
                        "heartbeat_revision": 1,
                        "audit_session_id": self.audit_session_id,
                        "id": "111111111",
                        "uuid": self.host_uuid,
                        "conn_id": 7,
                        "session_id": 99,
                    },
                ),
                (
                    "/api/audit/conn",
                    {
                        "version": 3,
                        "event_id": close_event_id,
                        "action": "close",
                        "audit_session_id": self.audit_session_id,
                        "id": "111111111",
                        "uuid": self.host_uuid,
                        "conn_id": 7,
                        "session_id": 99,
                    },
                ),
            ]
        )

        heartbeat_status, heartbeat_body = responses[0]
        close_status, close_body = responses[1]
        self.assertEqual(close_status, 200, close_body)
        self.assertIn(heartbeat_status, (200, 409), heartbeat_body)
        self.assertEqual(close_body["state"], ConnLog.STATE_CLOSED)
        self.assertEqual(close_body["lease_remaining_seconds"], 0)

        connection_log = ConnLog.objects.get()
        self.assertEqual(connection_log.state, ConnLog.STATE_CLOSED)
        self.assertEqual(connection_log.event_revision, 4)
        self.assertEqual(connection_log.events.filter(kind=ConnectionAuditEvent.KIND_CLOSED).count(), 1)
        self.assertEqual(connection_log.heartbeat_revision, 1 if heartbeat_status == 200 else 0)
        if heartbeat_status == 409:
            self.assertEqual(heartbeat_body["state"], ConnLog.STATE_CLOSED)

        late = self._host_event(
            "heartbeat",
            heartbeat_revision=connection_log.heartbeat_revision + 1,
            audit_session_id=self.audit_session_id,
        )
        self.assertEqual(late.status_code, 409, late.content)
        connection_log.refresh_from_db()
        self.assertEqual(connection_log.state, ConnLog.STATE_CLOSED)
        self.assertEqual(connection_log.event_revision, 4)

    @override_settings(
        AUDIT_MAX_EVENTS_PER_CONNECTION=10,
        AUDIT_MAX_EVENTS_PER_DEVICE=5,
        AUDIT_MAX_EVENTS_PER_OWNER=5,
        AUDIT_MAX_EVENTS_GLOBAL=5,
    )
    def test_concurrent_connections_cannot_oversell_the_last_retained_event_slot(self):
        second = self._host_event(
            "new",
            conn_id=8,
            session_id=100,
            ip="192.0.2.11",
            type=0,
            conn_audit_ref="concurrent-ref-two",
        )
        self.assertEqual(second.status_code, 201, second.content)
        second_audit_session_id = second.json()["audit_session_id"]

        def update_payload(audit_session_id, conn_id, session_id, primary_auth):
            return {
                "version": 3,
                "event_id": str(uuid.uuid4()),
                "action": "update",
                "audit_session_id": audit_session_id,
                "id": "111111111",
                "uuid": self.host_uuid,
                "conn_id": conn_id,
                "session_id": session_id,
                "primary_auth": primary_auth,
            }

        responses = self._post_concurrently(
            [
                (
                    "/api/audit/conn",
                    update_payload(self.audit_session_id, 7, 99, 1),
                ),
                (
                    "/api/audit/conn",
                    update_payload(second_audit_session_id, 8, 100, 3),
                ),
            ]
        )

        self.assertEqual(sorted(status for status, _payload in responses), [200, 507])
        self.assertEqual(ConnectionAuditEvent.objects.count(), 3)
        self.assertEqual(sum(ConnLog.objects.values_list("event_revision", flat=True)), 3)
        usage = PersistentIngestionUsage.objects.get(kind="audit", scope="global")
        self.assertEqual((usage.items, usage.events), (2, 5))

    def test_concurrent_distinct_values_can_set_an_unset_fact_only_once(self):
        payloads = []
        for primary_auth in (1, 3):
            payloads.append(
                (
                    "/api/audit/conn",
                    {
                        "version": 3,
                        "event_id": str(uuid.uuid4()),
                        "action": "update",
                        "audit_session_id": self.audit_session_id,
                        "id": "111111111",
                        "uuid": self.host_uuid,
                        "conn_id": 7,
                        "session_id": 99,
                        "primary_auth": primary_auth,
                    },
                )
            )

        responses = self._post_concurrently(payloads)

        self.assertEqual(sorted(status for status, _payload in responses), [200, 409])
        connection_log = ConnLog.objects.get()
        self.assertIn(connection_log.primary_auth, (1, 3))
        self.assertEqual(connection_log.events.count(), 2)
        self.assertEqual(connection_log.event_revision, 2)
