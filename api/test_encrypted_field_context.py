import hashlib
import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import DatabaseError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase

from api import ingestion_governance, recording_crypto
from api.encrypted_fields import FIELD_PREFIX, UNBOUND_FIELD_PREFIX
from api.migration_test_support import restore_latest_migration_state
from api.models import (
    AddressBookProfile,
    OidcPendingAuth,
    RecordingUpload,
    RemoteDevice,
    RemotePeer,
    UserProfile,
)


class EncryptedFieldContextTests(TestCase):
    def setUp(self):
        self.owner = UserProfile.objects.create_user("context-owner", "context-password")
        self.profile = AddressBookProfile.objects.create(
            guid="context-profile",
            name="Context profile",
            owner=self.owner,
        )

    @staticmethod
    def _raw_value(table, column, pk_column, pk):
        with connection.cursor() as cursor:
            cursor.execute(
                f'SELECT "{column}" FROM "{table}" WHERE "{pk_column}" = %s',  # noqa: S608 - test allowlist
                [pk],
            )
            return cursor.fetchone()[0]

    @staticmethod
    def _replace_raw_value(table, column, pk_column, pk, value):
        with connection.cursor() as cursor:
            cursor.execute(
                f'UPDATE "{table}" SET "{column}" = %s WHERE "{pk_column}" = %s',  # noqa: S608
                [value, pk],
            )

    def _peer(self, rid, *, profile=None, rhash="", password=""):
        return RemotePeer.objects.create(
            profile=profile or self.profile,
            rid=rid,
            rhash=rhash,
            password=password,  # noqa: S106 - encrypted-field regression input
        )

    def test_ciphertext_cannot_move_between_fields(self):
        source = self._peer("context-source", rhash="source-rhash-secret")
        target = self._peer(
            "context-target",
            password="target-field-secret",  # noqa: S106 - encrypted-field regression input
        )
        source_rhash = self._raw_value("api_remotepeer", "rhash", "id", source.pk)

        self._replace_raw_value("api_remotepeer", "password", "id", target.pk, source_rhash)

        with self.assertRaises(ValidationError):
            target.refresh_from_db()

    def test_ciphertext_cannot_move_between_models(self):
        source = self._peer("model-source", rhash="source-model-secret")
        source_rhash = self._raw_value("api_remotepeer", "rhash", "id", source.pk)

        self._replace_raw_value(
            "api_addressbookprofile",
            "default_password",
            "id",
            self.profile.pk,
            source_rhash,
        )

        with self.assertRaises(ValidationError):
            self.profile.refresh_from_db()

    def test_ciphertext_cannot_move_between_rows_or_profiles(self):
        source = self._peer("row-source", rhash="source-row-secret")
        target = self._peer("row-target", rhash="target-row-secret")
        other_profile = AddressBookProfile.objects.create(
            guid="other-context-profile",
            name="Other context profile",
            owner=self.owner,
        )
        other_target = self._peer("profile-target", profile=other_profile, rhash="other-secret")
        source_rhash = self._raw_value("api_remotepeer", "rhash", "id", source.pk)

        for peer in (target, other_target):
            with self.subTest(peer=peer.rid):
                self._replace_raw_value("api_remotepeer", "rhash", "id", peer.pk, source_rhash)
                with self.assertRaises(ValidationError):
                    peer.refresh_from_db()

    def test_context_digest_tampering_is_rejected(self):
        peer = self._peer("digest-target", rhash="digest-secret")
        envelope = self._raw_value("api_remotepeer", "rhash", "id", peer.pk)
        prefix, key_id, digest, encoded = envelope.split(":", 3)
        tampered_digest = ("0" if digest[0] != "0" else "1") + digest[1:]
        self._replace_raw_value(
            "api_remotepeer",
            "rhash",
            "id",
            peer.pk,
            f"{prefix}:{key_id}:{tampered_digest}:{encoded}",
        )

        with self.assertRaises(ValidationError):
            peer.refresh_from_db()

    def test_authorized_plaintext_copy_reencrypts_for_the_target(self):
        source = self._peer("copy-source", rhash="copy-secret")
        target = self._peer("copy-target", rhash="old-target-secret")
        source_envelope = self._raw_value("api_remotepeer", "rhash", "id", source.pk)

        target.rhash = source.rhash
        target.save(update_fields=("rhash",))

        target_envelope = self._raw_value("api_remotepeer", "rhash", "id", target.pk)
        self.assertNotEqual(target_envelope, source_envelope)
        target.refresh_from_db()
        self.assertEqual(target.rhash, "copy-secret")

    def test_deleted_business_identifier_cannot_reuse_old_ciphertext(self):
        original = self._peer("reused-rid", rhash="old-generation-secret")
        old_envelope = self._raw_value("api_remotepeer", "rhash", "id", original.pk)
        old_context = original.secret_context
        original.delete()
        replacement = self._peer("reused-rid", rhash="new-generation-secret")
        self.assertNotEqual(replacement.secret_context, old_context)

        self._replace_raw_value("api_remotepeer", "rhash", "id", replacement.pk, old_envelope)

        with self.assertRaises(ValidationError):
            replacement.refresh_from_db()

    def test_context_and_plaintext_bulk_updates_fail_closed(self):
        peer = self._peer("bulk-target", rhash="bulk-secret")
        with self.assertRaises(ValidationError), transaction.atomic():
            RemotePeer.objects.filter(pk=peer.pk).update(rhash="bulk-plaintext")

        with self.assertRaises(DatabaseError), transaction.atomic():
            RemotePeer.objects.filter(pk=peer.pk).update(secret_context=uuid.uuid4())
        with self.assertRaises(DatabaseError), transaction.atomic():
            self._replace_raw_value("api_remotepeer", "secret_context", "id", peer.pk, None)
        with self.assertRaises(DatabaseError), transaction.atomic():
            RemotePeer.objects.create(
                profile=self.profile,
                rid="duplicate-context",
                secret_context=peer.secret_context,
            )
        with self.assertRaises(DatabaseError), transaction.atomic():
            RemotePeer.objects.create(
                profile=self.profile,
                rid="missing-context",
                secret_context=None,
            )

        peer.refresh_from_db()
        self.assertEqual(peer.rhash, "bulk-secret")

    def test_oidc_secrets_cannot_move_between_fields(self):
        pending = OidcPendingAuth.objects.create(
            state="context-oidc",
            poll_code_hash=hashlib.sha256(b"context-poll").hexdigest(),
            provider="example",
            nonce="context-nonce",
            code_verifier="context-verifier",
        )
        nonce = self._raw_value("api_oidcpendingauth", "nonce", "state", pending.pk)
        self._replace_raw_value("api_oidcpendingauth", "code_verifier", "state", pending.pk, nonce)

        with self.assertRaises(ValidationError):
            pending.refresh_from_db()

    def test_device_authority_change_clears_address_book_password(self):
        device = RemoteDevice.objects.create(
            rid="context-device",
            uuid="context-device-uuid",
            owner=self.owner,
            cpu="-",
            hostname="-",
            memory="-",
            os="linux",
            username="",
            version="-",
            address_book_password="device-secret",  # noqa: S106 - encrypted-field regression input
        )
        device.deployment_generation += 1
        device.save(update_fields=("deployment_generation",))
        self.assertEqual(
            self._raw_value("api_remotedevice", "address_book_password", "id", device.pk),
            "",
        )

        device.address_book_password = "replacement-secret"  # noqa: S105 - encrypted-field regression input
        device.save(update_fields=("address_book_password",))
        other_owner = UserProfile.objects.create_user("context-other-owner", "other-password")
        RemoteDevice.objects.filter(pk=device.pk).update(owner=other_owner)
        self.assertEqual(
            self._raw_value("api_remotedevice", "address_book_password", "id", device.pk),
            "",
        )

    def _recording_upload(self, name):
        storage_object_id = uuid.uuid4()
        return RecordingUpload.objects.create(
            create_id=uuid.uuid4(),
            device_id=None,
            device_id_at_create=1,
            owner_id_at_create=self.owner.pk,
            deployment_generation=0,
            device_rid_at_create="record-context",
            device_uuid_at_create="recording-context-uuid",
            storage_object_id=storage_object_id,
            storage_namespace=ingestion_governance.recording_namespace(storage_object_id),
            filename=f"{name}.webm",
            encryption_version=recording_crypto.FORMAT_VERSION,
            data_key_kek_id=settings.DATA_ENCRYPTION_PRIMARY_KEY_ID,
            encrypted_data_key=recording_crypto.encode_data_key(name.encode().ljust(32, b"x")[:32]),
            storage_offset=recording_crypto.HEADER_SIZE,
        )

    def test_recording_data_key_cannot_move_between_uploads(self):
        source = self._recording_upload("source")
        target = self._recording_upload("target")
        source_pk = RecordingUpload._meta.pk.get_db_prep_value(source.pk, connection)
        target_pk = RecordingUpload._meta.pk.get_db_prep_value(target.pk, connection)
        envelope = self._raw_value("api_recordingupload", "encrypted_data_key", "upload_id", source_pk)
        self._replace_raw_value("api_recordingupload", "encrypted_data_key", "upload_id", target_pk, envelope)

        with self.assertRaises(ValidationError):
            target.refresh_from_db()


class EncryptedFieldContextMigrationTests(TransactionTestCase):
    migrate_from = ("api", "0031_control_filter_indexes")
    migrate_to = ("api", "0032_context_bound_encrypted_fields")

    def test_v2_values_migrate_to_v3_and_reverse_to_v2(self):
        executor = MigrationExecutor(connection)
        try:
            executor.migrate([self.migrate_from])
            old_apps = executor.loader.project_state([self.migrate_from]).apps
            OldPending = old_apps.get_model("api", "OidcPendingAuth")
            pending = OldPending.objects.create(
                state="migration-context-state",
                poll_code_hash=hashlib.sha256(b"migration-context-poll").hexdigest(),
                provider="example",
                nonce="migration-nonce",
                code_verifier="migration-verifier",
            )
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT nonce, code_verifier FROM api_oidcpendingauth WHERE state = %s",
                    [pending.pk],
                )
                legacy_values = cursor.fetchone()
            self.assertTrue(all(value.startswith(UNBOUND_FIELD_PREFIX) for value in legacy_values))

            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_to])
            new_apps = executor.loader.project_state([self.migrate_to]).apps
            NewPending = new_apps.get_model("api", "OidcPendingAuth")
            migrated = NewPending.objects.get(pk=pending.pk)
            self.assertEqual(migrated.nonce, "migration-nonce")
            self.assertEqual(migrated.code_verifier, "migration-verifier")
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT nonce, code_verifier, secret_context FROM api_oidcpendingauth WHERE state = %s",
                    [pending.pk],
                )
                nonce, verifier, secret_context = cursor.fetchone()
            self.assertTrue(nonce.startswith(FIELD_PREFIX))
            self.assertTrue(verifier.startswith(FIELD_PREFIX))
            self.assertIsNotNone(secret_context)

            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_from])
            restored_apps = executor.loader.project_state([self.migrate_from]).apps
            RestoredPending = restored_apps.get_model("api", "OidcPendingAuth")
            restored = RestoredPending.objects.get(pk=pending.pk)
            self.assertEqual(restored.nonce, "migration-nonce")
            self.assertEqual(restored.code_verifier, "migration-verifier")
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT nonce, code_verifier FROM api_oidcpendingauth WHERE state = %s",
                    [pending.pk],
                )
                restored_values = cursor.fetchone()
            self.assertTrue(all(value.startswith(UNBOUND_FIELD_PREFIX) for value in restored_values))

            executor = MigrationExecutor(connection)
            executor.migrate([self.migrate_to])
        finally:
            restore_latest_migration_state()
