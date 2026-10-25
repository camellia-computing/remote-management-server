import json
import uuid

from django.db import IntegrityError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

from api.management_operations import (
    ManagementMutation,
    ManagementOperationRetired,
    execute_management_operation,
    find_management_operation,
)
from api.migration_test_support import restore_latest_migration_state
from api.models import ManagementBatchOperation, UserProfile


class PrivateReceiptMigrationTests(TransactionTestCase):
    old_target = ("api", "0034_frozen_username_identity")
    new_target = ("api", "0035_private_operation_receipts")

    def setUp(self):
        executor = MigrationExecutor(connection)
        executor.migrate([self.old_target])
        apps = executor.loader.project_state([self.old_target]).apps
        self.LegacyOperation = apps.get_model("api", "ManagementBatchOperation")
        self.owner = apps.get_model("api", "UserProfile")._base_manager.create(
            username="receipt-migration-owner", username_canonical=b"receipt-migration-owner"
        )

    def tearDown(self):
        restore_latest_migration_state()
        UserProfile._base_manager.filter(pk=self.owner.pk).delete()
        super().tearDown()

    def legacy_receipt(self):
        return self.LegacyOperation._base_manager.create(
            operation_id=uuid.uuid4(),
            actor_id=self.owner.pk,
            operation="privacy_migration",
            request_digest="a" * 64,
            status_code=200,
            response={"request_digest": "a" * 64, "legacy": "unsafe-public-copy"},
            secret_response=json.dumps({"token": "SYNTHETIC-LEGACY-SHARE-TOKEN"}),
        )

    def test_upgrade_retires_legacy_receipt_without_forgetting_the_operation_or_repeating_mutation(self):
        legacy = self.legacy_receipt()
        MigrationExecutor(connection).migrate([self.new_target])
        retired = ManagementBatchOperation.objects.get(pk=legacy.pk)
        self.assertEqual(
            (retired.actor_id, retired.operation_id, retired.operation),
            (legacy.actor_id, legacy.operation_id, legacy.operation),
        )
        self.assertEqual(
            (retired.receipt_version, retired.status_code, retired.request_digest, retired.secret_response),
            (0, 410, "0" * 64, ""),
        )
        with connection.cursor() as cursor:
            columns = {
                field.name
                for field in connection.introspection.get_table_description(cursor, "api_managementbatchoperation")
            }
        self.assertNotIn("response", columns)
        owner = UserProfile.objects.get(pk=self.owner.pk)
        self.client.force_login(owner)
        retired_response = self.client.get(f"/api/management-operations/{legacy.operation_id}")
        self.assertEqual(retired_response.status_code, 410, retired_response.content)
        self.assertEqual(retired_response.json()["code"], "operation_receipt_retired")
        self.assertEqual(retired_response["Cache-Control"], "no-store, private")
        intruder = UserProfile.objects.create_user("retired-receipt-intruder", "Synthetic-intruder-password-78!")
        self.client.force_login(intruder)
        denied = self.client.get(f"/api/management-operations/{legacy.operation_id}")
        self.assertEqual(denied.status_code, 404, denied.content)
        with self.assertRaises(ManagementOperationRetired):
            find_management_operation(actor=owner, operation_id=legacy.operation_id)
        with self.assertRaises(ManagementOperationRetired):
            execute_management_operation(
                actor=owner,
                operation_id=legacy.operation_id,
                operation=legacy.operation,
                request_document={"password": "SYNTHETIC-NEW-INTENT"},
                requested={"results": 1},
                mutation=lambda: self.fail("retired operation ID must never apply a second mutation"),
            )
        for version, status in [(1, 410), (2, 200), (0, 200)]:
            with (
                self.subTest(version=version, status=status),
                self.assertRaises(IntegrityError),
                transaction.atomic(),
                connection.cursor() as cursor,
            ):
                cursor.execute(
                    "UPDATE api_managementbatchoperation SET receipt_version = %s, status_code = %s WHERE generation = %s",
                    [version, status, legacy.pk],
                )

    def test_reverse_retires_private_keys_before_the_old_reader_can_expose_the_container(self):
        MigrationExecutor(connection).migrate([self.new_target])
        owner = UserProfile.objects.get(pk=self.owner.pk)
        operation_id = uuid.uuid4()
        execute_management_operation(
            actor=owner,
            operation_id=operation_id,
            operation="reverse_privacy",
            request_document={"password": "SYNTHETIC-PRIVATE-INTENT"},
            requested={"results": 1},
            mutation=lambda: ManagementMutation(
                status_code=200,
                body={"token": "SYNTHETIC-PRIVATE-RESPONSE"},
                applied={"results": 1},
                result_state={"created": True},
            ),
        )
        private_key = json.loads(ManagementBatchOperation.objects.get(operation_id=operation_id).secret_response)[
            "binding"
        ]["key"]
        MigrationExecutor(connection).migrate([self.old_target])
        old = self.LegacyOperation._base_manager.get(operation_id=operation_id)
        self.assertEqual(
            (old.request_digest, old.status_code, old.secret_response, old.response), ("0" * 64, 410, "", {})
        )
        self.assertNotIn(private_key, json.dumps(old.response))
        MigrationExecutor(connection).migrate([self.new_target])
        with self.assertRaises(ManagementOperationRetired):
            find_management_operation(actor=owner, operation_id=operation_id)

    def test_ddl_failure_rolls_back_retirement_keys_schema_and_migration_record(self):
        legacy = self.legacy_receipt()

        def fail_drop(execute, sql, params, many, context):
            if "DROP COLUMN response" in sql:
                raise RuntimeError("injected receipt migration failure")
            return execute(sql, params, many, context)

        with connection.execute_wrapper(fail_drop), self.assertRaisesMessage(RuntimeError, "injected receipt"):
            MigrationExecutor(connection).migrate([self.new_target])
        untouched = self.LegacyOperation._base_manager.get(pk=legacy.pk)
        self.assertEqual(
            (untouched.request_digest, untouched.status_code, untouched.response), ("a" * 64, 200, legacy.response)
        )
        self.assertEqual(json.loads(untouched.secret_response)["token"], "SYNTHETIC-LEGACY-SHARE-TOKEN")
        MigrationExecutor(connection).migrate([self.new_target])
        self.assertEqual(ManagementBatchOperation.objects.get(pk=legacy.pk).receipt_version, 0)
