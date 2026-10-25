from contextlib import contextmanager
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.core.management.commands.migrate import Command as DjangoMigrateCommand
from django.test import SimpleTestCase

from api import migration_lease as lease_module
from api.migration_lease import LOCK_TIMEOUT_EXIT_CODE, MigrationLeaseError, MigrationLeaseTimeout


class MigrationLeaseCommandTests(SimpleTestCase):
    def test_executor_is_constructed_only_after_the_lease_is_acquired(self):
        events = []

        @contextmanager
        def acquired(*args, **kwargs):
            events.append("lease-acquired")
            yield {"operation_id": "test"}
            events.append("lease-released")

        def migrate(*args, **kwargs):
            events.append("django-migrate")

        with (
            patch("api.management.commands.migrate_with_lease.migration_lease", acquired),
            patch.object(DjangoMigrateCommand, "handle", migrate),
            patch("api.management.commands.migrate_with_lease.check_release_schema") as schema_check,
        ):
            call_command(
                "migrate_with_lease",
                interactive=False,
                actor="unit-test",
                release_revision="test-revision",
            )

        self.assertEqual(events, ["lease-acquired", "django-migrate", "lease-released"])
        schema_check.assert_called_once_with(using="default")

    def test_lock_timeout_has_a_distinct_retryable_operation_exit_code(self):
        with patch(
            "api.management.commands.migrate_with_lease.migration_lease",
            side_effect=MigrationLeaseTimeout("migration lease acquisition timed out"),
        ):
            with self.assertRaises(CommandError) as captured:
                call_command(
                    "migrate_with_lease",
                    interactive=False,
                    actor="unit-test",
                    release_revision="test-revision",
                )
        self.assertEqual(captured.exception.returncode, LOCK_TIMEOUT_EXIT_CODE)

    def test_identity_and_deadline_contracts_fail_closed(self):
        with self.assertRaises(MigrationLeaseError):
            lease_module.migration_identity("actor with spaces", "actor")
        with self.assertRaises(MigrationLeaseError):
            lease_module.migration_identity("x" * 129, "release revision")

    def test_ledger_bypass_options_are_rejected_before_lock_acquisition(self):
        with patch("api.management.commands.migrate_with_lease.migration_lease") as acquire:
            with self.assertRaisesMessage(CommandError, "ledger-bypass options: fake"):
                call_command(
                    "migrate_with_lease",
                    interactive=False,
                    fake=True,
                    actor="unit-test",
                    release_revision="test-revision",
                )
        acquire.assert_not_called()
