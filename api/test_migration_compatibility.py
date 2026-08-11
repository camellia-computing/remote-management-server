import datetime
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.db.models import Func, TextField
from django.test import SimpleTestCase

from api import migration_compatibility
from api.migration_compatibility import (
    MigrationCompatibilityError,
    check_migration_compatibility,
    discover_migration_runtime_symbols,
    load_migration_compatibility_manifest,
)


class MigrationCompatibilityTests(SimpleTestCase):
    def test_manifest_matches_every_historical_runtime_reference(self):
        manifest = check_migration_compatibility()
        self.assertEqual(
            {item["path"]: item["consumers"] for item in manifest},
            discover_migration_runtime_symbols(),
        )

    def test_all_contracts_have_frozen_deconstruct_or_callable_shape(self):
        manifest = {item["path"]: item for item in load_migration_compatibility_manifest()}
        encrypted = migration_compatibility._resolve("api.encrypted_fields.EncryptedTextField")
        self.assertTrue(issubclass(encrypted, TextField))
        self.assertEqual(
            encrypted(max_length=1).deconstruct()[1],
            manifest["api.encrypted_fields.EncryptedTextField"]["deconstruct_path"],
        )

        manager = migration_compatibility._resolve("api.models_user.MyUserManager")
        self.assertEqual(
            manager().deconstruct()[1],
            manifest["api.models_user.MyUserManager"]["deconstruct_path"],
        )

        expression = migration_compatibility._resolve("api.audit_expressions.AuditSearchDocument")
        self.assertTrue(issubclass(expression, Func))
        self.assertEqual(
            expression("field").deconstruct()[0],
            manifest["api.audit_expressions.AuditSearchDocument"]["deconstruct_path"],
        )

        expiry = migration_compatibility._resolve("api.models_work.share_link_expiry")
        frozen_now = datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC)
        with patch("api.models_work.timezone.now", return_value=frozen_now):
            self.assertEqual(expiry(), frozen_now + datetime.timedelta(minutes=15))

    def test_missing_or_new_source_reference_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="camellia-migration-compat-") as temporary:
            migration_dir = Path(temporary)
            (migration_dir / "0001_initial.py").write_text(
                "import api.models_work\n\nvalue = api.models_work.share_link_expiry\n",
                encoding="utf-8",
            )
            with self.assertRaisesMessage(MigrationCompatibilityError, "source drift"):
                check_migration_compatibility(migration_dir)
