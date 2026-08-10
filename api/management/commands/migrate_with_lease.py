import os

from django.conf import settings
from django.core.management.base import CommandError
from django.core.management.commands.migrate import Command as DjangoMigrateCommand
from django.db import connections

from api.migration_lease import (
    LOCK_TIMEOUT_EXIT_CODE,
    MigrationLeaseError,
    MigrationLeaseTimeout,
    migration_lease,
)
from api.release_schema import ReleaseSchemaError, check_release_schema


class Command(DjangoMigrateCommand):
    help = "Run Django migrations under the global PostgreSQL migration lease."

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument(
            "--lock-timeout-seconds",
            type=int,
            default=settings.MIGRATION_LOCK_TIMEOUT_SECONDS,
        )
        parser.add_argument(
            "--actor",
            default=os.environ.get("CAMELLIA_REMOTE_MIGRATION_ACTOR", "operator"),
        )
        parser.add_argument(
            "--release-revision",
            default=os.environ.get("CAMELLIA_REMOTE_RELEASE_REVISION", "source-tree"),
        )

    def handle(self, *args, **options):
        unsupported = [flag for flag in ("fake", "fake_initial", "prune", "run_syncdb") if options.get(flag)]
        if unsupported:
            raise CommandError(
                "leased production migrations reject ledger-bypass options: " + ",".join(sorted(unsupported))
            )
        database = connections[options["database"]]
        try:
            with migration_lease(
                database,
                timeout_seconds=options.pop("lock_timeout_seconds"),
                actor=options.pop("actor"),
                release_revision=options.pop("release_revision"),
                output=self.stdout,
            ):
                # Django constructs its MigrationExecutor inside handle(). It
                # therefore reads the ledger and rebuilds the plan only after
                # this process becomes the lease holder.
                result = super().handle(*args, **options)
                if (
                    options.get("app_label") is None
                    and not options.get("plan")
                    and not options.get("check_unapplied")
                    and not options.get("prune")
                ):
                    check_release_schema(using=options["database"])
                return result
        except MigrationLeaseTimeout as exc:
            raise CommandError(str(exc), returncode=LOCK_TIMEOUT_EXIT_CODE) from exc
        except (MigrationLeaseError, ReleaseSchemaError) as exc:
            raise CommandError(str(exc)) from exc
