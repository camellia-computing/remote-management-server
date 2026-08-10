import json

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from api.sequence_capacity import collect_sequence_samples, record_sequence_capacity
from camellia_remote_management.observability import background_operation

_FAIL_LEVELS = {"none": 3, "warning": 1, "critical": 2}
_STATUS_RANK = {"ok": 0, "warning": 1, "critical": 2}


class Command(BaseCommand):
    help = "Report application-owned database sequence use, growth, and estimated exhaustion time."

    def add_arguments(self, parser):
        parser.add_argument(
            "--fail-level",
            choices=tuple(_FAIL_LEVELS),
            default="critical",
            help="Exit non-zero when the overall status reaches this level; use none to only report.",
        )

    def handle(self, *args, **options):
        with background_operation("check_sequence_capacity"):
            sampled_at = timezone.now()
            report = record_sequence_capacity(
                collect_sequence_samples(),
                sampled_at=sampled_at,
                warning_percent=settings.SEQUENCE_CAPACITY_WARNING_PERCENT,
                critical_percent=settings.SEQUENCE_CAPACITY_CRITICAL_PERCENT,
            )
            payload = {
                "schema_version": 1,
                "sampled_at": sampled_at.isoformat(),
                **report,
            }
            self.stdout.write(json.dumps(payload, separators=(",", ":"), sort_keys=True))
            fail_level = options["fail_level"]
            if fail_level != "none" and _STATUS_RANK[report["status"]] >= _FAIL_LEVELS[fail_level]:
                raise CommandError(f"database sequence capacity reached {report['status']} status")
