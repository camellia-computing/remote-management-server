import datetime
import json

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from api.ingestion_retention import purge_audit_retention, purge_recording_retention
from api.models import (
    DeviceProofChallenge,
    DeviceRecoveryApproval,
    LoginAdmissionLock,
    LoginAttempt,
    OidcPendingAuth,
    RemoteToken,
    RequestRateBucket,
    RequestRateLease,
    ShareLink,
)


class Command(BaseCommand):
    help = "Delete expired authentication, request-admission, and retained share state."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report eligible rows without changing the database.",
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=settings.INGESTION_CLEANUP_BATCH_SIZE,
            help="Maximum number of rows processed per persistent-ingestion category.",
        )

    def handle(self, *args, **options):
        now = timezone.now()
        batch_size = options["batch_size"]
        if not 1 <= batch_size <= 1000:
            raise CommandError("batch-size must be between 1 and 1000")
        login_cutoff = now - datetime.timedelta(minutes=settings.LOGIN_ATTEMPT_RETENTION_MINUTES)
        oidc_cutoff = now - datetime.timedelta(minutes=settings.OIDC_PENDING_RETENTION_MINUTES)
        share_cutoff = now - datetime.timedelta(days=settings.SHARE_LINK_RETENTION_DAYS)

        login_attempts = LoginAttempt.objects.filter(created_at__lt=login_cutoff)
        login_admission_locks = LoginAdmissionLock.objects.filter(updated_at__lt=login_cutoff)
        oidc_sessions = OidcPendingAuth.objects.filter(created_at__lt=oidc_cutoff)
        device_proof_challenges = DeviceProofChallenge.objects.filter(expires_at__lte=now)
        device_recovery_approvals = DeviceRecoveryApproval.objects.filter(expires_at__lte=now)
        access_tokens = RemoteToken.objects.filter(expires_at__lte=now)
        expired_share_links = ShareLink.objects.filter(expires_at__lte=now, is_expired=False)
        retained_share_links = ShareLink.objects.filter(
            Q(is_used=True) | Q(expires_at__lte=now),
            create_time__lt=share_cutoff,
        )
        request_rate_buckets = RequestRateBucket.objects.filter(expires_at__lte=now)
        request_rate_leases = RequestRateLease.objects.filter(expires_at__lte=now)

        result = {
            "expired_access_tokens": access_tokens.count(),
            "expired_oidc_sessions": oidc_sessions.count(),
            "expired_device_proof_challenges": device_proof_challenges.count(),
            "expired_device_recovery_approvals": device_recovery_approvals.count(),
            "expired_share_links_marked": expired_share_links.count(),
            "login_attempts": login_attempts.count(),
            "login_admission_locks": login_admission_locks.count(),
            "retained_share_links": retained_share_links.count(),
            "request_rate_buckets": request_rate_buckets.count(),
            "request_rate_leases": request_rate_leases.count(),
        }
        if not options["dry_run"]:
            with transaction.atomic():
                login_attempts.delete()
                login_admission_locks.delete()
                oidc_sessions.delete()
                device_proof_challenges.delete()
                device_recovery_approvals.delete()
                access_tokens.delete()
                expired_share_links.update(is_expired=True)
                retained_share_links.delete()
                request_rate_buckets.delete()
                request_rate_leases.delete()

        result["dry_run"] = bool(options["dry_run"])
        result.update(
            purge_recording_retention(
                now,
                batch_size=batch_size,
                dry_run=bool(options["dry_run"]),
            )
        )
        result.update(
            purge_audit_retention(
                now,
                batch_size=batch_size,
                dry_run=bool(options["dry_run"]),
            )
        )
        self.stdout.write(json.dumps(result, sort_keys=True))
