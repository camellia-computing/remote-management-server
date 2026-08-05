import json
import uuid

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from api.models import ConnLog, RecordingUpload, UserProfile


class Command(BaseCommand):
    help = "Place or release an explicit retention hold on one recording or connection audit."

    def add_arguments(self, parser):
        parser.add_argument("kind", choices=("recording", "audit"))
        parser.add_argument("resource_id")
        parser.add_argument("--actor", required=True, help="Active administrator username authorizing the change.")
        parser.add_argument("--reason", required=True)
        action = parser.add_mutually_exclusive_group(required=True)
        action.add_argument("--hold", action="store_true")
        action.add_argument("--release", action="store_true")

    def handle(self, *args, **options):
        reason = options["reason"].strip()
        if not reason:
            raise CommandError("reason must contain between 1 and 512 UTF-8 bytes")
        actor = UserProfile.objects.filter(
            username=options["actor"],
            is_active=True,
            is_admin=True,
        ).first()
        if actor is None:
            raise CommandError("actor must be an active administrator")
        recorded_reason = f"{actor.username}: {reason}"
        if len(recorded_reason.encode()) > 512:
            raise CommandError("actor and reason must fit within 512 UTF-8 bytes")
        try:
            resource_id = uuid.UUID(options["resource_id"])
        except ValueError as error:
            raise CommandError("resource_id must be a canonical UUID") from error
        if str(resource_id) != options["resource_id"]:
            raise CommandError("resource_id must be a canonical UUID")
        model = RecordingUpload if options["kind"] == "recording" else ConnLog
        lookup = {"pk": resource_id} if model is RecordingUpload else {"guid": resource_id}
        with transaction.atomic():
            resource = model.objects.select_for_update().filter(**lookup).first()
            if resource is None:
                raise CommandError("retention resource does not exist")
            resource.retention_hold = bool(options["hold"])
            resource.retention_hold_reason = recorded_reason
            resource.retention_hold_at = timezone.now()
            resource.save(
                update_fields=(
                    "retention_hold",
                    "retention_hold_reason",
                    "retention_hold_at",
                )
            )
        self.stdout.write(
            json.dumps(
                {
                    "actor_id": actor.pk,
                    "hold": resource.retention_hold,
                    "kind": options["kind"],
                    "resource_id": str(resource_id),
                },
                sort_keys=True,
            )
        )
