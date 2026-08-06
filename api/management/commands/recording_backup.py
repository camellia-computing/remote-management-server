import json
import sys

from django.core.management.base import BaseCommand, CommandError

from api import recording_inventory


class Command(BaseCommand):
    help = "Create, export, complete, abort, or restore a consistent recording backup epoch."

    def add_arguments(self, parser):
        commands = parser.add_subparsers(dest="operation", required=True)
        begin = commands.add_parser("begin")
        begin.add_argument("--backup-id", required=True)
        begin.add_argument("--requested-at", required=True)

        export = commands.add_parser("export")
        export.add_argument("--backup-id", required=True)

        for operation in ("finish", "abort"):
            command = commands.add_parser(operation)
            command.add_argument("--backup-id", required=True)
        commands.choices["abort"].add_argument("--ignore-missing", action="store_true")

        commands.add_parser("restore-preflight")

        restore = commands.add_parser("restore")
        restore.add_argument("--backup-id", required=True)
        restore.add_argument("--epoch-id", required=True)
        restore.add_argument("--inventory-digest", required=True)

    def handle(self, *args, **options):
        operation = options["operation"]
        try:
            if operation == "begin":
                epoch = recording_inventory.begin_backup(options["backup_id"], options["requested_at"])
                self.stdout.write(json.dumps(recording_inventory.backup_summary(epoch), sort_keys=True))
                return
            if operation == "export":
                output = getattr(getattr(self.stdout, "_out", sys.stdout), "buffer", None)
                if output is None:
                    raise CommandError("recording backup export requires a binary stdout stream")
                recording_inventory.export_backup(options["backup_id"], output)
                output.flush()
                return
            if operation == "finish":
                epoch = recording_inventory.finish_backup(options["backup_id"])
                self.stdout.write(json.dumps(recording_inventory.backup_summary(epoch), sort_keys=True))
                return
            if operation == "abort":
                aborted = recording_inventory.abort_backup(
                    options["backup_id"],
                    ignore_mismatch=bool(options["ignore_missing"]),
                )
                self.stdout.write(json.dumps({"aborted": aborted, "backup_id": options["backup_id"]}, sort_keys=True))
                return
            if operation == "restore-preflight":
                recording_inventory.restore_preflight()
                self.stdout.write(json.dumps({"recording_restore_preflight": "ok"}, sort_keys=True))
                return
            input_stream = getattr(sys.stdin, "buffer", sys.stdin)
            epoch = recording_inventory.restore_backup(
                options["backup_id"],
                options["epoch_id"],
                options["inventory_digest"],
                input_stream,
            )
            self.stdout.write(json.dumps(recording_inventory.backup_summary(epoch), sort_keys=True))
        except (recording_inventory.RecordingBackupInProgress, recording_inventory.RecordingInventoryError) as error:
            raise CommandError(str(error)) from error
