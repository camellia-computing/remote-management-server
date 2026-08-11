import json

from django.core.management.base import BaseCommand, CommandError

from api.release_schema import ReleaseSchemaError, check_release_schema


class Command(BaseCommand):
    help = "Verify the exact release migration ledger and critical schema capabilities."

    def add_arguments(self, parser):
        parser.add_argument("--database", default="default")

    def handle(self, *args, **options):
        try:
            result = check_release_schema(using=options["database"])
        except ReleaseSchemaError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(json.dumps(result, sort_keys=True))
