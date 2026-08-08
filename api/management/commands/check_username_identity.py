from django.core.management.base import BaseCommand, CommandError

from api.username_identity import (
    USERNAME_CANONICAL_ALGORITHM,
    UsernameIdentityError,
    check_username_identity,
)


class Command(BaseCommand):
    help = "Validate the versioned username canonical identity and database contract."

    def add_arguments(self, parser):
        parser.add_argument("--database", default="default")

    def handle(self, *args, **options):
        try:
            check_username_identity(using=options["database"], full=True)
        except UsernameIdentityError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(self.style.SUCCESS(f"username identity contract is valid: {USERNAME_CANONICAL_ALGORITHM}"))
