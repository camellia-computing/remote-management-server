from dataclasses import dataclass

from django.db import transaction

from api.models_user import UserProfile
from api.models_work import RemoteToken

MAX_CREDENTIAL_GENERATION = (1 << 63) - 1


class CredentialGenerationExhausted(RuntimeError):
    pass


@dataclass(frozen=True)
class CredentialRevocation:
    revoked_users: int
    deleted_tokens: int


def revoke_device_credentials(device_ids):
    """Delete every bearer bound to the selected device rows."""

    normalized_ids = {int(device_id) for device_id in device_ids if not isinstance(device_id, bool)}
    normalized_ids = {device_id for device_id in normalized_ids if device_id > 0}
    if not normalized_ids:
        return 0
    return RemoteToken.objects.filter(device_id__in=sorted(normalized_ids)).delete()[0]


def revoke_user_credentials(user_ids):
    """Atomically invalidate every credential issued for the selected users."""

    normalized_ids = set()
    for user_id in user_ids:
        if isinstance(user_id, bool):
            raise ValueError("User IDs must be positive integers")
        try:
            parsed_user_id = int(user_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("User IDs must be positive integers") from exc
        if parsed_user_id <= 0:
            raise ValueError("User IDs must be positive integers")
        normalized_ids.add(parsed_user_id)
    normalized_ids = sorted(normalized_ids)
    if not normalized_ids:
        return CredentialRevocation(revoked_users=0, deleted_tokens=0)

    with transaction.atomic():
        users = list(
            UserProfile.objects.select_for_update()
            .filter(pk__in=normalized_ids)
            .only("pk", "credential_generation")
            .order_by("pk")
        )
        for user in users:
            if user.credential_generation >= MAX_CREDENTIAL_GENERATION:
                raise CredentialGenerationExhausted("Credential generation is exhausted")
            user.credential_generation += 1
        if users:
            UserProfile.objects.bulk_update(users, ("credential_generation",))
        deleted_tokens = RemoteToken.objects.filter(device__owner_id__in=[user.pk for user in users]).delete()[0]

    return CredentialRevocation(
        revoked_users=len(users),
        deleted_tokens=deleted_tokens,
    )
