from django.conf import settings
from django.db import DEFAULT_DB_ALIAS, transaction

from api.encrypted_fields import key_canary, key_fingerprint, verify_key_canary
from api.models import DataEncryptionKeyState


def reset_data_encryption_key_inventory(*, using=DEFAULT_DB_ALIAS):
    """Build the exact key inventory required by one isolated database test."""
    keyring = dict(settings.DATA_ENCRYPTION_KEYS)
    primary_key_id = settings.DATA_ENCRYPTION_PRIMARY_KEY_ID
    if not keyring or primary_key_id not in keyring:
        raise AssertionError("Test data-encryption settings have no configured primary key")

    expected_ids = sorted(keyring)
    with transaction.atomic(using=using):
        manager = DataEncryptionKeyState.objects.using(using)
        manager.all().delete()
        manager.bulk_create(
            [
                DataEncryptionKeyState(
                    key_id=key_id,
                    key_fingerprint=key_fingerprint(key),
                    encrypted_canary=key_canary(key_id),
                    is_primary=key_id == primary_key_id,
                )
                for key_id, key in keyring.items()
            ]
        )
        states = list(manager.order_by("key_id"))
        if (
            [state.key_id for state in states] != expected_ids
            or [state.key_id for state in states if state.is_primary] != [primary_key_id]
            or any(
                not verify_key_canary(
                    state.key_id,
                    state.key_fingerprint,
                    state.encrypted_canary,
                )
                for state in states
            )
        ):
            raise AssertionError("Test data-encryption key inventory failed verification")
    return states
