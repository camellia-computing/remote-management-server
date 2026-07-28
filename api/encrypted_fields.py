import base64
import binascii

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import models
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox


FIELD_PREFIX = "secretbox:v1:"


def _secret_box():
    key = getattr(settings, "DATA_ENCRYPTION_KEY_BYTES", b"")
    if not isinstance(key, bytes) or len(key) != SecretBox.KEY_SIZE:
        raise ImproperlyConfigured("CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY must decode to exactly 32 bytes")
    return SecretBox(key)


class EncryptedTextField(models.TextField):
    """Randomized authenticated encryption for non-searchable secrets."""

    description = "SecretBox-encrypted text"

    def _decrypt(self, value):
        if value in (None, "") or not isinstance(value, str):
            return value
        if not value.startswith(FIELD_PREFIX):
            raise ValidationError("Encrypted field contains unversioned data")
        encoded = value.removeprefix(FIELD_PREFIX)
        try:
            ciphertext = base64.b64decode(encoded, validate=True)
            return _secret_box().decrypt(ciphertext).decode("utf-8")
        except (binascii.Error, CryptoError, UnicodeDecodeError) as exc:
            raise ValidationError("Encrypted field authentication failed") from exc

    def from_db_value(self, value, expression, connection):
        return self._decrypt(value)

    def to_python(self, value):
        if isinstance(value, str) and value.startswith(FIELD_PREFIX):
            return self._decrypt(value)
        return value

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        if value in (None, ""):
            return value
        if not isinstance(value, str):
            raise ValidationError("Encrypted field value must be text")
        encrypted = _secret_box().encrypt(value.encode("utf-8"))
        return FIELD_PREFIX + base64.b64encode(bytes(encrypted)).decode("ascii")
