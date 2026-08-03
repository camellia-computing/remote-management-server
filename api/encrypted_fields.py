import base64
import binascii
import hashlib
import secrets
from collections.abc import Mapping

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.db import models
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox

LEGACY_FIELD_PREFIX = "secretbox:v1:"
FIELD_PREFIX = "secretbox:v2:"
KEY_CANARY_PLAINTEXT = b"camellia-data-encryption-canary-v1"


def _keyring():
    keyring = getattr(settings, "DATA_ENCRYPTION_KEYS", {})
    primary_key_id = getattr(settings, "DATA_ENCRYPTION_PRIMARY_KEY_ID", "")
    if not isinstance(keyring, Mapping):
        raise ImproperlyConfigured("The data-encryption keyring is invalid")
    if primary_key_id not in keyring:
        raise ImproperlyConfigured("The primary data-encryption key is not present in the keyring")
    for key_id, key in keyring.items():
        if not isinstance(key_id, str) or not isinstance(key, bytes) or len(key) != SecretBox.KEY_SIZE:
            raise ImproperlyConfigured("The data-encryption keyring contains an invalid entry")
    return keyring, primary_key_id


def key_fingerprint(key):
    if not isinstance(key, bytes) or len(key) != SecretBox.KEY_SIZE:
        raise ImproperlyConfigured("A data-encryption key must contain exactly 32 bytes")
    return hashlib.sha256(key).hexdigest()


def encrypt_text(value, *, key_id=None):
    if not isinstance(value, str):
        raise ValidationError("Encrypted field value must be text")
    keyring, primary_key_id = _keyring()
    selected_key_id = key_id or primary_key_id
    key = keyring.get(selected_key_id)
    if key is None:
        raise ImproperlyConfigured("The requested data-encryption key ID is not configured")
    encrypted = SecretBox(key).encrypt(value.encode("utf-8"))
    encoded = base64.b64encode(bytes(encrypted)).decode("ascii")
    return f"{FIELD_PREFIX}{selected_key_id}:{encoded}"


def _decode_ciphertext(encoded):
    try:
        ciphertext = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError("Encrypted field authentication failed") from exc
    if base64.b64encode(ciphertext).decode("ascii") != encoded:
        raise ValidationError("Encrypted field authentication failed")
    return ciphertext


def decrypt_text(value):
    if not isinstance(value, str):
        raise ValidationError("Encrypted field contains invalid data")
    keyring, _primary_key_id = _keyring()
    if value.startswith(FIELD_PREFIX):
        envelope = value.removeprefix(FIELD_PREFIX)
        key_id, separator, encoded = envelope.partition(":")
        if not separator or not key_id or not encoded:
            raise ValidationError("Encrypted field contains an invalid versioned envelope")
    elif value.startswith(LEGACY_FIELD_PREFIX):
        key_id = getattr(settings, "DATA_ENCRYPTION_V1_KEY_ID", "")
        encoded = value.removeprefix(LEGACY_FIELD_PREFIX)
        if not key_id or not encoded:
            raise ValidationError("Encrypted field contains an invalid legacy envelope")
    else:
        raise ValidationError("Encrypted field contains unversioned data")
    key = keyring.get(key_id)
    if key is None:
        raise ValidationError("Encrypted field references an unavailable key")
    ciphertext = _decode_ciphertext(encoded)
    try:
        return SecretBox(key).decrypt(ciphertext).decode("utf-8")
    except (CryptoError, UnicodeDecodeError) as exc:
        raise ValidationError("Encrypted field authentication failed") from exc


def key_canary(key_id):
    return encrypt_text(KEY_CANARY_PLAINTEXT.decode("ascii"), key_id=key_id)


def verify_key_canary(key_id, fingerprint, envelope):
    keyring, _primary_key_id = _keyring()
    key = keyring.get(key_id)
    if key is None or not secrets.compare_digest(key_fingerprint(key), fingerprint):
        return False
    if not envelope.startswith(f"{FIELD_PREFIX}{key_id}:"):
        return False
    try:
        plaintext = decrypt_text(envelope)
    except ValidationError:
        return False
    return secrets.compare_digest(plaintext.encode("utf-8"), KEY_CANARY_PLAINTEXT)


class EncryptedTextField(models.TextField):
    """Randomized authenticated encryption for non-searchable secrets."""

    description = "Versioned keyring-encrypted text"

    def _decrypt(self, value):
        if value in (None, "") or not isinstance(value, str):
            return value
        return decrypt_text(value)

    def from_db_value(self, value, expression, connection):
        return self._decrypt(value)

    def to_python(self, value):
        if isinstance(value, str) and value.startswith((FIELD_PREFIX, LEGACY_FIELD_PREFIX)):
            return self._decrypt(value)
        return value

    def get_prep_value(self, value):
        value = super().get_prep_value(value)
        if value in (None, ""):
            return value
        return encrypt_text(value)
