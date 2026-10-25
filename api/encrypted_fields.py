import base64
import binascii
import hashlib
import hmac
import json
import secrets
import uuid
from collections.abc import Iterable, Mapping

from django.conf import settings
from django.core import checks
from django.core.exceptions import FieldDoesNotExist, ImproperlyConfigured, ObjectDoesNotExist, ValidationError
from django.core.serializers.base import SerializationError
from django.db import models
from django.db.models.query_utils import DeferredAttribute
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox

LEGACY_FIELD_PREFIX = "secretbox:v1:"
UNBOUND_FIELD_PREFIX = "secretbox:v2:"
FIELD_PREFIX = "secretbox:v3:"
KEY_CANARY_PLAINTEXT = b"camellia-data-encryption-canary-v1"
CONTEXT_SCHEMA = "camellia-encrypted-field-context-v1"
CONTEXT_SUBKEY_DOMAIN = b"camellia-encrypted-field-subkey-v1\x00"
_ENVELOPE_PREFIXES = (FIELD_PREFIX, UNBOUND_FIELD_PREFIX, LEGACY_FIELD_PREFIX)


class _PreparedEncryptedValue(str):
    """A value encrypted with the model instance's authenticated context."""


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


def _canonical_context_value(value):
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, uuid.UUID):
        return str(value)
    raise ValidationError("Encrypted field context contains an unsupported value")


def build_encryption_context(
    model_label: str,
    field_name: str,
    components: Iterable[tuple[str, object]],
) -> bytes:
    if not isinstance(model_label, str) or not model_label or not isinstance(field_name, str) or not field_name:
        raise ValidationError("Encrypted field context is incomplete")
    normalized_components = []
    observed_names = set()
    for name, value in components:
        if not isinstance(name, str) or not name or name in observed_names:
            raise ValidationError("Encrypted field context is invalid")
        observed_names.add(name)
        normalized_components.append([name, _canonical_context_value(value)])
    if not normalized_components:
        raise ValidationError("Encrypted field context is incomplete")
    return json.dumps(
        {
            "components": normalized_components,
            "field": field_name,
            "model": model_label,
            "schema": CONTEXT_SCHEMA,
        },
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _context_bytes(context):
    if not isinstance(context, bytes) or not context:
        raise ValidationError("Encrypted field authentication failed")
    return context


def _context_digest(context):
    return hashlib.sha256(_context_bytes(context)).hexdigest()


def _context_key(key, context):
    return hmac.new(key, CONTEXT_SUBKEY_DOMAIN + _context_bytes(context), hashlib.sha256).digest()


def encrypt_text(value, *, key_id=None, context=None):
    if not isinstance(value, str):
        raise ValidationError("Encrypted field value must be text")
    keyring, primary_key_id = _keyring()
    selected_key_id = key_id or primary_key_id
    key = keyring.get(selected_key_id)
    if key is None:
        raise ImproperlyConfigured("The requested data-encryption key ID is not configured")
    if context is None:
        prefix = f"{UNBOUND_FIELD_PREFIX}{selected_key_id}:"
        encryption_key = key
    else:
        digest = _context_digest(context)
        prefix = f"{FIELD_PREFIX}{selected_key_id}:{digest}:"
        encryption_key = _context_key(key, context)
    encrypted = SecretBox(encryption_key).encrypt(value.encode("utf-8"))
    encoded = base64.b64encode(bytes(encrypted)).decode("ascii")
    return f"{prefix}{encoded}"


def _decode_ciphertext(encoded):
    try:
        ciphertext = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError("Encrypted field authentication failed") from exc
    if base64.b64encode(ciphertext).decode("ascii") != encoded:
        raise ValidationError("Encrypted field authentication failed")
    return ciphertext


def decrypt_text(value, *, context=None):
    if not isinstance(value, str):
        raise ValidationError("Encrypted field contains invalid data")
    keyring, _primary_key_id = _keyring()
    if value.startswith(FIELD_PREFIX):
        envelope = value.removeprefix(FIELD_PREFIX)
        key_id, separator, remainder = envelope.partition(":")
        context_digest, digest_separator, encoded = remainder.partition(":")
        if (
            not separator
            or not digest_separator
            or not key_id
            or len(context_digest) != hashlib.sha256().digest_size * 2
            or not encoded
        ):
            raise ValidationError("Encrypted field contains an invalid context envelope")
        expected_context = _context_bytes(context)
        if not secrets.compare_digest(context_digest, _context_digest(expected_context)):
            raise ValidationError("Encrypted field authentication failed")
        master_key = keyring.get(key_id)
        if master_key is None:
            raise ValidationError("Encrypted field references an unavailable key")
        key = _context_key(master_key, expected_context)
    elif value.startswith(UNBOUND_FIELD_PREFIX):
        envelope = value.removeprefix(UNBOUND_FIELD_PREFIX)
        key_id, separator, encoded = envelope.partition(":")
        if not separator or not key_id or not encoded:
            raise ValidationError("Encrypted field contains an invalid versioned envelope")
        key = keyring.get(key_id)
        if key is None:
            raise ValidationError("Encrypted field references an unavailable key")
    elif value.startswith(LEGACY_FIELD_PREFIX):
        key_id = getattr(settings, "DATA_ENCRYPTION_V1_KEY_ID", "")
        encoded = value.removeprefix(LEGACY_FIELD_PREFIX)
        if not key_id or not encoded:
            raise ValidationError("Encrypted field contains an invalid legacy envelope")
        key = keyring.get(key_id)
        if key is None:
            raise ValidationError("Encrypted field references an unavailable key")
    else:
        raise ValidationError("Encrypted field contains unversioned data")
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
    if not envelope.startswith(f"{UNBOUND_FIELD_PREFIX}{key_id}:"):
        return False
    try:
        plaintext = decrypt_text(envelope)
    except ValidationError:
        return False
    return secrets.compare_digest(plaintext.encode("utf-8"), KEY_CANARY_PLAINTEXT)


class EncryptedFieldDescriptor(DeferredAttribute):
    def __set__(self, instance, value):
        # DeferredAttribute is normally a non-data descriptor, so a value in
        # Model.__dict__ bypasses __get__.  Encrypted fields must always pass
        # through the instance-aware authentication boundary on reads.
        instance.__dict__[self.field.attname] = value

    def __get__(self, instance, cls=None):
        value = super().__get__(instance, cls)
        if instance is None or value in (None, "") or not isinstance(value, str):
            return value
        if value.startswith(_ENVELOPE_PREFIXES):
            value = self.field.decrypt_for_instance(instance, value)
            instance.__dict__[self.field.attname] = value
        return value


class EncryptedTextField(models.TextField):
    """Randomized authenticated encryption for non-searchable secrets."""

    description = "Versioned keyring and context-encrypted text"
    descriptor_class = EncryptedFieldDescriptor

    def __init__(self, *args, context_fields=(), **kwargs):
        self.context_fields = tuple(context_fields)
        super().__init__(*args, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        if self.context_fields:
            kwargs["context_fields"] = self.context_fields
        return name, path, args, kwargs

    def check(self, **kwargs):
        errors = super().check(**kwargs)
        if len(set(self.context_fields)) != len(self.context_fields) or any(
            not isinstance(name, str) or not name for name in self.context_fields
        ):
            errors.append(
                checks.Error(
                    "EncryptedTextField context_fields must contain unique non-empty field names.",
                    obj=self,
                    id="api.E001",
                )
            )
            return errors
        if self.model is not None:
            for field_name in self.context_fields:
                try:
                    context_field = self.model._meta.get_field(field_name)
                except FieldDoesNotExist:
                    try:
                        context_field = self.model._meta.get_field(field_name.removesuffix("_id"))
                    except FieldDoesNotExist:
                        errors.append(
                            checks.Error(
                                f"EncryptedTextField context field {field_name!r} does not exist.",
                                obj=self,
                                id="api.E002",
                            )
                        )
                        continue
                if context_field is self:
                    errors.append(
                        checks.Error(
                            "EncryptedTextField cannot include itself in context_fields.",
                            obj=self,
                            id="api.E003",
                        )
                    )
        return errors

    def context_for_instance(self, instance):
        if not self.context_fields:
            return None
        components = []
        for field_name in self.context_fields:
            try:
                value = getattr(instance, field_name)
            except (AttributeError, ObjectDoesNotExist) as exc:
                raise ValidationError("Encrypted field context is incomplete") from exc
            components.append((field_name, value))
        return build_encryption_context(self.model._meta.label_lower, self.name, components)

    def decrypt_for_instance(self, instance, value):
        return decrypt_text(value, context=self.context_for_instance(instance))

    def from_db_value(self, value, expression, connection):
        if value in (None, ""):
            return value
        if not isinstance(value, str) or not value.startswith(_ENVELOPE_PREFIXES):
            raise ValidationError("Encrypted field contains unversioned data")
        return value

    def to_python(self, value):
        if isinstance(value, str) and value.startswith(_ENVELOPE_PREFIXES):
            if self.context_fields:
                return value
            return decrypt_text(value)
        return value

    def value_to_string(self, obj):
        # Django's logical serializers read the descriptor value, which is
        # necessarily plaintext after instance-aware authentication. There is
        # no safe generic fixture representation for a context-bound envelope:
        # plaintext leaks credentials, while raw ciphertext would either be
        # double-encrypted by loaddata or detached from its row authority.
        raise SerializationError(
            "EncryptedTextField cannot be written to a logical fixture; use the authenticated physical backup set"
        )

    def pre_save(self, model_instance, add):
        value = getattr(model_instance, self.attname)
        if value in (None, ""):
            return value
        context = self.context_for_instance(model_instance)
        if isinstance(value, str) and value.startswith(_ENVELOPE_PREFIXES):
            decrypt_text(value, context=context)
            return _PreparedEncryptedValue(value)
        return _PreparedEncryptedValue(encrypt_text(value, context=context))

    def get_prep_value(self, value):
        if isinstance(value, _PreparedEncryptedValue):
            return str(value)
        value = super().get_prep_value(value)
        if value in (None, ""):
            return value
        if self.context_fields:
            raise ValidationError("Context-bound encrypted fields must be saved through a model instance")
        if isinstance(value, str) and value.startswith(_ENVELOPE_PREFIXES):
            decrypt_text(value)
            return value
        return encrypt_text(value)
