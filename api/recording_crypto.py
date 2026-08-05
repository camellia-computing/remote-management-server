import base64
import binascii
import hashlib
import os
import re
import secrets
import struct
import uuid

from nacl.bindings import crypto_secretbox, crypto_secretbox_open
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox

FORMAT_VERSION = 1
DATA_KEY_BYTES = SecretBox.KEY_SIZE

HEADER_MAGIC = b"CMLREC01"
RECORD_MAGIC = b"CMLCHK01"
HEADER_AUTH_CONTEXT = b"camellia-recording-header-v1\x00"
RECORD_AUTH_CONTEXT = b"camellia-recording-chunk-v1\x00"

_HEADER_PUBLIC = struct.Struct(">8sB16s")
_RECORD_FRAME = struct.Struct(">8sQ24s")
_RECORD_METADATA = struct.Struct(">16sQQQ32s")
_HEADER_PLAINTEXT_BYTES = len(HEADER_AUTH_CONTEXT) + _HEADER_PUBLIC.size
_HEADER_CIPHERTEXT_BYTES = _HEADER_PLAINTEXT_BYTES + SecretBox.MACBYTES
HEADER_SIZE = _HEADER_PUBLIC.size + SecretBox.NONCE_SIZE + _HEADER_CIPHERTEXT_BYTES
_RECORD_FIXED_CIPHERTEXT_BYTES = len(RECORD_AUTH_CONTEXT) + _RECORD_METADATA.size + SecretBox.MACBYTES
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_UINT64 = (1 << 64) - 1


class RecordingCryptoError(OSError):
    """Base class for fail-closed recording ciphertext errors."""


class RecordingFormatError(RecordingCryptoError):
    """The recording envelope is malformed or inconsistent."""


class RecordingAuthenticationError(RecordingCryptoError):
    """The recording envelope failed authenticated decryption."""


def generate_data_key():
    return secrets.token_bytes(DATA_KEY_BYTES)


def encode_data_key(data_key):
    _validate_data_key(data_key)
    return base64.b64encode(data_key).decode("ascii")


def decode_data_key(encoded):
    if not isinstance(encoded, str):
        raise RecordingAuthenticationError("Recording data key is unavailable")
    try:
        data_key = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RecordingAuthenticationError("Recording data key is unavailable") from exc
    if len(data_key) != DATA_KEY_BYTES or base64.b64encode(data_key).decode("ascii") != encoded:
        raise RecordingAuthenticationError("Recording data key is unavailable")
    return data_key


def build_header(upload_id, data_key):
    upload_id = _validate_upload_id(upload_id)
    _validate_data_key(data_key)
    public_header = _HEADER_PUBLIC.pack(HEADER_MAGIC, FORMAT_VERSION, upload_id.bytes)
    nonce = _nonce_for_revision(upload_id, 0)
    plaintext = HEADER_AUTH_CONTEXT + public_header
    ciphertext = crypto_secretbox(plaintext, nonce, data_key)
    if len(ciphertext) != _HEADER_CIPHERTEXT_BYTES:
        raise RecordingCryptoError("Recording encryption failed")
    return public_header + nonce + ciphertext


def chunk_record_size(plaintext_length):
    _validate_uint64(plaintext_length)
    if plaintext_length <= 0:
        raise ValueError("Recording chunks must not be empty")
    return _RECORD_FRAME.size + _RECORD_FIXED_CIPHERTEXT_BYTES + plaintext_length


def encrypt_chunk_record(*, upload_id, data_key, revision, offset, digest, data):
    upload_id = _validate_upload_id(upload_id)
    _validate_data_key(data_key)
    _validate_uint64(revision)
    _validate_uint64(offset)
    if revision <= 0:
        raise ValueError("Recording chunk revisions must be positive")
    if not isinstance(data, bytes) or not data:
        raise ValueError("Recording chunks must contain bytes")
    _validate_uint64(len(data))
    digest_bytes = _decode_digest(digest)
    if not secrets.compare_digest(hashlib.sha256(data).digest(), digest_bytes):
        raise ValueError("Recording chunk digest does not match its payload")
    metadata = _RECORD_METADATA.pack(
        upload_id.bytes,
        revision,
        offset,
        len(data),
        digest_bytes,
    )
    plaintext = RECORD_AUTH_CONTEXT + metadata + data
    nonce = _nonce_for_revision(upload_id, revision)
    ciphertext = crypto_secretbox(plaintext, nonce, data_key)
    expected_length = _RECORD_FIXED_CIPHERTEXT_BYTES + len(data)
    if len(ciphertext) != expected_length:
        raise RecordingCryptoError("Recording encryption failed")
    return _RECORD_FRAME.pack(RECORD_MAGIC, len(ciphertext), nonce), ciphertext


def validate_header_fd(fd, *, upload_id, data_key):
    """Authenticate the fixed header and leave the descriptor after it."""

    upload_id = _validate_upload_id(upload_id)
    _validate_data_key(data_key)
    os.lseek(fd, 0, os.SEEK_SET)
    public_header = _read_exact(fd, _HEADER_PUBLIC.size)
    try:
        magic, version, stored_upload_id = _HEADER_PUBLIC.unpack(public_header)
    except struct.error as exc:
        raise RecordingFormatError("Recording ciphertext format is invalid") from exc
    if magic != HEADER_MAGIC or version != FORMAT_VERSION or stored_upload_id != upload_id.bytes:
        raise RecordingFormatError("Recording ciphertext format is invalid")
    nonce = _read_exact(fd, SecretBox.NONCE_SIZE)
    if nonce != _nonce_for_revision(upload_id, 0):
        raise RecordingFormatError("Recording ciphertext format is invalid")
    ciphertext = _read_exact(fd, _HEADER_CIPHERTEXT_BYTES)
    try:
        plaintext = crypto_secretbox_open(ciphertext, nonce, data_key)
    except CryptoError as exc:
        raise RecordingAuthenticationError("Recording ciphertext authentication failed") from exc
    expected = HEADER_AUTH_CONTEXT + public_header
    if not secrets.compare_digest(plaintext, expected):
        raise RecordingAuthenticationError("Recording ciphertext authentication failed")
    return nonce


def verify_recording_fd(
    fd,
    *,
    upload_id,
    data_key,
    receipts,
    expected_revision,
    expected_storage_offset,
    max_chunk_bytes,
):
    """Authenticate a recording and return its plaintext size and SHA-256.

    Plaintext is held only one bounded chunk at a time and is never written to
    another file. The database receipts are the expected sequence authority.
    """

    upload_id = _validate_upload_id(upload_id)
    _validate_data_key(data_key)
    _validate_uint64(expected_revision)
    _validate_uint64(expected_storage_offset)
    if not isinstance(max_chunk_bytes, int) or max_chunk_bytes <= 0:
        raise ValueError("The recording chunk bound is invalid")
    if expected_storage_offset < HEADER_SIZE:
        raise RecordingFormatError("Recording ciphertext format is invalid")
    if os.fstat(fd).st_size != expected_storage_offset:
        raise RecordingFormatError("Recording ciphertext format is invalid")

    validate_header_fd(fd, upload_id=upload_id, data_key=data_key)
    full_digest = hashlib.sha256()
    plaintext_size = 0
    next_revision = 1

    for receipt in receipts:
        if next_revision > expected_revision:
            raise RecordingFormatError("Recording ciphertext format is invalid")
        revision = receipt.revision
        offset = receipt.offset
        length = receipt.length
        digest = receipt.digest
        if (
            revision != next_revision
            or offset != plaintext_size
            or not isinstance(length, int)
            or length <= 0
            or length > max_chunk_bytes
        ):
            raise RecordingFormatError("Recording ciphertext format is invalid")
        digest_bytes = _decode_digest(digest, error_type=RecordingFormatError)
        frame = _read_exact(fd, _RECORD_FRAME.size)
        try:
            magic, ciphertext_length, nonce = _RECORD_FRAME.unpack(frame)
        except struct.error as exc:
            raise RecordingFormatError("Recording ciphertext format is invalid") from exc
        expected_ciphertext_length = _RECORD_FIXED_CIPHERTEXT_BYTES + length
        if (
            magic != RECORD_MAGIC
            or ciphertext_length != expected_ciphertext_length
            or nonce != _nonce_for_revision(upload_id, revision)
        ):
            raise RecordingFormatError("Recording ciphertext format is invalid")
        ciphertext = _read_exact(fd, ciphertext_length)
        try:
            plaintext = crypto_secretbox_open(ciphertext, nonce, data_key)
        except CryptoError as exc:
            raise RecordingAuthenticationError("Recording ciphertext authentication failed") from exc
        expected_metadata = RECORD_AUTH_CONTEXT + _RECORD_METADATA.pack(
            upload_id.bytes,
            revision,
            offset,
            length,
            digest_bytes,
        )
        if len(plaintext) != len(expected_metadata) + length or not secrets.compare_digest(
            plaintext[: len(expected_metadata)],
            expected_metadata,
        ):
            raise RecordingAuthenticationError("Recording ciphertext authentication failed")
        payload = memoryview(plaintext)[len(expected_metadata) :]
        if not secrets.compare_digest(hashlib.sha256(payload).digest(), digest_bytes):
            raise RecordingAuthenticationError("Recording ciphertext authentication failed")
        full_digest.update(payload)
        plaintext_size += length
        next_revision += 1

    if next_revision - 1 != expected_revision:
        raise RecordingFormatError("Recording ciphertext format is invalid")
    if os.lseek(fd, 0, os.SEEK_CUR) != expected_storage_offset or os.read(fd, 1):
        raise RecordingFormatError("Recording ciphertext format is invalid")
    return plaintext_size, full_digest.hexdigest()


def _read_exact(fd, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = os.read(fd, remaining)
        if not chunk:
            raise RecordingFormatError("Recording ciphertext format is invalid")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _validate_upload_id(upload_id):
    if not isinstance(upload_id, uuid.UUID) or upload_id.version != 4:
        raise ValueError("Recording upload identity must be a UUIDv4")
    return upload_id


def _validate_data_key(data_key):
    if not isinstance(data_key, bytes) or len(data_key) != DATA_KEY_BYTES:
        raise ValueError("Recording data keys must contain exactly 32 bytes")


def _validate_uint64(value):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > _MAX_UINT64:
        raise ValueError("Recording integer is outside the supported range")


def _nonce_for_revision(upload_id, revision):
    _validate_uint64(revision)
    nonce = upload_id.bytes + revision.to_bytes(8, "big")
    if len(nonce) != SecretBox.NONCE_SIZE:
        raise RecordingCryptoError("Recording nonce derivation failed")
    return nonce


def _decode_digest(digest, *, error_type=ValueError):
    if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
        raise error_type("Recording digest is invalid")
    return bytes.fromhex(digest)
