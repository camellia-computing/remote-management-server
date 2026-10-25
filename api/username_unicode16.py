"""Frozen username identity v1 primitives, independent of Python's Unicode tables.

This module is a migration contract. Keep it and its data after later identity
versions are introduced; published migrations must never acquire new semantics.
Unicode data and its full license are shipped in api/data/unicode16/.
"""

import hashlib
import unicodedata as _stdlib_data
from pathlib import Path
from types import MappingProxyType

try:
    import unicodedata2 as _backport_data
except ImportError:
    _backport_data = None

UNICODE_VERSION = "16.0.0"
ALGORITHM = "unicode-16.0.0-nfkc-casefold-nfkc-strip-v1"
MAX_LENGTH = 50
MAX_INPUT_LENGTH = 200
MAX_CANONICAL_BYTES = 1024

# Python 3.14's identity-v1 strip set: Unicode White_Space plus the four
# information separators U+001C..U+001F. Do not delegate this to str.isspace().
STRIP_CHARACTERS = (
    "\u0009\u000a\u000b\u000c\u000d\u001c\u001d\u001e\u001f\u0020"
    "\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006"
    "\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
)
CASEFOLD_SOURCE_URL = "https://www.unicode.org/Public/16.0.0/ucd/CaseFolding.txt"
CASEFOLD_SOURCE_SHA256 = "6f1f9c588eb4a5c718d9e8f93b782685e5c7fec872cf05e8e6878053599e09bb"
_MAX_DATA_BYTES = 128 * 1024
_CASEFOLD_SOURCE = Path(__file__).parent / "data" / "unicode16" / "CaseFolding.txt"
_DATA = _stdlib_data if _stdlib_data.unidata_version == UNICODE_VERSION else _backport_data or _stdlib_data


class Unicode16IdentityError(RuntimeError):
    pass


def require_unicode_version():
    if _DATA.unidata_version != UNICODE_VERSION:
        raise Unicode16IdentityError(
            f"username canonicalization requires Unicode data {UNICODE_VERSION}, found {_DATA.unidata_version}"
        )


def _load_casefold_table():
    try:
        with _CASEFOLD_SOURCE.open("rb") as source:
            raw = source.read(_MAX_DATA_BYTES + 1)
    except OSError:
        raise Unicode16IdentityError("username casefold data is unavailable") from None
    if len(raw) > _MAX_DATA_BYTES or hashlib.sha256(raw).hexdigest() != CASEFOLD_SOURCE_SHA256:
        raise Unicode16IdentityError("username casefold data integrity mismatch")
    table = {}
    try:
        for line in raw.decode("utf-8").splitlines():
            record = line.split("#", 1)[0].strip()
            if not record:
                continue
            code, status, mapping, trailing = (field.strip() for field in record.split(";"))
            if trailing or status not in {"C", "F", "S", "T"}:
                raise ValueError
            if status not in {"C", "F"}:
                continue  # Default full casefold; never simple-only or Turkic mappings.
            scalar = int(code, 16)
            if scalar in table:
                raise ValueError
            table[scalar] = "".join(chr(int(value, 16)) for value in mapping.split())
        if len(table) != 1557:
            raise ValueError
    except (UnicodeError, ValueError):
        raise Unicode16IdentityError("username casefold data is invalid") from None
    return MappingProxyType(table)


_CASEFOLD_TABLE = _load_casefold_table()


def full_casefold(value: str) -> str:
    return value.translate(_CASEFOLD_TABLE)


def valid_character(value: str) -> bool:
    require_unicode_version()
    if not isinstance(value, str) or len(value) != 1:
        return False
    # The frozen equivalent of UnicodeUsernameValidator's [\w.@+-]. Python's
    # \w otherwise changes when the interpreter learns new Unicode letters.
    return value in "_@.+-" or _DATA.category(value)[0] in {"L", "N"}


def normalize_username(value):
    require_unicode_version()
    if not isinstance(value, str) or len(value) > MAX_INPUT_LENGTH:
        raise ValueError("username is not a bounded string")
    normalized = _DATA.normalize("NFKC", value.strip(STRIP_CHARACTERS))
    if not normalized or len(normalized) > MAX_LENGTH:
        raise ValueError("username has an invalid normalized length")
    if not all(valid_character(character) for character in normalized):
        raise ValueError("username contains an invalid character")
    return normalized


def canonical_username(value):
    normalized = normalize_username(value)
    canonical = _DATA.normalize("NFKC", full_casefold(normalized))
    if not canonical:
        raise ValueError("username has an empty canonical form")
    return canonical


def canonical_username_key(value):
    key = canonical_username(value).encode("utf-8")
    if len(key) > MAX_CANONICAL_BYTES:
        raise ValueError("username canonical form is too large")
    return key


def username_candidate(value):
    """Project a bounded optional IdP label; it never selects an existing user."""
    require_unicode_version()
    if not isinstance(value, str) or len(value) > MAX_INPUT_LENGTH:
        return ""
    value = _DATA.normalize("NFKC", value.strip(STRIP_CHARACTERS))
    result = []
    replacing = False
    for character in value:
        if valid_character(character):
            result.append(character)
            replacing = False
        elif not replacing:
            result.append("-")
            replacing = True
    return "".join(result).strip("-")[:MAX_LENGTH]
