import base64
import binascii
import math
import re
from urllib.parse import urlsplit

from api.request_utils import InvalidJsonPayload, JsonPayloadTooLarge, load_json_text

OIDC_DOCUMENT_MAX_BYTES = 1024 * 1024
OIDC_JSON_MAX_DEPTH = 8
OIDC_JSON_MAX_CONTAINER_ITEMS = 64
OIDC_JSON_MAX_TOTAL_NODES = 2048
OIDC_JSON_MAX_STRING_BYTES = 8192
OIDC_DISCOVERY_MAX_ALGORITHMS = 16
OIDC_JWKS_MAX_KEYS = 32
OIDC_JWK_MAX_X509_CERTIFICATES = 5
OIDC_SAFE_ID_TOKEN_ALGORITHMS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)

_PRIVATE_JWK_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_COMMON_JWK_FIELDS = frozenset(
    {
        "kty",
        "kid",
        "use",
        "key_ops",
        "alg",
        "x5u",
        "x5c",
        "x5t",
        "x5t#S256",
    }
)
_BASE64URL = re.compile(r"[A-Za-z0-9_-]+\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_EC_CURVES = {
    # (JWS algorithm, coordinate size, field prime, curve a, curve b)
    "P-256": (
        "ES256",
        32,
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    ),
    "P-384": (
        "ES384",
        48,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52970,
        0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    ),
    "P-521": (
        "ES512",
        66,
        (1 << 521) - 1,
        (1 << 521) - 4,
        0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,
    ),
}


class InvalidOidcDocument(ValueError):
    """Raised before an untrusted OIDC document reaches JOSE processing."""


def _utf8_size(value):
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise InvalidOidcDocument("OIDC JSON contains invalid Unicode") from error


def _validate_oidc_shape(document):
    total_nodes = 1
    stack = [(document, 1)]
    while stack:
        value, depth = stack.pop()
        if depth > OIDC_JSON_MAX_DEPTH:
            raise InvalidOidcDocument("OIDC JSON nesting is too deep")
        if isinstance(value, dict):
            if len(value) > OIDC_JSON_MAX_CONTAINER_ITEMS:
                raise InvalidOidcDocument("OIDC JSON object has too many members")
            total_nodes += len(value) * 2
            for key, item in value.items():
                if _utf8_size(key) > 256:
                    raise InvalidOidcDocument("OIDC JSON key is too long")
                stack.append((item, depth + 1))
        elif isinstance(value, list):
            if len(value) > OIDC_JSON_MAX_CONTAINER_ITEMS:
                raise InvalidOidcDocument("OIDC JSON array has too many items")
            total_nodes += len(value)
            stack.extend((item, depth + 1) for item in value)
        elif isinstance(value, str):
            if _utf8_size(value) > OIDC_JSON_MAX_STRING_BYTES:
                raise InvalidOidcDocument("OIDC JSON string is too long")
        elif isinstance(value, int) and not isinstance(value, bool):
            if not -(1 << 63) <= value <= (1 << 63) - 1:
                raise InvalidOidcDocument("OIDC JSON integer is outside the supported range")
        elif isinstance(value, float) and not math.isfinite(value):
            raise InvalidOidcDocument("OIDC JSON number is not finite")
        if total_nodes > OIDC_JSON_MAX_TOTAL_NODES:
            raise InvalidOidcDocument("OIDC JSON has too many nodes")


def parse_oidc_json(body):
    if not isinstance(body, bytes) or not body or len(body) > OIDC_DOCUMENT_MAX_BYTES:
        raise InvalidOidcDocument("OIDC document has an invalid byte length")
    if body.startswith(b"\xef\xbb\xbf"):
        raise InvalidOidcDocument("OIDC document must not contain a UTF-8 BOM")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InvalidOidcDocument("OIDC document is not valid UTF-8") from error
    try:
        document = load_json_text(text, max_bytes=OIDC_DOCUMENT_MAX_BYTES)
    except (InvalidJsonPayload, JsonPayloadTooLarge) as error:
        raise InvalidOidcDocument("OIDC document is not strict JSON") from error
    if not isinstance(document, dict):
        raise InvalidOidcDocument("OIDC document must be a JSON object")
    _validate_oidc_shape(document)
    return document


def _bounded_text(document, field, *, maximum=2048, required=True):
    if field not in document:
        if required:
            raise InvalidOidcDocument(f"OIDC document is missing {field}")
        return None
    value = document[field]
    if not isinstance(value, str) or not value or _utf8_size(value) > maximum:
        raise InvalidOidcDocument(f"OIDC document contains invalid {field}")
    return value


def validated_signing_algorithms(value):
    if value is None:
        return ("RS256",)
    if not isinstance(value, list) or not 1 <= len(value) <= OIDC_DISCOVERY_MAX_ALGORITHMS:
        raise InvalidOidcDocument("OIDC signing algorithm list is invalid")
    algorithms = []
    seen = set()
    for algorithm in value:
        if not isinstance(algorithm, str) or algorithm not in OIDC_SAFE_ID_TOKEN_ALGORITHMS or algorithm in seen:
            raise InvalidOidcDocument("OIDC signing algorithm list is invalid")
        seen.add(algorithm)
        algorithms.append(algorithm)
    return tuple(algorithms)


def validate_oidc_discovery(document):
    if not isinstance(document, dict):
        raise InvalidOidcDocument("OIDC discovery must be an object")
    result = {
        field: _bounded_text(document, field)
        for field in (
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
        )
    }
    if "userinfo_endpoint" in document:
        result["userinfo_endpoint"] = _bounded_text(document, "userinfo_endpoint")
    algorithms = validated_signing_algorithms(document.get("id_token_signing_alg_values_supported"))
    result["id_token_signing_alg_values_supported"] = list(algorithms)
    return result


def _decode_base64url(value, field, *, maximum_bytes, exact_bytes=None):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > ((maximum_bytes * 4 + 2) // 3)
        or not value.isascii()
        or _BASE64URL.fullmatch(value) is None
    ):
        raise InvalidOidcDocument(f"OIDC JWK contains invalid {field}")
    try:
        decoded = base64.b64decode(value + ("=" * (-len(value) % 4)), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise InvalidOidcDocument(f"OIDC JWK contains invalid {field}") from error
    if (
        not decoded
        or len(decoded) > maximum_bytes
        or (exact_bytes is not None and len(decoded) != exact_bytes)
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value
    ):
        raise InvalidOidcDocument(f"OIDC JWK contains invalid {field}")
    return decoded


def _validate_x509_metadata(key):
    x5u = key.get("x5u")
    if x5u is not None:
        if not isinstance(x5u, str) or len(x5u) > 2048:
            raise InvalidOidcDocument("OIDC JWK contains invalid x5u")
        parsed = urlsplit(x5u)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise InvalidOidcDocument("OIDC JWK contains invalid x5u")
    x5c = key.get("x5c")
    if x5c is not None:
        if not isinstance(x5c, list) or not 1 <= len(x5c) <= OIDC_JWK_MAX_X509_CERTIFICATES:
            raise InvalidOidcDocument("OIDC JWK contains invalid x5c")
        for certificate in x5c:
            if (
                not isinstance(certificate, str)
                or not certificate
                or len(certificate) > 8192
                or not certificate.isascii()
                or _BASE64.fullmatch(certificate) is None
            ):
                raise InvalidOidcDocument("OIDC JWK contains invalid x5c")
            try:
                decoded = base64.b64decode(certificate, validate=True)
            except (binascii.Error, ValueError) as error:
                raise InvalidOidcDocument("OIDC JWK contains invalid x5c") from error
            if not decoded or len(decoded) > 6144:
                raise InvalidOidcDocument("OIDC JWK contains invalid x5c")
    if "x5t" in key:
        _decode_base64url(key["x5t"], "x5t", maximum_bytes=20, exact_bytes=20)
    if "x5t#S256" in key:
        _decode_base64url(key["x5t#S256"], "x5t#S256", maximum_bytes=32, exact_bytes=32)


def _validated_common_jwk(key, seen_kids):
    if not isinstance(key, dict) or _PRIVATE_JWK_FIELDS & key.keys():
        raise InvalidOidcDocument("OIDC JWKS contains private or malformed key material")
    kid = key.get("kid")
    if (
        not isinstance(kid, str)
        or not 1 <= len(kid) <= 128
        or not kid.isascii()
        or any(ord(character) < 33 or ord(character) > 126 for character in kid)
        or kid in seen_kids
    ):
        raise InvalidOidcDocument("OIDC JWKS key IDs must be unique bounded ASCII")
    seen_kids.add(kid)
    use = key.get("use")
    if use is not None and use != "sig":
        raise InvalidOidcDocument("OIDC JWK is not a signature key")
    key_ops = key.get("key_ops")
    if key_ops is not None and key_ops != ["verify"]:
        raise InvalidOidcDocument("OIDC JWK operations must be verify-only")
    algorithm = key.get("alg")
    if algorithm is not None and algorithm not in OIDC_SAFE_ID_TOKEN_ALGORITHMS:
        raise InvalidOidcDocument("OIDC JWK algorithm is not supported")
    _validate_x509_metadata(key)
    result = {"kty": key.get("kty"), "kid": kid}
    if use is not None:
        result["use"] = use
    if key_ops is not None:
        result["key_ops"] = key_ops
    if algorithm is not None:
        result["alg"] = algorithm
    return result, algorithm


def _validated_rsa_jwk(key, common, algorithm):
    if set(key) - (_COMMON_JWK_FIELDS | {"n", "e"}):
        raise InvalidOidcDocument("OIDC RSA JWK contains unsupported fields")
    if algorithm is not None and not algorithm.startswith(("RS", "PS")):
        raise InvalidOidcDocument("OIDC RSA JWK algorithm does not match its key type")
    modulus = _decode_base64url(key.get("n"), "RSA modulus", maximum_bytes=1024)
    if modulus[0] == 0 or not 2048 <= int.from_bytes(modulus, "big").bit_length() <= 8192:
        raise InvalidOidcDocument("OIDC RSA modulus is outside the supported size")
    exponent_bytes = _decode_base64url(key.get("e"), "RSA exponent", maximum_bytes=8)
    if exponent_bytes[0] == 0:
        raise InvalidOidcDocument("OIDC RSA exponent is not canonical")
    exponent = int.from_bytes(exponent_bytes, "big")
    if not 3 <= exponent <= (1 << 63) - 1 or exponent % 2 == 0:
        raise InvalidOidcDocument("OIDC RSA exponent is invalid")
    return {**common, "n": key["n"], "e": key["e"]}


def _validated_ec_jwk(key, common, algorithm):
    if set(key) - (_COMMON_JWK_FIELDS | {"crv", "x", "y"}):
        raise InvalidOidcDocument("OIDC EC JWK contains unsupported fields")
    curve = key.get("crv")
    if curve not in _EC_CURVES:
        raise InvalidOidcDocument("OIDC EC JWK curve is not supported")
    expected_algorithm, coordinate_bytes, prime, curve_a, curve_b = _EC_CURVES[curve]
    if algorithm is not None and algorithm != expected_algorithm:
        raise InvalidOidcDocument("OIDC EC JWK algorithm does not match its curve")
    x_bytes = _decode_base64url(
        key.get("x"),
        "EC x-coordinate",
        maximum_bytes=coordinate_bytes,
        exact_bytes=coordinate_bytes,
    )
    y_bytes = _decode_base64url(
        key.get("y"),
        "EC y-coordinate",
        maximum_bytes=coordinate_bytes,
        exact_bytes=coordinate_bytes,
    )
    x = int.from_bytes(x_bytes, "big")
    y = int.from_bytes(y_bytes, "big")
    if x >= prime or y >= prime or (y * y - (x * x * x + curve_a * x + curve_b)) % prime:
        raise InvalidOidcDocument("OIDC EC coordinates are not on the selected curve")
    return {**common, "crv": curve, "x": key["x"], "y": key["y"]}


def _validated_okp_jwk(key, common, algorithm):
    if set(key) - (_COMMON_JWK_FIELDS | {"crv", "x"}):
        raise InvalidOidcDocument("OIDC OKP JWK contains unsupported fields")
    if key.get("crv") != "Ed25519" or algorithm not in (None, "EdDSA"):
        raise InvalidOidcDocument("OIDC OKP JWK must be an Ed25519 signature key")
    _decode_base64url(key.get("x"), "OKP public key", maximum_bytes=32, exact_bytes=32)
    return {**common, "crv": "Ed25519", "x": key["x"]}


def validate_oidc_jwks(document):
    if not isinstance(document, dict) or set(document) - {"keys"}:
        raise InvalidOidcDocument("OIDC JWKS must contain only its key set")
    keys = document.get("keys")
    if not isinstance(keys, list) or not 1 <= len(keys) <= OIDC_JWKS_MAX_KEYS:
        raise InvalidOidcDocument("OIDC JWKS key count is outside the supported range")
    result = []
    seen_kids = set()
    for key in keys:
        common, algorithm = _validated_common_jwk(key, seen_kids)
        key_type = key.get("kty")
        if key_type == "RSA":
            result.append(_validated_rsa_jwk(key, common, algorithm))
        elif key_type == "EC":
            result.append(_validated_ec_jwk(key, common, algorithm))
        elif key_type == "OKP":
            result.append(_validated_okp_jwk(key, common, algorithm))
        else:
            raise InvalidOidcDocument("OIDC JWK key type is not supported")
    return {"keys": result}
