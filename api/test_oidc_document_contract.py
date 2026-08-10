import base64
import concurrent.futures
import json
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

import requests
from django.test import SimpleTestCase
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import JWKRegistry, KeySet

from api import views_api
from api.oidc_documents import validate_oidc_jwks

ISSUER = "https://issuer.example.test"
ALLOWED_HOSTS = ("issuer.example.test",)


def _base64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _rsa_key(kid="rsa-1", *, bits=2048, **overrides):
    size = bits // 8
    modulus = b"\x80" + (b"\x00" * (size - 2)) + b"\x01"
    key = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "key_ops": ["verify"],
        "alg": "RS256",
        "n": _base64url(modulus),
        "e": "AQAB",
    }
    key.update(overrides)
    return key


class _Response:
    def __init__(self, body, *, status_code=200, headers=None):
        self.body = body
        self.status_code = status_code
        self.headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            **(headers or {}),
        }

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def iter_content(self, _chunk_size):
        yield self.body


def _discovery(**overrides):
    document = {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/jwks",
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    document.update(overrides)
    return document


def _metadata():
    return _discovery()


def _provider():
    return {
        "allowed_hosts": ALLOWED_HOSTS,
        "client_id": "client-id",
    }


def _generated_public_jwk(key_type, curve_or_size, algorithm):
    return JWKRegistry.generate_key(
        key_type,
        curve_or_size,
        parameters={"alg": algorithm, "use": "sig", "key_ops": ["verify"]},
        private=False,
        auto_kid=True,
    ).as_dict(private=False)


class OidcJsonStructureContractTests(SimpleTestCase):
    def fetch(self, body, *, headers=None):
        with patch("api.views_api.requests.get", return_value=_Response(body, headers=headers)):
            return views_api._fetch_oidc_json(f"{ISSUER}/document", ALLOWED_HOSTS)

    def test_duplicate_keys_are_rejected_instead_of_last_key_wins(self):
        body = b'{"issuer":"first","issuer":"second"}'
        with self.assertRaises(ValueError):
            self.fetch(body)

    def test_deep_and_high_node_documents_are_bounded_value_errors(self):
        documents = (
            (b"[" * 5000) + b"0" + (b"]" * 5000),
            json.dumps({"extension": [0] * 2049}, separators=(",", ":")).encode(),
        )
        for body in documents:
            with self.subTest(bytes=len(body)), self.assertRaises(ValueError):
                self.fetch(body)

    def test_invalid_encoding_numbers_and_envelope_type_are_rejected(self):
        documents = (
            b"\xef\xbb\xbf{}",
            b'\xff{"issuer":"invalid-utf8"}',
            b'{"number":NaN}',
            b'{"number":' + (b"9" * 129) + b"}",
            b"[]",
        )
        for body in documents:
            with self.subTest(body=body[:32]), self.assertRaises(ValueError):
                self.fetch(body)

    def test_external_http_json_framing_is_strict(self):
        cases = (
            ({"Content-Type": "text/html"}, b"{}"),
            ({"Content-Type": 'application/json; charset="utf-8'}, b"{}"),
            ({"Content-Type": "application/json; charset=utf-8; charset=utf-8"}, b"{}"),
            ({"Content-Length": "01"}, b"{}"),
            ({"Content-Length": "not-a-number"}, b"{}"),
            ({"Content-Length": None}, b"{" + (b" " * (1024 * 1024)) + b"}"),
        )
        for headers, body in cases:
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                self.fetch(body, headers=headers)

    def test_jwk_set_media_type_is_accepted(self):
        self.assertEqual(
            self.fetch(b'{"keys":[]}', headers={"Content-Type": "application/jwk-set+json"}),
            {"keys": []},
        )

    def test_discovery_rejects_non_allowlisted_signing_algorithms(self):
        views_api._oidc_metadata.cache_clear()
        document = _discovery(id_token_signing_alg_values_supported=["RS256", "none"])
        with (
            patch("api.views_api._request_oidc_json", return_value=(document, "", False)),
            self.assertRaises(ValueError),
        ):
            views_api._oidc_metadata(ISSUER, ALLOWED_HOSTS)


class OidcJwksSchemaContractTests(SimpleTestCase):
    def assert_rejected_before_key_import(self, jwks):
        with (
            patch("api.views_api._oidc_jwks", return_value=jwks),
            patch("api.views_api.KeySet.import_key_set", side_effect=AssertionError("unsafe key import")) as importer,
            self.assertRaises(ValueError),
        ):
            views_api._validate_oidc_id_token(
                {"id_token": "header.payload.signature"},
                _metadata(),
                _provider(),
                "nonce",
            )
        importer.assert_not_called()

    def test_key_count_duplicate_and_missing_kid_are_rejected(self):
        documents = (
            {"keys": [_rsa_key(f"rsa-{index}") for index in range(33)]},
            {"keys": [_rsa_key("duplicate"), _rsa_key("duplicate")]},
            {"keys": [_rsa_key(None)]},
        )
        for jwks in documents:
            with self.subTest(keys=len(jwks["keys"])):
                self.assert_rejected_before_key_import(jwks)

    def test_key_type_algorithm_use_and_operation_are_allowlisted(self):
        documents = (
            {"keys": [_rsa_key(kty="oct", k="c2VjcmV0")]},
            {"keys": [_rsa_key(alg="HS256")]},
            {"keys": [_rsa_key(use="enc")]},
            {"keys": [_rsa_key(key_ops=["sign"])]},
            {
                "keys": [
                    {
                        "kty": "EC",
                        "kid": "ec-1",
                        "use": "sig",
                        "key_ops": ["verify"],
                        "alg": "ES256",
                        "crv": "secp256k1",
                        "x": _base64url(b"x" * 32),
                        "y": _base64url(b"y" * 32),
                    }
                ]
            },
            {
                "keys": [
                    {
                        "kty": "EC",
                        "kid": "ec-off-curve",
                        "use": "sig",
                        "key_ops": ["verify"],
                        "alg": "ES256",
                        "crv": "P-256",
                        "x": _base64url(b"x" * 32),
                        "y": _base64url(b"y" * 32),
                    }
                ]
            },
        )
        for jwks in documents:
            with self.subTest(key=jwks["keys"][0]):
                self.assert_rejected_before_key_import(jwks)

    def test_valid_rsa_ec_and_ed25519_keys_are_sanitized_and_importable(self):
        keys = [
            _generated_public_jwk("RSA", 2048, "RS256"),
            _generated_public_jwk("EC", "P-256", "ES256"),
            _generated_public_jwk("OKP", "Ed25519", "EdDSA"),
        ]
        keys[0]["x5u"] = "https://issuer.example.test/certificate.pem"
        keys[0]["x5c"] = [base64.b64encode(b"bounded-test-certificate").decode("ascii")]
        validated = validate_oidc_jwks({"keys": keys})
        self.assertEqual(len(KeySet.import_key_set(validated).keys), 3)
        self.assertNotIn("x5u", validated["keys"][0])
        self.assertNotIn("x5c", validated["keys"][0])

    def test_valid_signed_id_token_uses_the_validated_public_jwk(self):
        signing_key = JWKRegistry.generate_key("RSA", 2048, auto_kid=True)
        public_jwk = signing_key.as_dict(private=False)
        now = int(time.time())
        encoded = views_api.jwt.encode(
            {"alg": "RS256", "kid": public_jwk["kid"]},
            {
                "iss": ISSUER,
                "sub": "subject",
                "aud": "client-id",
                "exp": now + 300,
                "iat": now,
                "nonce": "nonce",
            },
            signing_key,
        )
        with patch("api.views_api._oidc_jwks", return_value={"keys": [public_jwk]}):
            claims = views_api._validate_oidc_id_token(
                {"id_token": encoded},
                _metadata(),
                _provider(),
                "nonce",
            )
        self.assertEqual(claims["sub"], "subject")

    def test_id_token_must_bind_to_a_bounded_key_id(self):
        signing_key = JWKRegistry.generate_key("RSA", 2048, auto_kid=True)
        now = int(time.time())
        encoded = views_api.jwt.encode(
            {"alg": "RS256"},
            {
                "iss": ISSUER,
                "sub": "subject",
                "aud": "client-id",
                "exp": now + 300,
                "iat": now,
                "nonce": "nonce",
            },
            signing_key,
        )
        with self.assertRaises(ValueError):
            views_api._decode_oidc_id_token(encoded, {"keys": [signing_key.as_dict(private=False)]}, ("RS256",))

    def test_maximum_key_count_is_accepted(self):
        validated = validate_oidc_jwks({"keys": [_rsa_key(f"rsa-{index}") for index in range(32)]})
        self.assertEqual(len(validated["keys"]), 32)

    def test_weak_oversized_or_private_key_material_is_rejected(self):
        documents = (
            {"keys": [_rsa_key(bits=1024)]},
            {"keys": [_rsa_key(bits=16384)]},
            {"keys": [_rsa_key(d="AQAB")]},
            {
                "keys": [
                    {
                        "kty": "OKP",
                        "kid": "okp-1",
                        "use": "sig",
                        "key_ops": ["verify"],
                        "alg": "EdDSA",
                        "crv": "Ed25519",
                        "x": _base64url(b"short"),
                    }
                ]
            },
        )
        for jwks in documents:
            with self.subTest(key=jwks["keys"][0]):
                self.assert_rejected_before_key_import(jwks)


class OidcDocumentCacheContractTests(SimpleTestCase):
    def setUp(self):
        views_api._clear_oidc_document_cache()

    def tearDown(self):
        views_api._clear_oidc_document_cache()

    def test_fresh_discovery_is_cached_and_expiry_revalidates_with_etag(self):
        clock = [100.0]
        document = _discovery()
        responses = (
            (document, '"discovery-v1"', False),
            (None, '"discovery-v1"', True),
        )
        with (
            patch("api.views_api.time.monotonic", side_effect=lambda: clock[0]),
            patch("api.views_api._request_oidc_json", side_effect=responses) as request,
        ):
            first = views_api._oidc_metadata(ISSUER, ALLOWED_HOSTS)
            self.assertEqual(views_api._oidc_metadata(ISSUER, ALLOWED_HOSTS), first)
            self.assertEqual(request.call_count, 1)
            clock[0] += views_api.OIDC_DOCUMENT_CACHE_TTL_SECONDS + 1
            self.assertEqual(views_api._oidc_metadata(ISSUER, ALLOWED_HOSTS), first)

        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args.kwargs["etag"], '"discovery-v1"')

    def test_transport_failure_uses_only_bounded_stale_valid_document(self):
        clock = [100.0]
        with (
            patch("api.views_api.time.monotonic", side_effect=lambda: clock[0]),
            patch(
                "api.views_api._request_oidc_json",
                side_effect=[
                    (_discovery(), "", False),
                    requests.Timeout("provider timeout"),
                    requests.Timeout("provider timeout"),
                ],
            ) as request,
        ):
            first = views_api._oidc_metadata(ISSUER, ALLOWED_HOSTS)
            clock[0] += views_api.OIDC_DOCUMENT_CACHE_TTL_SECONDS + 1
            self.assertEqual(views_api._oidc_metadata(ISSUER, ALLOWED_HOSTS), first)
            clock[0] += views_api.OIDC_DOCUMENT_CACHE_STALE_SECONDS + 1
            with self.assertRaises(requests.Timeout):
                views_api._oidc_metadata(ISSUER, ALLOWED_HOSTS)
        self.assertEqual(request.call_count, 3)

    def test_concurrent_transport_failure_shares_stale_fallback(self):
        clock = [100.0]
        started = threading.Event()
        release = threading.Event()
        calls = [0]

        def request(*_args, **_kwargs):
            calls[0] += 1
            if calls[0] == 1:
                return _discovery(), "", False
            started.set()
            self.assertTrue(release.wait(5))
            raise requests.Timeout("provider timeout")

        with (
            patch("api.views_api.time.monotonic", side_effect=lambda: clock[0]),
            patch("api.views_api._request_oidc_json", side_effect=request) as fetch,
            concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor,
        ):
            expected = views_api._oidc_metadata(ISSUER, ALLOWED_HOSTS)
            clock[0] += views_api.OIDC_DOCUMENT_CACHE_TTL_SECONDS + 1
            first = executor.submit(views_api._oidc_metadata, ISSUER, ALLOWED_HOSTS)
            self.assertTrue(started.wait(5))
            second = executor.submit(views_api._oidc_metadata, ISSUER, ALLOWED_HOSTS)
            release.set()
            self.assertEqual(first.result(5), expected)
            self.assertEqual(second.result(5), expected)
        self.assertEqual(fetch.call_count, 2)

    def test_invalid_refresh_does_not_replace_last_valid_cache_entry(self):
        clock = [100.0]
        invalid = _discovery(id_token_signing_alg_values_supported=["none"])
        with (
            patch("api.views_api.time.monotonic", side_effect=lambda: clock[0]),
            patch(
                "api.views_api._request_oidc_json",
                side_effect=[(_discovery(), "", False), (invalid, "", False), (_discovery(), "", False)],
            ) as request,
        ):
            expected = views_api._oidc_metadata(ISSUER, ALLOWED_HOSTS)
            clock[0] += views_api.OIDC_DOCUMENT_CACHE_TTL_SECONDS + 1
            with self.assertRaises(ValueError):
                views_api._oidc_metadata(ISSUER, ALLOWED_HOSTS)
            self.assertEqual(views_api._oidc_metadata(ISSUER, ALLOWED_HOSTS), expected)
        self.assertEqual(request.call_count, 3)

    def test_concurrent_cache_miss_is_single_flight(self):
        started = threading.Event()
        release = threading.Event()

        def request(*_args, **_kwargs):
            started.set()
            self.assertTrue(release.wait(5))
            return _discovery(), "", False

        with (
            patch("api.views_api._request_oidc_json", side_effect=request) as fetch,
            concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor,
        ):
            first = executor.submit(views_api._oidc_metadata, ISSUER, ALLOWED_HOSTS)
            self.assertTrue(started.wait(5))
            second = executor.submit(views_api._oidc_metadata, ISSUER, ALLOWED_HOSTS)
            release.set()
            self.assertEqual(first.result(5), second.result(5))
        self.assertEqual(fetch.call_count, 1)

    def test_concurrent_invalid_document_shares_one_failed_flight(self):
        started = threading.Event()
        release = threading.Event()

        def request(*_args, **_kwargs):
            started.set()
            self.assertTrue(release.wait(5))
            return _discovery(id_token_signing_alg_values_supported=["none"]), "", False

        with (
            patch("api.views_api._request_oidc_json", side_effect=request) as fetch,
            concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor,
        ):
            first = executor.submit(views_api._oidc_metadata, ISSUER, ALLOWED_HOSTS)
            self.assertTrue(started.wait(5))
            second = executor.submit(views_api._oidc_metadata, ISSUER, ALLOWED_HOSTS)
            release.set()
            for future in (first, second):
                with self.assertRaises(ValueError):
                    future.result(5)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(len(views_api._oidc_document_cache), 0)

    def test_cache_entry_count_is_bounded(self):
        def request(url, _allowed_hosts, **_kwargs):
            issuer = url.removesuffix("/.well-known/openid-configuration")
            return (
                _discovery(
                    issuer=issuer,
                    authorization_endpoint=f"{issuer}/authorize",
                    token_endpoint=f"{issuer}/token",
                    jwks_uri=f"{issuer}/jwks",
                ),
                "",
                False,
            )

        with patch("api.views_api._request_oidc_json", side_effect=request):
            for index in range(views_api.OIDC_DOCUMENT_CACHE_MAX_ENTRIES + 1):
                views_api._oidc_metadata(f"{ISSUER}/tenant-{index}", ALLOWED_HOSTS)
        self.assertEqual(len(views_api._oidc_document_cache), views_api.OIDC_DOCUMENT_CACHE_MAX_ENTRIES)

    def test_jwks_fresh_cache_returns_defensive_copies(self):
        document = {"keys": [_rsa_key()]}
        metadata = _metadata()
        provider = _provider()
        with patch(
            "api.views_api._request_oidc_json",
            return_value=(document, '"jwks-v1"', False),
        ) as request:
            first = views_api._oidc_jwks(metadata, provider)
            first["keys"].clear()
            second = views_api._oidc_jwks(metadata, provider)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(len(second["keys"]), 1)

    def test_unknown_kid_forces_one_jwks_refresh(self):
        jwks = {"keys": [_rsa_key()]}
        now = int(time.time())
        decoded = SimpleNamespace(
            claims={
                "iss": ISSUER,
                "sub": "subject",
                "aud": "client-id",
                "exp": now + 300,
                "iat": now,
                "nonce": "nonce",
            }
        )
        with (
            patch("api.views_api._oidc_jwks", side_effect=[jwks, jwks]) as key_set,
            patch(
                "api.views_api._decode_oidc_id_token",
                side_effect=[InvalidKeyIdError("unknown kid"), decoded],
            ) as decode,
        ):
            claims = views_api._validate_oidc_id_token(
                {"id_token": "header.payload.signature"},
                _metadata(),
                _provider(),
                "nonce",
            )
        self.assertEqual(claims["sub"], "subject")
        self.assertEqual(decode.call_count, 2)
        self.assertEqual(key_set.call_count, 2)
        self.assertNotIn("force_refresh", key_set.call_args_list[0].kwargs)
        self.assertIs(key_set.call_args_list[1].kwargs["force_refresh"], True)
