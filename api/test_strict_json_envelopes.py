import base64
import json
import uuid
from unittest.mock import patch
from urllib.parse import urlencode

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, RequestFactory, SimpleTestCase, TestCase, override_settings

from api.models import RemoteDevice, RemotePeer, ShareLink, StrategyProfile, UserProfile
from api.request_utils import (
    InvalidJsonPayload,
    UnsupportedJsonMediaType,
    load_json_body,
    load_json_text,
)
from api.views_api import _issue_access_token
from api.views_front import _ensure_personal_profile

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}


@override_settings(STORAGES=TEST_STORAGES)
class StrictJsonEnvelopeHttpTests(TestCase):
    def setUp(self):
        self.admin = UserProfile.objects.create_superuser(
            "json-admin",
            "json-admin-password",  # noqa: S106 - isolated test credential
        )
        self.device = RemoteDevice.objects.create(
            rid="741000001",
            uuid=base64.b64encode(b"json-envelope-admin-device").decode("ascii"),
            owner=self.admin,
            is_active=True,
            cpu="-",
            hostname="json-envelope-device",
            memory="-",
            os="Linux",
            username=self.admin.username,
            version="test",
        )
        _token, self.bearer = _issue_access_token(self.admin, self.device)
        self.strategy = StrategyProfile.objects.create(
            name="json-envelope-strategy",
            config_options={},
            enabled=False,
        )
        self.client = Client(raise_request_exception=False)

    @property
    def auth(self):
        return {"HTTP_AUTHORIZATION": f"Bearer {self.bearer}"}

    @property
    def strategy_status_path(self):
        return f"/api/strategies/{self.strategy.guid}/status"

    def put_strategy(self, body, content_type="application/json", **extra):
        return self.client.generic(
            "PUT",
            self.strategy_status_path,
            data=body,
            content_type=content_type,
            **self.auth,
            **extra,
        )

    def assert_json_error(self, response, status):
        self.assertEqual(response.status_code, status, response.content[:1000])
        self.assertEqual(response.headers["Content-Type"], "application/json")
        self.assertIn("error", json.loads(response.content))
        self.assertNotIn(b"Traceback", response.content)
        self.assertLessEqual(len(response.content), 256)

    def assert_strategy_unchanged(self):
        self.strategy.refresh_from_db()
        self.assertIs(self.strategy.enabled, False)

    def test_duplicate_key_is_rejected_before_strategy_mutation(self):
        response = self.put_strategy(b'{"enabled":false,"enabled":true}')

        self.assert_json_error(response, 400)
        self.assert_strategy_unchanged()

    def test_unicode_equivalent_duplicate_keys_are_rejected(self):
        response = self.client.post(
            "/api/login",
            data='{"\u00e9":1,"e\u0301":2}',
            content_type="application/json",
        )

        self.assert_json_error(response, 400)

    def test_text_plain_is_rejected_before_strategy_mutation(self):
        response = self.put_strategy(b'{"enabled":true}', content_type="text/plain")

        self.assert_json_error(response, 415)
        self.assert_strategy_unchanged()

    def test_missing_media_type_is_rejected(self):
        response = self.put_strategy(b'{"enabled":true}', content_type="")

        self.assert_json_error(response, 415)
        self.assert_strategy_unchanged()

    def test_unknown_json_media_type_parameter_is_rejected(self):
        response = self.put_strategy(
            b'{"enabled":true}',
            content_type="application/json; charset=utf-8; profile=legacy",
        )

        self.assert_json_error(response, 415)
        self.assert_strategy_unchanged()

    def test_json_media_type_is_case_insensitive_and_utf8_charset_is_allowed(self):
        response = self.put_strategy(
            b'{"enabled":true}',
            content_type="Application/JSON; Charset=UTF-8",
        )

        self.assertEqual(response.status_code, 200, response.content[:1000])
        self.strategy.refresh_from_db()
        self.assertIs(self.strategy.enabled, True)

    def test_non_utf8_json_charset_is_rejected(self):
        response = self.put_strategy(
            b'{"enabled":true}',
            content_type="application/json; charset=iso-8859-1",
        )

        self.assert_json_error(response, 415)
        self.assert_strategy_unchanged()

    def test_content_encoding_is_rejected_before_strategy_mutation(self):
        response = self.put_strategy(
            b'{"enabled":true}',
            HTTP_CONTENT_ENCODING="gzip",
        )

        self.assert_json_error(response, 415)
        self.assert_strategy_unchanged()

    def test_transfer_encoding_is_rejected_before_strategy_mutation(self):
        response = self.put_strategy(
            b'{"enabled":true}',
            HTTP_TRANSFER_ENCODING="chunked",
        )

        self.assert_json_error(response, 400)
        self.assert_strategy_unchanged()

    def test_wrong_content_length_is_rejected_before_strategy_mutation(self):
        body = b'{"enabled":true}'
        response = self.put_strategy(
            body,
            CONTENT_LENGTH=str(len(body) + 1),
        )

        self.assert_json_error(response, 400)
        self.assert_strategy_unchanged()

    def test_empty_bom_invalid_utf8_malformed_and_trailing_payloads_are_json_errors(self):
        payloads = (
            b"",
            b'\xef\xbb\xbf{"enabled":true}',
            b'{"enabled":"\xff"}',
            b'{"enabled":',
            b'{"enabled":true} trailing',
        )
        for body in payloads:
            with self.subTest(body=body[:40]):
                extra = {"CONTENT_TYPE": "application/json", "CONTENT_LENGTH": "0"} if not body else {}
                response = self.put_strategy(body, **extra)
                self.assert_json_error(response, 400)
                self.assert_strategy_unchanged()

    def test_non_finite_numbers_are_rejected_as_json_syntax(self):
        for value in ("NaN", "Infinity", "-Infinity", "1e9999"):
            with self.subTest(value=value):
                response = self.put_strategy(f'{{"enabled":{value}}}'.encode())
                self.assert_json_error(response, 400)
                self.assert_strategy_unchanged()

    def test_non_object_payloads_are_rejected_by_object_route(self):
        for value in ("null", "true", "false", "0", '"text"', "[]"):
            with self.subTest(value=value):
                response = self.client.post(
                    "/api/login",
                    data=value,
                    content_type="application/json",
                )
                self.assert_json_error(response, 400)

    def test_large_integer_and_excessive_depth_never_escape_as_html_500(self):
        payloads = (
            b'{"username":' + (b"9" * 5000) + b"}",
            (b"[" * 2000) + b"{}" + (b"]" * 2000),
        )
        for body in payloads:
            with self.subTest(size=len(body)):
                response = self.client.post(
                    "/api/login",
                    data=body,
                    content_type="application/json",
                )
                self.assert_json_error(response, 400)

    @override_settings(JSON_AUTH_MAX_BODY_BYTES=128)
    def test_route_body_budget_returns_bounded_413(self):
        response = self.client.post(
            "/api/login",
            data=json.dumps({"username": "x" * 256}),
            content_type="application/json",
        )

        self.assert_json_error(response, 413)

    @override_settings(JSON_AUTH_MAX_BODY_BYTES=1024, DATA_UPLOAD_MAX_MEMORY_SIZE=128)
    def test_django_materialization_cap_is_normalized_to_json_413(self):
        response = self.client.post(
            "/api/login",
            data=json.dumps({"username": "x" * 256}),
            content_type="application/json",
        )

        self.assert_json_error(response, 413)

    @override_settings(JSON_CONTROL_MAX_BODY_BYTES=4096, JSON_ADDRESS_BOOK_BULK_MAX_BODY_BYTES=2 * 1024 * 1024)
    def test_address_book_bulk_route_does_not_inherit_control_budget(self):
        profile = _ensure_personal_profile(self.admin)
        values = ["x" * 1000] * 1000

        response = self.client.delete(
            f"/api/ab/peer/{profile.guid}",
            data=json.dumps(values),
            content_type="application/json",
            **self.auth,
        )

        self.assertEqual(response.status_code, 200, response.content[:1000])

    def test_alarm_embedded_json_uses_the_same_duplicate_and_depth_rules(self):
        raw_values = (
            '{"message":"first","message":"second"}',
            ("[" * 64) + "{}" + ("]" * 64),
        )
        for raw_info in raw_values:
            payload = {
                "id": self.device.rid,
                "uuid": self.device.uuid,
                "version": 3,
                "receipt_version": 1,
                "audit_session_id": str(uuid.uuid4()),
                "event_id": str(uuid.uuid4()),
                "reporter_sequence": 1,
                "conn_id": 1,
                "typ": 0,
                "info": raw_info,
            }
            with (
                self.subTest(size=len(raw_info)),
                patch(
                    "api.views_api._audit_device_context",
                    return_value=(object(), object(), None),
                ),
            ):
                response = self.client.post(
                    "/api/audit/alarm",
                    data=json.dumps(payload),
                    content_type="application/json",
                )
                self.assert_json_error(response, 400)


@override_settings(JSON_CONTROL_MAX_BODY_BYTES=1024 * 1024)
class StrictJsonParserBoundaryTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def request(self, body, content_type="application/json"):
        if isinstance(body, str):
            body = body.encode()
        return self.factory.generic(
            "POST",
            "/api/login",
            data=body,
            content_type=content_type,
        )

    def test_depth_boundary_is_exact_and_iterative(self):
        accepted = ("[" * 63) + "{}" + ("]" * 63)
        rejected = ("[" * 64) + "{}" + ("]" * 64)

        self.assertIsInstance(load_json_body(self.request(accepted)), list)
        with self.assertRaises(InvalidJsonPayload):
            load_json_body(self.request(rejected))

    def test_container_item_boundary_is_exact(self):
        accepted = "[" + ",".join("0" for _ in range(10_000)) + "]"
        rejected = "[" + ",".join("0" for _ in range(10_001)) + "]"

        self.assertEqual(len(load_json_body(self.request(accepted))), 10_000)
        with self.assertRaises(InvalidJsonPayload):
            load_json_body(self.request(rejected))

    def test_total_node_budget_rejects_many_individually_bounded_containers(self):
        accepted = json.dumps([[0] * 10_000 for _ in range(24)], separators=(",", ":"))
        rejected = json.dumps([[0] * 10_000 for _ in range(25)], separators=(",", ":"))

        self.assertEqual(len(load_json_body(self.request(accepted))), 24)
        with self.assertRaises(InvalidJsonPayload):
            load_json_body(self.request(rejected))

    def test_string_and_key_limits_use_utf8_bytes(self):
        accepted_string = json.dumps("x" * (64 * 1024))
        rejected_string = json.dumps("x" * (64 * 1024 + 1))
        accepted_key = json.dumps({"é" * 128: 1}, ensure_ascii=False)
        rejected_key = json.dumps({"é" * 129: 1}, ensure_ascii=False)

        self.assertEqual(len(load_json_text(accepted_string, max_bytes=128 * 1024)), 64 * 1024)
        with self.assertRaises(InvalidJsonPayload):
            load_json_text(rejected_string, max_bytes=128 * 1024)
        self.assertIsInstance(load_json_text(accepted_key, max_bytes=4096), dict)
        with self.assertRaises(InvalidJsonPayload):
            load_json_text(rejected_key, max_bytes=4096)

    def test_number_token_boundary_and_non_finite_float_are_rejected(self):
        accepted = "9" * 128
        rejected = "9" * 129

        self.assertIsInstance(load_json_text(accepted, max_bytes=1024), int)
        for value in (rejected, "NaN", "Infinity", "-Infinity", "1e9999"):
            with self.subTest(value=value[:20]):
                with self.assertRaises(InvalidJsonPayload):
                    load_json_text(value, max_bytes=1024)

    def test_lone_unicode_surrogates_are_rejected(self):
        with self.assertRaises(InvalidJsonPayload):
            load_json_text('"\\ud800"', max_bytes=1024)

    def test_content_length_is_required_and_must_match_cached_body(self):
        body = b'{"enabled":true}'
        for declared in ("", str(len(body) - 1), str(len(body) + 1), "01", "+1", "1,1"):
            request = self.request(body)
            request._body = body  # exercise both smaller and larger framing mismatches deterministically
            request.META["CONTENT_LENGTH"] = declared
            with self.subTest(declared=declared):
                with self.assertRaises(InvalidJsonPayload):
                    load_json_body(request)

    def test_media_type_rejects_ambiguous_parameters_and_json_suffixes(self):
        accepted = self.request(
            b'{"enabled":true}',
            content_type='Application/JSON; Charset="UTF-8"',
        )
        self.assertEqual(load_json_body(accepted), {"enabled": True})

        rejected = (
            "application/problem+json",
            "application/json; charset=utf-8; charset=utf-8",
            "application/json; charset",
            'application/json; charset="utf-8',
            "application/json; x=y",
        )
        for content_type in rejected:
            with self.subTest(content_type=content_type):
                with self.assertRaises(UnsupportedJsonMediaType):
                    load_json_body(self.request(b"{}", content_type=content_type))


@override_settings(STORAGES=TEST_STORAGES)
class StrictShareEnvelopeHttpTests(TestCase):
    def setUp(self):
        self.user = UserProfile.objects.create_user(
            "share-json-user",
            "share-json-password",  # noqa: S106 - isolated test credential
        )
        profile = _ensure_personal_profile(self.user)
        self.peer_one = RemotePeer.objects.create(profile=profile, rid="751000001", alias="one")
        self.peer_two = RemotePeer.objects.create(profile=profile, rid="751000002", alias="two")
        self.client = Client(raise_request_exception=False)
        self.client.force_login(self.user)

    def assert_json_error(self, response, status):
        self.assertEqual(response.status_code, status, response.content[:1000])
        self.assertEqual(response.headers["Content-Type"], "application/json")
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))
        self.assertNotIn(b"Traceback", response.content)
        self.assertLessEqual(len(response.content), 256)

    def test_share_duplicate_key_is_rejected_before_link_creation(self):
        data = f'[{{"value":"{self.peer_one.pk}","value":"{self.peer_two.pk}"}}]'

        response = self.client.post("/api/share", data={"data": data})

        self.assert_json_error(response, 400)
        self.assertEqual(ShareLink.objects.count(), 0)

    def test_share_deep_and_malformed_json_are_bounded_400(self):
        payloads = (
            ("[" * 2000) + "{}" + ("]" * 2000),
            '[{"value":',
        )
        for data in payloads:
            with self.subTest(size=len(data)):
                response = self.client.post("/api/share", data={"data": data})
                self.assert_json_error(response, 400)
                self.assertEqual(ShareLink.objects.count(), 0)

    @override_settings(JSON_SHARE_EMBEDDED_MAX_BYTES=1024, JSON_SHARE_FORM_MAX_BODY_BYTES=4096)
    def test_share_embedded_json_budget_returns_413(self):
        response = self.client.post(
            "/api/share",
            data={"data": json.dumps([{"value": "x" * 2048}])},
        )

        self.assert_json_error(response, 413)
        self.assertEqual(ShareLink.objects.count(), 0)

    def test_share_rejects_non_form_media_type(self):
        response = self.client.post(
            "/api/share",
            data=json.dumps([{"value": str(self.peer_one.pk)}]),
            content_type="text/plain",
        )

        self.assert_json_error(response, 415)
        self.assertEqual(ShareLink.objects.count(), 0)

    def test_share_rejects_duplicate_form_fields(self):
        first = json.dumps([{"value": str(self.peer_one.pk)}])
        second = json.dumps([{"value": str(self.peer_two.pk)}])
        response = self.client.post(
            "/api/share",
            data=urlencode([("data", first), ("data", second)]),
            content_type="application/x-www-form-urlencoded",
        )

        self.assert_json_error(response, 400)
        self.assertEqual(ShareLink.objects.count(), 0)

    @override_settings(JSON_SHARE_EMBEDDED_MAX_BYTES=4096, JSON_SHARE_FORM_MAX_BODY_BYTES=1024)
    def test_share_total_form_budget_is_checked_before_form_parsing(self):
        response = self.client.post(
            "/api/share",
            data={"data": json.dumps([{"value": "x" * 2048}])},
        )

        self.assert_json_error(response, 413)
        self.assertEqual(ShareLink.objects.count(), 0)

    @override_settings(JSON_SHARE_EMBEDDED_MAX_BYTES=4096, JSON_SHARE_FORM_MAX_BODY_BYTES=1024)
    def test_share_form_budget_runs_before_csrf_materializes_the_body(self):
        csrf_client = Client(enforce_csrf_checks=True, raise_request_exception=False)
        csrf_client.force_login(self.user)

        response = csrf_client.post(
            "/api/share",
            data={"data": json.dumps([{"value": "x" * 2048}])},
        )

        self.assert_json_error(response, 413)
        self.assertEqual(ShareLink.objects.count(), 0)

    def test_share_excess_form_fields_return_json_instead_of_django_html(self):
        valid = json.dumps([{"value": str(self.peer_one.pk)}])
        fields = [(f"unused-{index}", "x") for index in range(1001)]
        fields.append(("data", valid))

        response = self.client.post(
            "/api/share",
            data=urlencode(fields),
            content_type="application/x-www-form-urlencoded",
        )

        self.assert_json_error(response, 400)
        self.assertEqual(ShareLink.objects.count(), 0)

    def test_share_rejects_file_parts_with_a_bounded_json_error(self):
        valid = json.dumps([{"value": str(self.peer_one.pk)}])

        response = self.client.post(
            "/api/share",
            data={
                "data": valid,
                "unexpected": SimpleUploadedFile("unexpected.txt", b"x", content_type="text/plain"),
            },
        )

        self.assert_json_error(response, 400)
        self.assertEqual(ShareLink.objects.count(), 0)

    def test_share_preflight_preserves_valid_csrf_processing(self):
        csrf_client = Client(enforce_csrf_checks=True, raise_request_exception=False)
        csrf_client.force_login(self.user)
        page = csrf_client.get("/api/share")
        token = page.cookies["csrftoken"].value

        response = csrf_client.post(
            "/api/share",
            data={
                "csrfmiddlewaretoken": token,
                "data": json.dumps([{"value": str(self.peer_one.pk)}]),
            },
            HTTP_X_CSRFTOKEN=token,
        )

        self.assertEqual(response.status_code, 200, response.content[:1000])
        self.assertEqual(ShareLink.objects.count(), 1)

    def test_share_accepts_multipart_and_urlencoded_forms(self):
        first = json.dumps([{"value": str(self.peer_one.pk)}])
        response = self.client.post("/api/share", data={"data": first})
        self.assertEqual(response.status_code, 200, response.content[:1000])

        second = json.dumps([{"value": str(self.peer_two.pk)}])
        encoded = urlencode({"data": second})
        response = self.client.post(
            "/api/share",
            data=encoded,
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(response.status_code, 200, response.content[:1000])
        self.assertEqual(ShareLink.objects.count(), 2)
