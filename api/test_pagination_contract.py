import json
from unittest.mock import patch

from django.test import Client, TestCase, override_settings

from api.models import AddressBookProfile, RemotePeer
from api.tests import ApiTestMixin

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}

PAGINATION_CONTRACT_VERSION = 1
MAX_PAGE_SIZE = 500
MAX_PAGE_OFFSET = 10_000


@override_settings(
    STORAGES=TEST_STORAGES,
    REQUEST_RATE_LIMIT_ENABLED=False,
)
class PaginationContractTests(ApiTestMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.client = Client(raise_request_exception=False)
        self.token = self._login("admin", "admin-pass")
        self.profile = AddressBookProfile.objects.create(
            owner=self.admin,
            guid="pagination-contract-book",
            name="Pagination Contract Book",
            rule=3,
        )
        RemotePeer.objects.create(
            profile=self.profile,
            rid="765710001",
            alias="Pagination Contract Peer",
        )

    @property
    def routes(self):
        return (
            ("GET", "/api/users"),
            ("GET", "/api/devices"),
            ("GET", "/api/device-groups"),
            ("GET", "/api/peers"),
            ("POST", "/api/ab/shared/profiles"),
            ("GET", f"/api/ab/rules?ab={self.profile.guid}"),
            ("POST", f"/api/ab/peers?ab={self.profile.guid}"),
        )

    def request_route(self, method, path, query=""):
        separator = "&" if "?" in path else "?"
        target = f"{path}{separator}{query}" if query else path
        headers = self._auth_headers(self.token)
        if method == "GET":
            return self.client.get(target, **headers)
        return self.client.post(
            target,
            data=json.dumps({}),
            content_type="application/json",
            **headers,
        )

    def assert_pagination_error(self, response, *, field):
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(
            response.json(),
            {
                "error": "Invalid pagination",
                "code": "invalid_pagination",
                "pagination_contract_version": PAGINATION_CONTRACT_VERSION,
                "field": field,
                "limits": {
                    "max_page_size": MAX_PAGE_SIZE,
                    "max_offset": MAX_PAGE_OFFSET,
                },
            },
        )
        self.assertLessEqual(len(response.content), 320)

    def assert_page(self, response, *, current, page_size):
        self.assertEqual(response.status_code, 200, response.content)
        payload = response.json()
        self.assertEqual(payload["pagination_contract_version"], PAGINATION_CONTRACT_VERSION)
        self.assertEqual(payload["current"], current)
        self.assertEqual(payload["pageSize"], page_size)
        self.assertIn("total", payload)
        self.assertIn("data", payload)

    def test_every_route_rejects_noncanonical_or_out_of_budget_values(self):
        invalid_queries = (
            ("current=", "current"),
            ("current=0", "current"),
            ("current=-1", "current"),
            ("current=%2B1", "current"),
            ("current=01", "current"),
            ("current=\u0661", "current"),
            ("current=1.0", "current"),
            (f"current={'9' * 20}", "current"),
            (f"current={'9' * 100}", "current"),
            (f"current={'9' * 5000}", "current"),
            ("current=9223372036854775807", "current"),
            ("current=9223372036854775808", "current"),
            ("current=1&current=1", "current"),
            ("current=1&current=2", "current"),
            ("pageSize=", "pageSize"),
            ("pageSize=0", "pageSize"),
            ("pageSize=-1", "pageSize"),
            ("pageSize=%2B1", "pageSize"),
            ("pageSize=01", "pageSize"),
            ("pageSize=\u0661", "pageSize"),
            ("pageSize=501", "pageSize"),
            (f"pageSize={'9' * 5000}", "pageSize"),
            ("pageSize=1&pageSize=1", "pageSize"),
            ("current=102&pageSize=100", "current"),
            ("current=22&pageSize=500", "current"),
            ("current=10002&pageSize=1", "current"),
        )
        for method, path in self.routes:
            for query, field in invalid_queries:
                with self.subTest(method=method, path=path, query=query):
                    response = self.request_route(method, path, query)
                    self.assert_pagination_error(response, field=field)

    def test_missing_and_maximum_boundaries_use_one_empty_page_contract(self):
        boundaries = (
            ("", 1, 100),
            ("current=101&pageSize=100", 101, 100),
            ("current=21&pageSize=500", 21, 500),
            ("current=10001&pageSize=1", 10001, 1),
        )
        for method, path in self.routes:
            for query, current, page_size in boundaries:
                with self.subTest(method=method, path=path, query=query or "missing"):
                    response = self.request_route(method, path, query)
                    self.assert_page(response, current=current, page_size=page_size)
                    if current > 1:
                        self.assertEqual(response.json()["data"], [])

    def test_rejected_deep_pages_do_not_touch_route_data_sources(self):
        cases = (
            ("GET", "/api/users", "api.views_api.UserProfile"),
            ("GET", "/api/devices", "api.views_api.RemoteDevice"),
            ("GET", "/api/device-groups", "api.views_api.DeviceGroup"),
            ("GET", "/api/peers", "api.views_api.DeviceInventory"),
            ("POST", "/api/ab/shared/profiles", "api.views_api.AddressBookProfile"),
            (
                "GET",
                f"/api/ab/rules?ab={self.profile.guid}",
                "api.views_api._get_profile_access",
            ),
            (
                "POST",
                f"/api/ab/peers?ab={self.profile.guid}",
                "api.views_api._get_profile_access",
            ),
        )
        for method, path, source_path in cases:
            with (
                self.subTest(method=method, path=path),
                patch("api.views_api._get_token_user", return_value=(None, self.admin)),
                patch(source_path) as source,
            ):
                response = self.request_route(method, path, "current=10002&pageSize=1")
                self.assert_pagination_error(response, field="current")
                self.assertEqual(source.mock_calls, [])

    def test_signed_peer_cursor_uses_keyset_position_instead_of_page_offset(self):
        self._device(
            owner=self.admin,
            rid="765710002",
            uuid="12345678-1234-4234-8234-123456789012",
        )
        first = self.client.get(
            "/api/peers?status=1&pageSize=1",
            **self._auth_headers(self.token),
        )
        self.assertEqual(first.status_code, 200, first.content)
        cursor = first.json()["nextCursor"]
        self.assertTrue(cursor)

        with patch("api.views_api.DeviceInventory.rows", return_value=[]) as rows:
            response = self.client.get(
                "/api/peers",
                {
                    "status": "1",
                    "current": "22",
                    "pageSize": "500",
                    "cursor": cursor,
                },
                **self._auth_headers(self.token),
            )

        self.assert_page(response, current=22, page_size=500)
        rows.assert_called_once_with(
            offset=0,
            limit=501,
            status_filter="1",
            rid_after=first.json()["data"][-1]["id"],
        )
