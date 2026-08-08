from unittest.mock import patch

from django.test import TestCase, override_settings

from api.models import AddressBookProfile, AddressBookShare, RemotePeer, RemoteTag, UserProfile

TEST_STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}

EXPORT_SCHEMA = "address-book-export-v1"
FORMAT_VALUES = ["csv", "xls", "xlsx"]
KIND_VALUES = ["peers", "tags"]


@override_settings(
    STORAGES=TEST_STORAGES,
    REQUEST_RATE_LIMIT_ENABLED=False,
)
class AddressBookExportContractTests(TestCase):
    def setUp(self):
        self.admin = UserProfile.objects.create_superuser(
            "export-contract-admin",
            "export-contract-admin-password",  # noqa: S106 - isolated test credential
        )
        self.owner = UserProfile.objects.create_user(
            "export-contract-owner",
            "export-contract-owner-password",  # noqa: S106 - isolated test credential
        )
        self.shared_user = UserProfile.objects.create_user(
            "export-contract-shared",
            "export-contract-shared-password",  # noqa: S106 - isolated test credential
        )
        self.profile = AddressBookProfile.objects.create(
            owner=self.owner,
            guid="export-contract-book",
            name="Export Contract Book",
            rule=3,
        )
        self.tag = RemoteTag.objects.create(
            profile=self.profile,
            tag_name="Export Contract Tag",
            tag_color="#123456",
        )
        self.peer = RemotePeer.objects.create(
            profile=self.profile,
            rid="765700001",
            alias="Export Contract Peer",
        )
        self.peer.tags.add(self.tag)
        AddressBookShare.objects.create(
            profile=self.profile,
            user=self.shared_user,
            rule=1,
        )
        self.client.force_login(self.admin)

    def assert_export_error(self, response, *, parameter, supported_values):
        self.assertEqual(response.status_code, 400, response.content)
        self.assertTrue(response.headers["Content-Type"].startswith("application/json"))
        self.assertEqual(response.headers.get("X-Camellia-Export-Schema"), EXPORT_SCHEMA)
        self.assertNotIn("Content-Disposition", response.headers)
        self.assertEqual(response.headers.get("Cache-Control"), "no-store, private")
        payload = response.json()
        self.assertEqual(payload["code"], "invalid_export_parameter")
        self.assertEqual(payload["parameter"], parameter)
        self.assertEqual(payload["supported_values"], supported_values)
        self.assertEqual(payload["export_schema"], EXPORT_SCHEMA)
        self.assertLessEqual(len(response.content), 512)

    def assert_artifact(self, response, *, export_format, kind=None):
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.headers.get("X-Camellia-Export-Schema"), EXPORT_SCHEMA)
        self.assertEqual(response.headers.get("X-Camellia-Export-Format"), export_format)
        if kind is None:
            self.assertNotIn("X-Camellia-Export-Kind", response.headers)
        else:
            self.assertEqual(response.headers.get("X-Camellia-Export-Kind"), kind)
        disposition = response.headers.get("Content-Disposition", "")
        if export_format == "xlsx":
            self.assertTrue(
                response.headers["Content-Type"].startswith(
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
            )
            self.assertIn(".xlsx", disposition)
            self.assertTrue(response.content.startswith(b"PK"))
        else:
            self.assertTrue(response.headers["Content-Type"].startswith("text/csv"))
            self.assertIn(".csv", disposition)
            self.assertFalse(response.content.startswith(b"PK"))

    def test_unknown_format_is_rejected_before_data_sources_or_artifact_builders(self):
        cases = (
            ("/api/ab_books_export?format=json", "api.views_front._ab_accessible_profiles"),
            (
                f"/api/ab_book_export?guid={self.profile.guid}&kind=peers&format=json",
                "api.views_front._get_profile_access_web",
            ),
            ("/api/tag_export?format=json", "api.views_front._ab_accessible_profiles"),
            ("/api/ab_rules_export?format=json", "api.views_front._collect_global_rules"),
            ("/api/ab_shares_export?format=json", "api.views_front.AddressBookShare"),
        )
        for path, source_path in cases:
            with (
                self.subTest(path=path),
                patch(source_path) as source,
                patch("api.views_front.safe_csv_writer") as csv_builder,
                patch("api.views_front.xlsx_response") as workbook_builder,
            ):
                response = self.client.get(path)
                self.assert_export_error(
                    response,
                    parameter="format",
                    supported_values=FORMAT_VALUES,
                )
                self.assertEqual(source.mock_calls, [])
                csv_builder.assert_not_called()
                workbook_builder.assert_not_called()

    def test_format_missing_defaults_but_present_invalid_values_fail_closed(self):
        routes = (
            "/api/ab_books_export",
            f"/api/ab_book_export?guid={self.profile.guid}&kind=peers",
            "/api/tag_export",
            "/api/ab_rules_export",
            "/api/ab_shares_export",
        )
        invalid_queries = (
            "format=",
            "format=CSV",
            f"format={'x' * 4096}",
            "format=csv&format=csv",
            "format=csv&format=xlsx",
        )
        for route in routes:
            separator = "&" if "?" in route else "?"
            with self.subTest(route=route, query="missing"):
                defaulted = self.client.get(route)
                expected_kind = "peers" if "ab_book_export" in route else None
                self.assert_artifact(defaulted, export_format="csv", kind=expected_kind)
            for query in invalid_queries:
                with self.subTest(route=route, query=query):
                    response = self.client.get(f"{route}{separator}{query}")
                    self.assert_export_error(
                        response,
                        parameter="format",
                        supported_values=FORMAT_VALUES,
                    )

    def test_every_export_has_consistent_csv_and_ooxml_artifacts(self):
        routes = (
            "/api/ab_books_export",
            f"/api/ab_book_export?guid={self.profile.guid}&kind=peers",
            "/api/tag_export",
            "/api/ab_rules_export",
            "/api/ab_shares_export",
        )
        for route in routes:
            separator = "&" if "?" in route else "?"
            for requested_format, actual_format in (
                ("csv", "csv"),
                ("xls", "xlsx"),
                ("xlsx", "xlsx"),
            ):
                with self.subTest(route=route, requested_format=requested_format):
                    response = self.client.get(f"{route}{separator}format={requested_format}")
                    expected_kind = "peers" if "ab_book_export" in route else None
                    self.assert_artifact(
                        response,
                        export_format=actual_format,
                        kind=expected_kind,
                    )

    def test_browser_templates_emit_the_canonical_xlsx_value(self):
        routes = (
            "/api/ab_books",
            f"/api/ab_book?guid={self.profile.guid}",
            "/api/tag_manage",
            "/api/ab_rules",
        )
        for route in routes:
            with self.subTest(route=route):
                response = self.client.get(route)
                self.assertEqual(response.status_code, 200, response.content)
                content = response.content.decode()
                self.assertIn("format=xlsx", content)
                self.assertNotRegex(content, r"format=xls(?:[\"&])")

    def test_book_kind_missing_defaults_but_present_invalid_values_fail_closed(self):
        base = f"/api/ab_book_export?guid={self.profile.guid}"
        defaulted = self.client.get(f"{base}&format=csv")
        self.assert_artifact(defaulted, export_format="csv", kind="peers")

        for kind in KIND_VALUES:
            for requested_format, actual_format in (
                ("csv", "csv"),
                ("xls", "xlsx"),
                ("xlsx", "xlsx"),
            ):
                with self.subTest(kind=kind, requested_format=requested_format):
                    response = self.client.get(f"{base}&kind={kind}&format={requested_format}")
                    self.assert_artifact(
                        response,
                        export_format=actual_format,
                        kind=kind,
                    )

        invalid_queries = (
            "kind=",
            "kind=PEERS",
            "kind=unknown",
            f"kind={'x' * 4096}",
            "kind=peers&kind=peers",
            "kind=peers&kind=tags",
        )
        for query in invalid_queries:
            with self.subTest(query=query), patch("api.views_front._get_profile_access_web") as profile_lookup:
                response = self.client.get(f"{base}&format=csv&{query}")
                self.assert_export_error(
                    response,
                    parameter="kind",
                    supported_values=KIND_VALUES,
                )
                profile_lookup.assert_not_called()
