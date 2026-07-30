import json
import re
from html.parser import HTMLParser
from pathlib import Path
from unittest import skipUnless

from django.conf import settings
from django.contrib.staticfiles import finders
from django.test import SimpleTestCase, TestCase, override_settings

from api.models import UserProfile
from webui2.views import (
    _normalize_relay_server,
    _normalize_rendezvous_server,
    _resolve_webui2_servers,
)


class _AccessibilityParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.label_targets = set()
        self.controls = []
        self.blank_links = []
        self.destructive_actions = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "form":
            self._current_form = {"confirm": attributes.get("data-confirm"), "actions": []}
        if tag == "label" and attributes.get("for"):
            self.label_targets.add(attributes["for"])
        if tag in {"input", "select", "textarea"} and attributes.get("type", "").lower() != "hidden":
            self.controls.append(attributes)
        if (
            tag == "input"
            and self._current_form is not None
            and attributes.get("type", "").lower() == "hidden"
            and attributes.get("name") == "action"
        ):
            self._current_form["actions"].append((attributes.get("value"), self._current_form["confirm"]))
        if tag == "button" and attributes.get("name") == "action":
            self.destructive_actions.append((attributes.get("value"), attributes.get("data-confirm")))
        if tag == "a" and attributes.get("target", "").lower() == "_blank":
            self.blank_links.append(attributes)

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.destructive_actions.extend(self._current_form["actions"])
            self._current_form = None


class TemplateAccessibilityTests(SimpleTestCase):
    def test_form_controls_and_new_windows_have_accessible_names(self):
        template_roots = (
            Path(settings.BASE_DIR) / "api" / "templates",
            Path(settings.BASE_DIR) / "webui2" / "templates",
            Path(settings.BASE_DIR) / "templates",
        )
        for template_path in sorted(path for root in template_roots for path in root.rglob("*.html")):
            parser = _AccessibilityParser()
            parser.feed(template_path.read_text(encoding="utf-8"))
            for attributes in parser.controls:
                with self.subTest(template=template_path.name, control=attributes.get("name")):
                    self.assertTrue(
                        attributes.get("aria-label")
                        or attributes.get("aria-labelledby")
                        or attributes.get("id") in parser.label_targets,
                        f"{template_path}: visible form control has no accessible name",
                    )
            for attributes in parser.blank_links:
                with self.subTest(template=template_path.name, href=attributes.get("href")):
                    rel = set((attributes.get("rel") or "").split())
                    self.assertIn("noopener", rel, f"{template_path}: target=_blank must isolate opener")
                    self.assertIn("noreferrer", rel, f"{template_path}: target=_blank must suppress referrer")
            for action, confirmation in parser.destructive_actions:
                if action and (
                    action.startswith("delete_") or action in {"bulk_delete", "bulk_peer_delete", "transfer_book"}
                ):
                    with self.subTest(template=template_path.name, action=action):
                        self.assertTrue(
                            confirmation,
                            f"{template_path}: {action} must require explicit confirmation",
                        )


class WebClientServerConfigurationTests(SimpleTestCase):
    @override_settings(
        DEFAULT_ID_PORT=21116,
        ID_SERVER="id.example.com",
        RELAY_SERVER="",
    )
    def test_native_endpoints_use_service_ports(self):
        raw, rendezvous, relay = _resolve_webui2_servers()

        self.assertEqual(raw, ["id.example.com"])
        self.assertEqual(rendezvous, ["id.example.com:21116"])
        self.assertEqual(relay, ["id.example.com:21117"])

    @override_settings(
        DEFAULT_ID_PORT=21116,
        ID_SERVER="ws://id.example.com",
        RELAY_SERVER="",
    )
    def test_plain_websocket_endpoints_use_websocket_ports(self):
        _raw, rendezvous, relay = _resolve_webui2_servers()

        self.assertEqual(rendezvous, ["ws://id.example.com:21118"])
        self.assertEqual(relay, ["ws://id.example.com:21119"])

    @override_settings(
        DEFAULT_ID_PORT=21116,
        ID_SERVER="wss://remote.example.com:443",
        RELAY_SERVER="",
    )
    def test_tls_reverse_proxy_uses_one_origin_and_distinct_paths(self):
        _raw, rendezvous, relay = _resolve_webui2_servers()

        self.assertEqual(
            rendezvous,
            ["wss://remote.example.com:443/ws/id"],
        )
        self.assertEqual(
            relay,
            ["wss://remote.example.com:443/ws/relay"],
        )

    @override_settings(
        DEFAULT_ID_PORT=21116,
        ID_SERVER="wss://remote.example.com:8443/custom-id?tenant=one",
        RELAY_SERVER="wss://relay.example.com:9443/custom-relay?tenant=one",
    )
    def test_explicit_proxy_paths_and_queries_are_preserved(self):
        _raw, rendezvous, relay = _resolve_webui2_servers()

        self.assertEqual(
            rendezvous,
            ["wss://remote.example.com:8443/custom-id?tenant=one"],
        )
        self.assertEqual(
            relay,
            ["wss://relay.example.com:9443/custom-relay?tenant=one"],
        )

    @override_settings(DEFAULT_ID_PORT=21116)
    def test_invalid_or_credentialed_endpoints_are_rejected(self):
        self.assertEqual(_normalize_rendezvous_server("https://id.example.com"), "")
        self.assertEqual(
            _normalize_rendezvous_server("wss://user:secret@id.example.com"),
            "",
        )
        self.assertEqual(
            _normalize_relay_server("relay.example.com/path"),
            "",
        )


class WebClientRuntimeTests(TestCase):
    @property
    def runtime_root(self):
        return Path(settings.BASE_DIR) / "static" / "web_client"

    @skipUnless(
        (Path(settings.BASE_DIR) / "static" / "web_client" / ".source_revision").is_file(),
        "Web runtime is generated on demand; run sync_web_client.sh to validate it locally",
    )
    def test_runtime_bundle_excludes_build_tooling(self):
        required_files = (
            ".source_revision",
            "flutter_bootstrap.js",
            "main.dart.js",
            "manifest.json",
            "canvaskit/canvaskit.wasm",
            "js/dist/web_bridge.js",
        )
        for relative_path in required_files:
            with self.subTest(relative_path=relative_path):
                self.assertTrue((self.runtime_root / relative_path).is_file())

        source_revision = (self.runtime_root / ".source_revision").read_text().strip()
        self.assertRegex(source_revision, r"^[0-9a-f]{40,64} clean$")

        forbidden_paths = (
            "js/node_modules",
            "js/src",
            "js/tools",
            "js/package.json",
            "js/package-lock.json",
            "js/tsconfig.json",
            "js/vite.config.ts",
        )
        for relative_path in forbidden_paths:
            with self.subTest(relative_path=relative_path):
                self.assertFalse((self.runtime_root / relative_path).exists())

    @skipUnless(
        (Path(settings.BASE_DIR) / "static" / "web_client" / ".source_revision").is_file(),
        "Web runtime is generated on demand; run sync_web_client.sh to validate it locally",
    )
    def test_bootstrap_has_one_complete_javascript_target(self):
        bootstrap = (self.runtime_root / "flutter_bootstrap.js").read_text()
        match = re.search(r"_flutter\.buildConfig = (\{[^\n]+\});", bootstrap)
        self.assertIsNotNone(match)
        config = json.loads(match.group(1))
        self.assertEqual(
            config["builds"],
            [
                {
                    "compileTarget": "dart2js",
                    "renderer": "canvaskit",
                    "mainJsPath": "main.dart.js",
                }
            ],
        )
        self.assertNotIn("sourceMappingURL=", bootstrap)
        self.assertNotIn(
            "sourceMappingURL=",
            (self.runtime_root / "flutter.js").read_text(),
        )

    def test_admin_assets_use_the_framework_version_without_shadowing(self):
        self.assertEqual(
            len(finders.find("admin/css/base.css", find_all=True)),
            1,
        )
        self.assertEqual(
            len(finders.find("camellia_admin/admin.css", find_all=True)),
            1,
        )

    @override_settings(
        STORAGES={
            "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
            "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
        }
    )
    def test_entrypoint_is_nonce_bound_without_unsafe_eval(self):
        user = UserProfile.objects.create_user(
            username="web-client-user",
            password="test-password",
        )
        self.client.force_login(user)

        response = self.client.get("/webui2/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "/static/web_client/js/dist/web_bridge.js")
        self.assertContains(response, "/static/web_client/flutter_bootstrap.js")
        csp = response.headers.get("Content-Security-Policy", "")
        self.assertIn("script-src", csp)
        self.assertIn("'nonce-", csp)
        self.assertIn("'wasm-unsafe-eval'", csp)
        self.assertNotIn("'unsafe-eval'", csp)
