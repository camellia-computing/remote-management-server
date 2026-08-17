import importlib.util
import io
import json
import tempfile
from pathlib import Path

from django.apps import apps
from django.core import serializers
from django.core.management import call_command, get_commands
from django.core.management.base import CommandError
from django.core.serializers.base import SerializationError
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from api.encrypted_fields import EncryptedTextField
from api.models import AddressBookProfile, RemotePeer, RemoteTag, UserProfile


class SafeLogicalSerializationTests(TestCase):
    CANARY = "logical-export-plaintext-canary"

    def setUp(self):
        self.owner = UserProfile.objects.create_user("logical-export-owner", "owner-password")
        self.profile = AddressBookProfile.objects.create(
            guid="logical-export-profile",
            name="Logical export profile",
            owner=self.owner,
            default_password="profile-secret",  # noqa: S106 - encrypted-field regression input
        )
        self.peer = RemotePeer.objects.create(
            profile=self.profile,
            rid="logical-export-peer",
            rhash=self.CANARY,
            password="logical-export-password",  # noqa: S106 - encrypted-field regression input
        )

    @staticmethod
    def encrypted_model_labels():
        return {
            model._meta.label
            for model in apps.get_models()
            if any(isinstance(field, EncryptedTextField) for field in model._meta.concrete_fields)
        }

    def test_encrypted_model_inventory_and_dumpdata_override_are_complete(self):
        self.assertEqual(get_commands()["dumpdata"], "api")
        self.assertEqual(
            self.encrypted_model_labels(),
            {
                "api.AddressBookProfile",
                "api.OidcPendingAuth",
                "api.RecordingUpload",
                "api.RemoteDevice",
                "api.RemotePeer",
            },
        )

    def test_programmatic_serializers_fail_before_writing_plaintext(self):
        formats = set(serializers.get_public_serializer_formats()) & {"json", "jsonl", "xml", "yaml"}
        if importlib.util.find_spec("yaml") is None:
            formats.discard("yaml")
        self.assertGreaterEqual(formats, {"json", "jsonl", "xml"})
        for format_name in sorted(formats):
            with self.subTest(format=format_name):
                output = io.StringIO()
                with self.assertRaises(SerializationError) as raised:
                    serializers.serialize(format_name, [self.peer], stream=output)
                observed = output.getvalue() + str(raised.exception)
                self.assertNotIn(self.CANARY, observed)
                self.assertNotIn("logical-export-password", observed)

    def test_deferred_encrypted_field_still_fails_closed(self):
        deferred = RemotePeer.objects.only("pk", "profile_id", "secret_context", "rid").get(pk=self.peer.pk)
        output = io.StringIO()
        with self.assertRaises(SerializationError):
            serializers.serialize("json", [deferred], stream=output)
        self.assertNotIn(self.CANARY, output.getvalue())

    def test_dumpdata_refuses_secret_selection_before_query_or_output_creation(self):
        cases = tuple(((label,), {}) for label in sorted(self.encrypted_model_labels())) + (
            ((), {}),
            (("api",), {}),
            (("api.RemotePeer",), {"pks": str(self.peer.pk)}),
            (("api.RemotePeer",), {"use_natural_foreign_keys": True}),
            (("api.RemotePeer",), {"use_natural_primary_keys": True}),
            (("api.RemotePeer",), {"format": "yaml"}),
        )
        for labels, options in cases:
            with self.subTest(labels=labels, options=options):
                output = io.StringIO()
                with CaptureQueriesContext(connection) as queries:
                    with self.assertRaises(CommandError) as raised:
                        call_command("dumpdata", *labels, stdout=output, **options)
                observed = output.getvalue() + str(raised.exception)
                self.assertEqual(len(queries), 0)
                self.assertIn("authenticated physical backup set", observed)
                self.assertNotIn(self.CANARY, observed)
                self.assertLess(len(observed), 2048)

        with tempfile.TemporaryDirectory(prefix="camellia-logical-export-") as temporary:
            destination = Path(temporary) / "secrets.json"
            with self.assertRaises(CommandError):
                call_command("dumpdata", "api.RemotePeer", output=str(destination), verbosity=0)
            self.assertFalse(destination.exists())

    def test_explicitly_safe_model_selection_can_still_use_dumpdata(self):
        tag = RemoteTag.objects.create(profile=self.profile, tag_name="logical-safe-tag", tag_color="#123456")
        output = io.StringIO()
        call_command(
            "dumpdata",
            "api.RemotePeer",
            "api.RemoteTag",
            exclude=["api.RemotePeer"],
            stdout=output,
        )
        payload = json.loads(output.getvalue())
        self.assertEqual([(row["model"], row["pk"]) for row in payload], [("api.remotetag", tag.pk)])
        self.assertNotIn(self.CANARY, output.getvalue())
