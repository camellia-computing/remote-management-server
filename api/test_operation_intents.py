import copy
import json
import unittest
import uuid

from api.operation_intents import (
    SecretIntent,
    new_private_binding,
    partition_intent,
    private_binding_matches,
    public_intent_digest,
)


class OperationIntentPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.context = {"actor_id": 7, "operation_id": uuid.uuid4(), "operation": "privacy_test"}
        self.intent = {
            "target": "stable-target",
            "password": "SYNTHETIC-CREDENTIAL-A",
            "body": [{"note": "visible note", "rhash": "SYNTHETIC-CREDENTIAL-B"}],
        }

    def test_public_proof_has_no_secret_value_length_or_unkeyed_secret_verifier(self):
        public, private = partition_intent(self.intent)
        self.assertEqual(private, self.intent)
        self.assertEqual(public["password"], {"$secret_intent": "set"})
        self.assertEqual(public["body"][0]["rhash"], {"$secret_intent": "set"})
        self.assertNotIn("SYNTHETIC-CREDENTIAL", json.dumps(public))
        changed = copy.deepcopy(self.intent)
        changed["password"] = "SYNTHETIC-DIFFERENT-AND-MUCH-LONGER"  # noqa: S105 - isolated synthetic intent
        self.assertEqual(public_intent_digest(self.intent), public_intent_digest(changed))
        changed["target"] = "other-target"
        self.assertNotEqual(public_intent_digest(self.intent), public_intent_digest(changed))

    def test_private_binding_covers_every_secret_public_field_and_authority_context(self):
        binding = new_private_binding(self.intent, **self.context)
        self.assertTrue(private_binding_matches(binding, self.intent, **self.context))
        self.assertTrue(private_binding_matches(binding, dict(reversed(list(self.intent.items()))), **self.context))
        for changed in [
            {**self.intent, "password": "other"},
            {**self.intent, "target": "other"},
            {**self.intent, "body": [{"note": "visible note", "rhash": "other"}]},
        ]:
            with self.subTest(fields=tuple(changed)):
                self.assertFalse(private_binding_matches(binding, changed, **self.context))
        for key, value in [("actor_id", 8), ("operation_id", uuid.uuid4()), ("operation", "other")]:
            self.assertFalse(private_binding_matches(binding, self.intent, **{**self.context, key: value}))
        self.assertNotEqual(binding, new_private_binding(self.intent, **self.context))

    def test_personal_peer_wire_hash_is_secret_not_an_offline_public_verifier(self):
        first = {"body": {"id": "123", "hash": "SYNTHETIC-PERSONAL-HASH-A"}}
        changed = {"body": {"id": "123", "hash": "SYNTHETIC-PERSONAL-HASH-B"}}
        self.assertEqual(public_intent_digest(first), public_intent_digest(changed))
        binding = new_private_binding(first, **self.context)
        self.assertFalse(private_binding_matches(binding, changed, **self.context))

    def test_secret_actions_and_explicit_form_markers_are_unambiguous(self):
        for value, action in [(None, "keep"), ("", "clear"), ("nonempty", "set")]:
            with self.subTest(action=action):
                public, private = partition_intent({"default_password": value})
                self.assertEqual(public, {"default_password": {"$secret_intent": action}})
                self.assertEqual(private, {"default_password": value})
        public, private = partition_intent({"fields": {"opaque": SecretIntent(["private value"])}})
        self.assertNotIn("private value", json.dumps(public))
        self.assertEqual(private, {"fields": {"opaque": ["private value"]}})
        self.assertNotIn("private value", repr(SecretIntent("private value")))

    def test_malformed_binding_or_excess_depth_is_rejected_without_echoing_secrets(self):
        binding = new_private_binding(self.intent, **self.context)
        for field, value in [("version", True), ("key", "SYNTHETIC-CREDENTIAL"), ("mac", "F" * 64)]:
            with self.assertRaisesRegex(ValueError, "Stored private operation binding is invalid") as captured:
                private_binding_matches({**binding, field: value}, self.intent, **self.context)
            self.assertNotIn("SYNTHETIC-CREDENTIAL", str(captured.exception))
        recursive = []
        recursive.append(recursive)
        with self.assertRaisesRegex(ValueError, "too deeply nested"):
            partition_intent(recursive)

    def test_http_json_depth_budget_still_fits_after_metadata_and_secret_projection(self):
        nested = "SYNTHETIC-DEEP-INTENT"
        for _index in range(64):
            nested = {"password": nested}
        document = {"operation": "depth_budget", "body": nested}
        public, private = partition_intent(document)
        self.assertEqual(private, document)
        self.assertNotIn("SYNTHETIC-DEEP-INTENT", json.dumps(public))
        binding = new_private_binding(document, **self.context)
        self.assertTrue(private_binding_matches(binding, document, **self.context))
