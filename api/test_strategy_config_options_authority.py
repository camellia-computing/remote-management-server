import json
import uuid
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, transaction
from django.test import TestCase
from django.utils import timezone

from api.models import RemoteDevice, StrategyProfile, UserProfile
from api.policy_generation import (
    MAX_POLICY_OPTIONS_BYTES,
    InvalidManagedPolicy,
    canonical_policy_options,
    normalize_policy_options,
)
from api.views_api import _issue_access_token, _serialize_strategy


class StrategyConfigOptionsAuthorityTests(TestCase):
    def test_instance_and_queryset_writes_reject_invalid_options(self):
        with self.assertRaises(ValidationError):
            StrategyProfile.objects.create(
                name="invalid-instance-options",
                config_options=["not-an-object"],
            )

        strategy = StrategyProfile.objects.create(
            name="invalid-queryset-options",
            config_options={"mode": "valid"},
        )
        with self.assertRaises(ValidationError):
            StrategyProfile.objects.filter(pk=strategy.pk).update(
                config_options={"mode": ["not-a-string"]},
            )
        strategy.refresh_from_db()
        self.assertEqual(strategy.config_options, {"mode": "valid"})

    def test_bulk_writes_reject_invalid_options(self):
        with self.assertRaises(ValidationError):
            StrategyProfile.objects.bulk_create(
                [
                    StrategyProfile(
                        name="invalid-bulk-create-options",
                        config_options={"mode": None},
                    )
                ]
            )

        strategy = StrategyProfile.objects.create(
            name="invalid-bulk-update-options",
            config_options={"mode": "valid"},
        )
        strategy.config_options = {"mode": {"nested": "object"}}
        with self.assertRaises(ValidationError):
            StrategyProfile.objects.bulk_update([strategy], ["config_options"])
        strategy.refresh_from_db()
        self.assertEqual(strategy.config_options, {"mode": "valid"})

    def test_failed_invalid_writes_do_not_advance_policy_generation(self):
        owner = UserProfile.objects.create_user(username="strategy-generation-owner")
        strategy = StrategyProfile.objects.create(
            name="strategy-generation-options",
            config_options={"mode": "valid"},
        )
        device = RemoteDevice.objects.create(
            rid="strategy-gen",
            uuid="strategy-gen",
            owner=owner,
            strategy=strategy,
            cpu="-",
            hostname="-",
            memory="-",
            os="linux",
            username="",
            version="-",
        )

        strategy.config_options = {"mode": ["invalid-instance"]}
        with self.assertRaises(ValidationError):
            strategy.save(update_fields=["config_options"])
        strategy.refresh_from_db()
        device.refresh_from_db()
        self.assertEqual(strategy.config_options, {"mode": "valid"})
        self.assertEqual(device.policy_generation, 0)

        with self.assertRaises(ValidationError):
            StrategyProfile.objects.filter(pk=strategy.pk).update(
                config_options={"mode": ["invalid-queryset"]},
            )
        strategy.refresh_from_db()
        device.refresh_from_db()
        self.assertEqual(strategy.config_options, {"mode": "valid"})
        self.assertEqual(device.policy_generation, 0)

        strategy.config_options = {"mode": ["invalid-bulk-update"]}
        with self.assertRaises(ValidationError):
            StrategyProfile.objects.bulk_update([strategy], ["config_options"])
        strategy.refresh_from_db()
        device.refresh_from_db()
        self.assertEqual(strategy.config_options, {"mode": "valid"})
        self.assertEqual(device.policy_generation, 0)

    def test_database_rejects_raw_invalid_options(self):
        strategy = StrategyProfile.objects.create(
            name="raw-update-options",
            config_options={"mode": "valid"},
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic(), connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO api_strategyprofile (
                        guid,
                        name,
                        config_options,
                        enabled,
                        updated_at
                    ) VALUES (%s, %s, %s, %s, %s)
                    """,
                    [
                        uuid.uuid4().hex,
                        "invalid-raw-options",
                        json.dumps({"mode": ["not-a-string"]}),
                        True,
                        timezone.now(),
                    ],
                )
        with self.assertRaises(IntegrityError):
            with transaction.atomic(), connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE api_strategyprofile SET config_options = %s WHERE id = %s",
                    [json.dumps({"mode": ["not-a-string"]}), strategy.pk],
                )
        strategy.refresh_from_db()
        self.assertEqual(strategy.config_options, {"mode": "valid"})

    def test_schema_enforces_item_character_byte_and_document_budgets(self):
        valid_options = {
            "😀" * 128: "😀" * 4096,
            **{f"key-{index}": "value" for index in range(511)},
        }
        strategy = StrategyProfile.objects.create(
            name="valid-boundary-options",
            config_options=valid_options,
        )
        self.assertEqual(strategy.config_options, valid_options)

        exact_document_budget = {f"key-{index}": "v" * 4096 for index in range(15)}
        exact_document_budget["tail"] = ""
        tail_bytes = MAX_POLICY_OPTIONS_BYTES - len(canonical_policy_options(exact_document_budget))
        self.assertGreaterEqual(tail_bytes, 0)
        self.assertLessEqual(tail_bytes, 4096)
        exact_document_budget["tail"] = "v" * tail_bytes
        self.assertEqual(
            len(canonical_policy_options(exact_document_budget)),
            MAX_POLICY_OPTIONS_BYTES,
        )
        exact_budget_strategy = StrategyProfile.objects.create(
            name="valid-exact-document-budget",
            config_options=exact_document_budget,
        )
        self.assertEqual(exact_budget_strategy.config_options, exact_document_budget)

        invalid_documents = (
            {f"key-{index}": "value" for index in range(513)},
            {"": "value"},
            {"control\x01key": "value"},
            {"k" * 129: "value"},
            {"key": "v" * 4097},
            {f"key-{index}": "v" * 4096 for index in range(16)},
            {"\ud800": "value"},
            {"key": "\ud800"},
        )
        for index, document in enumerate(invalid_documents):
            with self.subTest(index=index):
                with self.assertRaises(ValidationError):
                    StrategyProfile.objects.create(
                        name=f"invalid-budget-options-{index}",
                        config_options=document,
                    )

    def test_normalizer_classifies_unencodable_unicode(self):
        for options in ({"\ud800": "value"}, {"key": "\ud800"}):
            with self.subTest(options=repr(options)):
                with self.assertRaises(InvalidManagedPolicy):
                    normalize_policy_options(options)

    def test_strategy_serialization_never_masks_invalid_data_as_empty(self):
        strategy = StrategyProfile(
            name="invalid-read-options",
            config_options={"mode": ["not-a-string"]},
        )
        with self.assertRaises(InvalidManagedPolicy):
            _serialize_strategy(strategy)

    def test_strategy_list_and_detail_fail_closed_on_read_validation_errors(self):
        admin_user = UserProfile.objects.create_user(
            username="strategy-options-admin",
            is_admin=True,
        )
        device = RemoteDevice.objects.create(
            rid="strategy-options",
            uuid="strategy-options",
            owner=admin_user,
            is_active=True,
            cpu="-",
            hostname="-",
            memory="-",
            os="linux",
            username="",
            version="-",
        )
        token = _issue_access_token(admin_user, device)[1]
        strategy = StrategyProfile.objects.create(
            name="strategy-read-failure",
            config_options={"mode": "valid"},
        )

        with patch(
            "api.views_api.normalize_policy_options",
            side_effect=InvalidManagedPolicy("injected read failure"),
        ):
            responses = (
                self.client.get(
                    "/api/strategies",
                    HTTP_AUTHORIZATION=f"Bearer {token}",
                ),
                self.client.get(
                    f"/api/strategies/{strategy.guid}",
                    HTTP_AUTHORIZATION=f"Bearer {token}",
                ),
            )

        for response in responses:
            with self.subTest(path=response.request["PATH_INFO"]):
                self.assertEqual(response.status_code, 503, response.content)
                self.assertEqual(response.json()["code"], "invalid_strategy_configuration")
                self.assertEqual(response.json()["response_schema_version"], 1)
