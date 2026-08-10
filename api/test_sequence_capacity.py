import json
from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.apps import apps
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import models
from django.test import TestCase
from django.utils import timezone

from api.models import SequenceCapacityState
from api.sequence_capacity import (
    SEQUENCE_MAX_VALUE,
    SequenceSample,
    collect_sequence_samples,
    record_sequence_capacity,
)


def _sample(name, last_value, max_value=100):
    return SequenceSample(
        sequence_name=f"public.{name}_id_seq",
        table_name=name,
        column_name="id",
        last_value=last_value,
        max_value=max_value,
    )


class BigAutoFieldRuntimeContractTests(TestCase):
    def test_every_api_auto_primary_key_is_64_bit(self):
        auto_models = [
            model
            for model in apps.get_app_config("api").get_models(include_auto_created=True)
            if isinstance(model._meta.pk, models.AutoField)
        ]

        self.assertEqual(len(auto_models), 30)
        self.assertTrue(auto_models)
        self.assertEqual(
            [model._meta.label for model in auto_models if not isinstance(model._meta.pk, models.BigAutoField)],
            [],
        )

    def test_backend_inventory_matches_runtime_auto_primary_keys(self):
        samples = collect_sequence_samples()
        primary_keys_by_table = {
            model._meta.db_table: model._meta.pk.column
            for model in apps.get_app_config("api").get_models(include_auto_created=True)
            if isinstance(model._meta.pk, models.AutoField)
        }

        self.assertEqual(len(samples), 30)
        self.assertEqual(len({sample.sequence_name for sample in samples}), 30)
        self.assertEqual(
            {sample.table_name: sample.column_name for sample in samples},
            primary_keys_by_table,
        )
        self.assertTrue(all(sample.max_value == SEQUENCE_MAX_VALUE for sample in samples))


class SequenceCapacityReportTests(TestCase):
    def test_thresholds_use_exact_integer_arithmetic(self):
        report = record_sequence_capacity(
            (_sample("ok", 79), _sample("warning", 80), _sample("critical", 95)),
            sampled_at=timezone.now(),
            warning_percent=80,
            critical_percent=95,
        )

        by_table = {sequence["table"]: sequence for sequence in report["sequences"]}
        self.assertEqual(report["status"], "critical")
        self.assertEqual(by_table["ok"]["status"], "ok")
        self.assertEqual(by_table["warning"]["reason"], "warning_threshold")
        self.assertEqual(by_table["critical"]["reason"], "critical_threshold")
        self.assertEqual(by_table["warning"]["consumed_ppm"], 800_000)
        self.assertEqual(by_table["critical"]["remaining"], 5)

    def test_growth_eta_and_regression_are_reported(self):
        started_at = timezone.now()
        sample = _sample("growth", 10, max_value=1_000)
        record_sequence_capacity(
            (sample,),
            sampled_at=started_at,
            warning_percent=80,
            critical_percent=95,
        )
        grown = record_sequence_capacity(
            (_sample("growth", 110, max_value=1_000),),
            sampled_at=started_at + timedelta(days=1),
            warning_percent=80,
            critical_percent=95,
        )["sequences"][0]

        self.assertEqual(grown["growth_per_day"], "100.000")
        self.assertEqual(grown["eta_days"], 8)

        regressed = record_sequence_capacity(
            (_sample("growth", 109, max_value=1_000),),
            sampled_at=started_at + timedelta(days=2),
            warning_percent=80,
            critical_percent=95,
        )["sequences"][0]
        self.assertEqual(regressed["status"], "critical")
        self.assertEqual(regressed["reason"], "sequence_regressed")
        self.assertIsNone(regressed["growth_per_day"])
        self.assertIsNone(regressed["eta_days"])

    def test_state_inventory_drops_sequences_that_no_longer_exist(self):
        sampled_at = timezone.now()
        SequenceCapacityState.objects.create(
            sequence_name="public.removed_id_seq",
            last_value=1,
            sampled_at=sampled_at,
        )

        record_sequence_capacity(
            (_sample("current", 2),),
            sampled_at=sampled_at + timedelta(minutes=5),
            warning_percent=80,
            critical_percent=95,
        )

        self.assertEqual(
            list(SequenceCapacityState.objects.values_list("sequence_name", flat=True)),
            ["public.current_id_seq"],
        )

    def test_invalid_or_empty_inventory_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "no application-owned"):
            record_sequence_capacity(
                (),
                sampled_at=timezone.now(),
                warning_percent=80,
                critical_percent=95,
            )
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            record_sequence_capacity(
                (_sample("duplicate", 1), _sample("duplicate", 2)),
                sampled_at=timezone.now(),
                warning_percent=80,
                critical_percent=95,
            )
        with self.assertRaisesRegex(RuntimeError, "invalid database sequence bounds"):
            record_sequence_capacity(
                (_sample("invalid", 101),),
                sampled_at=timezone.now(),
                warning_percent=80,
                critical_percent=95,
            )

    @patch("api.management.commands.check_sequence_capacity.collect_sequence_samples")
    def test_command_fail_levels_and_json_contract(self, collect_samples):
        collect_samples.return_value = (_sample("command", 80),)
        output = StringIO()
        call_command("check_sequence_capacity", fail_level="none", stdout=output)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["status"], "warning")

        with self.assertRaisesRegex(CommandError, "warning status"):
            call_command("check_sequence_capacity", fail_level="warning", stdout=StringIO())
        call_command("check_sequence_capacity", fail_level="critical", stdout=StringIO())

        collect_samples.return_value = (_sample("command", 95),)
        with self.assertRaisesRegex(CommandError, "critical status"):
            call_command("check_sequence_capacity", fail_level="critical", stdout=StringIO())
        call_command("check_sequence_capacity", fail_level="none", stdout=StringIO())
