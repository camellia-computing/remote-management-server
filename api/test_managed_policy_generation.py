import base64

from django.test import TestCase

from api.models import DeviceGroup, RemoteDevice, StrategyProfile, UserProfile
from api.policy_generation import (
    MAX_POLICY_GENERATION,
    PolicyGenerationExhausted,
    managed_policy_document,
)


class ManagedPolicyGenerationTests(TestCase):
    def setUp(self):
        self.user = UserProfile.objects.create_user("policy-user", "policy-password")
        self.device_counter = 0

    def device(self, **overrides):
        self.device_counter += 1
        values = {
            "rid": f"70000{self.device_counter:04d}",
            "uuid": base64.b64encode(f"policy-device-{self.device_counter}".encode()).decode(),
            "cpu": "cpu",
            "hostname": "host",
            "memory": "memory",
            "os": "linux",
            "username": "local-user",
            "version": "1.0",
            "owner": self.user,
        }
        values.update(overrides)
        return RemoteDevice.objects.create(**values)

    @staticmethod
    def refresh_generation(device):
        device.refresh_from_db()
        return device.policy_generation

    def test_precedence_fallback_and_tombstone_each_advance_generation(self):
        user_strategy = StrategyProfile.objects.create(
            name="user-policy",
            config_options={"source": "user"},
        )
        group_strategy = StrategyProfile.objects.create(
            name="group-policy",
            config_options={"source": "group"},
        )
        direct_strategy = StrategyProfile.objects.create(
            name="direct-policy",
            config_options={"source": "device"},
        )
        self.user.strategy = user_strategy
        self.user.save(update_fields=["strategy"])
        group = DeviceGroup.objects.create(name="policy-group", strategy=group_strategy)
        device = self.device(device_group=group, strategy=direct_strategy)

        self.assertEqual(device.policy_generation, 0)
        self.assertEqual(managed_policy_document(device)["config_options"], {"source": "device"})

        group_strategy.config_options = {"source": "masked-group"}
        group_strategy.save(update_fields=["config_options"])
        self.assertEqual(self.refresh_generation(device), 0)

        RemoteDevice.objects.filter(pk=device.pk).update(strategy=None)
        self.assertEqual(self.refresh_generation(device), 1)
        self.assertEqual(managed_policy_document(device)["config_options"], {"source": "masked-group"})

        group.strategy = None
        group.save(update_fields=["strategy"])
        self.assertEqual(self.refresh_generation(device), 2)
        self.assertEqual(managed_policy_document(device)["config_options"], {"source": "user"})

        UserProfile.objects.filter(pk=self.user.pk).update(strategy=None)
        self.assertEqual(self.refresh_generation(device), 3)
        policy = managed_policy_document(device)
        self.assertEqual(policy["config_options"], {})
        self.assertEqual(
            policy["digest"],
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        )

    def test_content_key_removal_disable_and_delete_do_not_use_wall_clock(self):
        strategy = StrategyProfile.objects.create(
            name="rapid-policy",
            config_options={"keep": "yes", "remove": "old"},
        )
        device = self.device(strategy=strategy)

        StrategyProfile.objects.filter(pk=strategy.pk).update(config_options={"keep": "first"})
        self.assertEqual(self.refresh_generation(device), 1)
        first = managed_policy_document(device)
        self.assertEqual(first["config_options"], {"keep": "first"})

        StrategyProfile.objects.filter(pk=strategy.pk).update(config_options={"keep": "second"})
        self.assertEqual(self.refresh_generation(device), 2)
        device.refresh_from_db()
        self.assertEqual(managed_policy_document(device)["config_options"], {"keep": "second"})

        strategy.refresh_from_db()
        strategy.enabled = False
        strategy.save(update_fields=["enabled"])
        self.assertEqual(self.refresh_generation(device), 3)
        self.assertEqual(managed_policy_document(device)["config_options"], {})

        StrategyProfile.objects.filter(pk=strategy.pk).delete()
        self.assertEqual(self.refresh_generation(device), 4)
        self.assertIsNone(device.strategy_id)
        self.assertEqual(managed_policy_document(device)["config_options"], {})

    def test_group_and_user_bulk_delete_advance_fallback_generation(self):
        user_strategy = StrategyProfile.objects.create(
            name="delete-user-policy",
            config_options={"source": "user"},
        )
        group_strategy = StrategyProfile.objects.create(
            name="delete-group-policy",
            config_options={"source": "group"},
        )
        self.user.strategy = user_strategy
        self.user.save(update_fields=["strategy"])
        group = DeviceGroup.objects.create(name="delete-group", strategy=group_strategy)
        device = self.device(device_group=group)

        DeviceGroup.objects.filter(pk=group.pk).delete()
        self.assertEqual(self.refresh_generation(device), 1)
        self.assertIsNone(device.device_group_id)
        self.assertEqual(managed_policy_document(device)["config_options"], {"source": "user"})

        UserProfile.objects.filter(pk=self.user.pk).delete()
        self.assertEqual(self.refresh_generation(device), 2)
        self.assertIsNone(device.owner_id)
        self.assertEqual(managed_policy_document(device)["config_options"], {})

    def test_stale_device_save_cannot_move_generation_backward(self):
        first = StrategyProfile.objects.create(
            name="stale-first",
            config_options={"source": "first"},
        )
        second = StrategyProfile.objects.create(
            name="stale-second",
            config_options={"source": "second"},
        )
        device = self.device(strategy=first)
        stale = RemoteDevice.objects.get(pk=device.pk)

        RemoteDevice.objects.filter(pk=device.pk).update(strategy=second)
        self.assertEqual(self.refresh_generation(device), 1)
        stale.hostname = "updated-hostname"
        stale.save()

        self.assertEqual(self.refresh_generation(device), 2)
        self.assertEqual(device.strategy_id, first.pk)
        self.assertEqual(device.hostname, "updated-hostname")

        with self.assertRaisesRegex(ValueError, "managed internally"):
            RemoteDevice.objects.filter(pk=device.pk).update(policy_generation=0)
        self.assertEqual(self.refresh_generation(device), 2)

    def test_generation_exhaustion_rolls_back_content_and_assignment(self):
        strategy = StrategyProfile.objects.create(
            name="exhausted-policy",
            config_options={"mode": "old"},
        )
        group = DeviceGroup.objects.create(name="exhausted-group")
        device = self.device(strategy=strategy)
        RemoteDevice._base_manager.filter(pk=device.pk).update(policy_generation=MAX_POLICY_GENERATION)

        strategy.config_options = {"mode": "new"}
        with self.assertRaises(PolicyGenerationExhausted):
            strategy.save(update_fields=["config_options"])
        strategy.refresh_from_db()
        self.assertEqual(strategy.config_options, {"mode": "old"})

        with self.assertRaises(PolicyGenerationExhausted):
            RemoteDevice.objects.filter(pk=device.pk).update(device_group=group)
        device.refresh_from_db()
        self.assertIsNone(device.device_group_id)
        self.assertEqual(device.policy_generation, MAX_POLICY_GENERATION)

    def test_one_exhausted_device_rolls_back_the_whole_strategy_bulk_update(self):
        strategy = StrategyProfile.objects.create(
            name="bulk-exhausted-policy",
            config_options={"mode": "old"},
        )
        exhausted = self.device(strategy=strategy)
        normal = self.device(strategy=strategy)
        RemoteDevice._base_manager.filter(pk=exhausted.pk).update(policy_generation=MAX_POLICY_GENERATION)

        with self.assertRaises(PolicyGenerationExhausted):
            StrategyProfile.objects.filter(pk=strategy.pk).update(config_options={"mode": "new"})

        strategy.refresh_from_db()
        exhausted.refresh_from_db()
        normal.refresh_from_db()
        self.assertEqual(strategy.config_options, {"mode": "old"})
        self.assertEqual(exhausted.policy_generation, MAX_POLICY_GENERATION)
        self.assertEqual(normal.policy_generation, 0)
