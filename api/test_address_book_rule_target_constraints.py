import json
import queue
import threading
import uuid

from django.contrib.auth.models import Group
from django.db import IntegrityError, close_old_connections, connection, transaction
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from api.models import AddressBookProfile, AddressBookRule, RemoteDevice, UserProfile
from api.views_api import _issue_access_token


class AddressBookRuleTargetConstraintTests(TestCase):
    def setUp(self):
        self.owner = UserProfile.objects.create_user(username="rule-target-owner")
        self.target_user = UserProfile.objects.create_user(username="rule-target-user")
        self.other_user = UserProfile.objects.create_user(username="rule-target-other-user")
        self.group = Group.objects.create(name="rule-target-group")
        self.other_group = Group.objects.create(name="rule-target-other-group")
        self.profile = AddressBookProfile.objects.create(
            owner=self.owner,
            guid="rule-target-profile",
            name="Rule target profile",
        )

    def _target_cases(self):
        return (
            (
                "user",
                {"user": self.target_user},
                (self.target_user.pk, None, False),
            ),
            (
                "group",
                {"group": self.group},
                (None, self.group.pk, False),
            ),
            (
                "everyone",
                {"is_everyone": True},
                (None, None, True),
            ),
        )

    def test_true_targets_are_unique_for_bulk_and_raw_writes(self):
        for label, target_fields, raw_target in self._target_cases():
            with self.subTest(target=label):
                AddressBookRule.objects.create(
                    profile=self.profile,
                    rule=1,
                    **target_fields,
                )
                with self.assertRaises(IntegrityError):
                    with transaction.atomic():
                        AddressBookRule.objects.bulk_create(
                            [
                                AddressBookRule(
                                    profile=self.profile,
                                    rule=3,
                                    **target_fields,
                                )
                            ]
                        )

                user_id, group_id, is_everyone = raw_target
                now = timezone.now()
                with self.assertRaises(IntegrityError):
                    with transaction.atomic(), connection.cursor() as cursor:
                        cursor.execute(
                            """
                            INSERT INTO api_addressbookrule (
                                guid,
                                profile_id,
                                rule,
                                user_id,
                                group_id,
                                is_everyone,
                                created_at,
                                updated_at
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            [
                                uuid.uuid4().hex,
                                self.profile.pk,
                                3,
                                user_id,
                                group_id,
                                is_everyone,
                                now,
                                now,
                            ],
                        )

    def test_queryset_target_changes_cannot_create_duplicates(self):
        user_rule = AddressBookRule.objects.create(profile=self.profile, user=self.target_user, rule=1)
        other_user_rule = AddressBookRule.objects.create(profile=self.profile, user=self.other_user, rule=2)
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                AddressBookRule.objects.filter(pk=other_user_rule.pk).update(user=self.target_user)

        group_rule = AddressBookRule.objects.create(profile=self.profile, group=self.group, rule=1)
        other_group_rule = AddressBookRule.objects.create(profile=self.profile, group=self.other_group, rule=2)
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                AddressBookRule.objects.filter(pk=other_group_rule.pk).update(group=self.group)

        AddressBookRule.objects.create(profile=self.profile, is_everyone=True, rule=3)
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                AddressBookRule.objects.filter(pk=user_rule.pk).update(
                    user=None,
                    is_everyone=True,
                )

        self.assertEqual(AddressBookRule.objects.filter(profile=self.profile, user=self.target_user).count(), 1)
        self.assertEqual(AddressBookRule.objects.filter(profile=self.profile, group=self.group).count(), 1)
        self.assertEqual(AddressBookRule.objects.filter(profile=self.profile, is_everyone=True).count(), 1)
        self.assertFalse(AddressBookRule.objects.filter(pk=group_rule.pk, group=self.other_group).exists())

    def test_upsert_uses_the_real_target_instead_of_a_derived_key(self):
        group_rule, created = AddressBookRule.objects.update_or_create(
            profile=self.profile,
            group=self.group,
            defaults={"rule": 1, "is_everyone": False, "user": None},
        )
        self.assertTrue(created)
        same_group_rule, created = AddressBookRule.objects.update_or_create(
            profile=self.profile,
            group=self.group,
            defaults={"rule": 3, "is_everyone": False, "user": None},
        )
        self.assertFalse(created)
        self.assertEqual(same_group_rule.pk, group_rule.pk)
        self.assertEqual(same_group_rule.rule, 3)

        everyone_rule, created = AddressBookRule.objects.update_or_create(
            profile=self.profile,
            is_everyone=True,
            defaults={"rule": 1, "user": None, "group": None},
        )
        self.assertTrue(created)
        same_everyone_rule, created = AddressBookRule.objects.update_or_create(
            profile=self.profile,
            is_everyone=True,
            defaults={"rule": 2, "user": None, "group": None},
        )
        self.assertFalse(created)
        self.assertEqual(same_everyone_rule.pk, everyone_rule.pk)
        self.assertEqual(same_everyone_rule.rule, 2)

        self.assertNotIn("target_key", {field.name for field in AddressBookRule._meta.fields})
        self.assertEqual(AddressBookRule.objects.filter(profile=self.profile, group=self.group).count(), 1)
        self.assertEqual(AddressBookRule.objects.filter(profile=self.profile, is_everyone=True).count(), 1)

    def test_api_and_web_upserts_keep_one_row_per_real_target(self):
        device = RemoteDevice.objects.create(
            rid="rule-target-dev",
            uuid="rule-target-uuid",
            owner=self.owner,
            is_active=True,
            cpu="-",
            hostname="-",
            memory="-",
            os="linux",
            username="",
            version="-",
        )
        token = _issue_access_token(self.owner, device)[1]

        generation = 0
        for rule in (1, 3):
            group_response = self.client.post(
                "/api/ab/rule",
                data=json.dumps(
                    {
                        "guid": self.profile.guid,
                        "group": self.group.name,
                        "rule": rule,
                    }
                ),
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {token}",
                HTTP_IDEMPOTENCY_KEY="v2:" + str(uuid.uuid4()),
                HTTP_IF_MATCH=f'"{generation}"',
            )
            generation += 1
            everyone_response = self.client.post(
                "/api/ab/rule",
                data=json.dumps({"guid": self.profile.guid, "rule": rule}),
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {token}",
                HTTP_IDEMPOTENCY_KEY="v2:" + str(uuid.uuid4()),
                HTTP_IF_MATCH=f'"{generation}"',
            )
            generation += 1
            self.assertEqual(group_response.status_code, 200, group_response.content)
            self.assertEqual(everyone_response.status_code, 200, everyone_response.content)

        self.assertEqual(
            AddressBookRule.objects.get(profile=self.profile, group=self.group).rule,
            3,
        )
        self.assertEqual(
            AddressBookRule.objects.get(profile=self.profile, is_everyone=True).rule,
            3,
        )

        web_profile = AddressBookProfile.objects.create(
            owner=self.owner,
            guid="rule-target-web-profile",
            name="Rule target web profile",
        )
        self.client.force_login(self.owner)
        generation = 0
        for rule in (1, 2):
            group_response = self.client.post(
                "/api/ab_manage",
                {
                    "action": "add_group_rule",
                    "profile_guid": web_profile.guid,
                    "group": self.group.name,
                    "rule": rule,
                    "idempotency_key": "v2:" + str(uuid.uuid4()),
                    "expected_generation": str(generation),
                },
            )
            generation += 1
            everyone_response = self.client.post(
                "/api/ab_manage",
                {
                    "action": "add_everyone_rule",
                    "profile_guid": web_profile.guid,
                    "rule": rule,
                    "idempotency_key": "v2:" + str(uuid.uuid4()),
                    "expected_generation": str(generation),
                },
            )
            generation += 1
            self.assertEqual(group_response.status_code, 302, group_response.content)
            self.assertEqual(everyone_response.status_code, 302, everyone_response.content)

        self.assertEqual(
            AddressBookRule.objects.get(profile=web_profile, group=self.group).rule,
            2,
        )
        self.assertEqual(
            AddressBookRule.objects.get(profile=web_profile, is_everyone=True).rule,
            2,
        )
        self.assertEqual(AddressBookRule.objects.filter(profile=web_profile).count(), 2)


class AddressBookRuleTargetConcurrencyTests(TransactionTestCase):
    def setUp(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL is the production concurrency authority")
        self.owner = UserProfile.objects.create_user(username="rule-race-owner")
        self.group = Group.objects.create(name="rule-race-group")
        self.profile = AddressBookProfile.objects.create(
            owner=self.owner,
            guid="rule-race-profile",
            name="Rule race profile",
        )

    def test_two_writers_cannot_commit_the_same_real_target(self):
        start = threading.Barrier(2)
        outcomes = queue.Queue()

        def create_rule(rule):
            close_old_connections()
            try:
                start.wait(timeout=10)
                with transaction.atomic():
                    AddressBookRule.objects.create(
                        profile_id=self.profile.pk,
                        group_id=self.group.pk,
                        rule=rule,
                    )
                outcomes.put("committed")
            except IntegrityError:
                outcomes.put("rejected")
            except Exception as exc:  # noqa: BLE001
                outcomes.put(f"error:{exc!r}")
            finally:
                close_old_connections()

        threads = [threading.Thread(target=create_rule, args=(rule,)) for rule in (1, 3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertTrue(all(not thread.is_alive() for thread in threads), "rule writers deadlocked")
        self.assertEqual(sorted(outcomes.queue), ["committed", "rejected"])
        self.assertEqual(
            AddressBookRule.objects.filter(profile=self.profile, group=self.group).count(),
            1,
        )
