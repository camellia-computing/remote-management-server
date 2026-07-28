import base64
import datetime
import hashlib
import json
from pathlib import Path
import tempfile

from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.contrib.auth.models import Group
from django.test import TestCase, override_settings
from django.utils import timezone
from nacl.signing import SigningKey

from api.models import (
    AddressBookProfile,
    AddressBookRule,
    AlarmLog,
    ConnLog,
    DeviceGroup,
    FileLog,
    LoginAttempt,
    OidcPendingAuth,
    RemoteDevice,
    RemotePeer,
    RemoteTag,
    RemoteToken,
    ShareLink,
    StrategyProfile,
    UserProfile,
)


def device_uuid(label):
    return base64.b64encode(label.encode()).decode()


DEFAULT_DEVICE_UUID = device_uuid("device-uuid")


class ApiTestMixin:
    def setUp(self):
        self.admin = UserProfile.objects.create_user(
            username="admin",
            password="admin-pass",
            is_admin=True,
            is_superuser=True,
        )
        self.user = UserProfile.objects.create_user(
            username="alice",
            password="alice-pass",
            email="alice@example.test",
        )

    def _post_json(self, path, payload, token=None):
        headers = self._auth_headers(token)
        return self.client.post(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )

    def _put_json(self, path, payload, token=None):
        headers = self._auth_headers(token)
        return self.client.put(
            path,
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )

    def _delete_json(self, path, payload=None, token=None):
        headers = self._auth_headers(token)
        return self.client.delete(
            path,
            data=json.dumps(payload if payload is not None else {}),
            content_type="application/json",
            **headers,
        )

    @staticmethod
    def _auth_headers(token):
        return {"HTTP_AUTHORIZATION": f"Bearer {token}"} if token else {}

    def _login(self, username, password, rid="123456789", uuid=DEFAULT_DEVICE_UUID):
        response = self._post_json(
            "/api/login",
            {
                "username": username,
                "password": password,
                "id": rid,
                "uuid": uuid,
                "type": "client",
                "deviceInfo": {
                    "os": "linux",
                    "type": "client",
                    "name": "desktop",
                },
            },
        )
        self.assertEqual(response.status_code, 200, response.content)
        body = response.json()
        self.assertIn("access_token", body)
        return body["access_token"]

    def _device(self, owner=None, rid="123456789", uuid=DEFAULT_DEVICE_UUID, **overrides):
        data = {
            "rid": rid,
            "cpu": "-",
            "hostname": "desktop",
            "memory": "-",
            "os": "linux",
            "uuid": uuid,
            "username": "desktop-user",
            "version": "2.0.0",
            "public_key_hash": hashlib.sha256(uuid.encode()).hexdigest(),
            "owner": owner,
        }
        data.update(overrides)
        return RemoteDevice.objects.create(**data)

    @staticmethod
    def _personal_profile(user):
        profile, _created = AddressBookProfile.objects.get_or_create(
            guid=f"personal-{user.id}",
            defaults={
                "name": "My address book",
                "owner": user,
                "rule": 3,
            },
        )
        return profile


class ApiContractTests(ApiTestMixin, TestCase):
    def test_login_requires_bearer_token_for_current_user(self):
        token = self._login("alice", "alice-pass")
        device = RemoteDevice.objects.get(rid="123456789")
        self.assertEqual(device.hostname, "desktop")
        self.assertEqual(device.os, "linux")
        stored_token = RemoteToken.objects.get(device=device)
        self.assertEqual(len(stored_token.access_token), 64)
        self.assertIsNotNone(stored_token.expires_at)

        query_token_response = self._post_json("/api/currentUser", {"access_token": token})
        self.assertEqual(query_token_response.status_code, 401)

        response = self._post_json("/api/currentUser", {}, token=token)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["name"], "alice")

    def test_failed_login_returns_401_with_error_body(self):
        response = self._post_json(
            "/api/login",
            {"username": "alice", "password": "wrong", "id": "123456789", "uuid": DEFAULT_DEVICE_UUID},
        )
        self.assertEqual(response.status_code, 401)
        self.assertIn("error", response.json())
        self.assertEqual(LoginAttempt.objects.filter(ip="127.0.0.1").count(), 1)

    def test_login_rejects_noncanonical_device_identity(self):
        malformed_values = (
            "not-base64",
            base64.b64encode(b"devices").decode().rstrip("="),
            "",
        )
        for malformed in malformed_values:
            with self.subTest(uuid=malformed):
                response = self._post_json(
                    "/api/login",
                    {
                        "username": "alice",
                        "password": "alice-pass",
                        "id": "123456789",
                        "uuid": malformed,
                    },
                )
                self.assertEqual(response.status_code, 400, response.content)
        self.assertFalse(RemoteToken.objects.exists())

    def test_repeated_login_failures_lock_out_ip(self):
        for _ in range(10):
            self._post_json(
                "/api/login",
                {"username": "alice", "password": "wrong", "id": "123456789", "uuid": DEFAULT_DEVICE_UUID},
            )
        locked = self._post_json(
            "/api/login",
            {"username": "alice", "password": "alice-pass", "id": "123456789", "uuid": DEFAULT_DEVICE_UUID},
        )
        self.assertEqual(locked.status_code, 429)
        self.assertIn("error", locked.json())

    def test_successful_login_clears_failures_and_stores_hashed_token(self):
        self._post_json(
            "/api/login",
            {"username": "alice", "password": "wrong", "id": "123456789", "uuid": DEFAULT_DEVICE_UUID},
        )
        token = self._login("alice", "alice-pass")
        self.assertEqual(LoginAttempt.objects.count(), 0)

        stored = RemoteToken.objects.get(device__owner=self.user)
        self.assertNotEqual(stored.access_token, token)
        self.assertEqual(stored.access_token, hashlib.sha256(token.encode()).hexdigest())

        # currentUser echoes the presented raw token, never the stored hash.
        response = self._post_json("/api/currentUser", {}, token=token)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["access_token"], token)

    def test_relogin_rotates_the_stored_token(self):
        first = self._login("alice", "alice-pass")
        second = self._login("alice", "alice-pass")
        self.assertNotEqual(first, second)

        stale = self._post_json("/api/currentUser", {}, token=first)
        self.assertEqual(stale.status_code, 401)
        fresh = self._post_json("/api/currentUser", {}, token=second)
        self.assertEqual(fresh.status_code, 200, fresh.content)

    def test_oidc_auth_query_reads_state_from_database(self):
        # Simulates the callback having completed on a different worker: the
        # pending state lives in the DB, not in process memory.
        poll_code = "test-poll-code"
        OidcPendingAuth.objects.create(
            state="test-state",
            poll_code_hash=hashlib.sha256(poll_code.encode()).hexdigest(),
            provider="example",
            rid="123456789",
            device_uuid=DEFAULT_DEVICE_UUID,
            nonce="test-nonce",
            code_verifier="test-code-verifier",
            status=OidcPendingAuth.STATUS_DONE,
            authenticated_user=self.user,
        )
        self.assertNotEqual(poll_code, "test-state")
        self.assertNotIn(poll_code, OidcPendingAuth.objects.get().poll_code_hash)

        state_is_not_a_poll_secret = self.client.get("/api/oidc/auth-query?code=test-state")
        self.assertNotIn("access_token", state_is_not_a_poll_secret.json())
        response = self.client.get(f"/api/oidc/auth-query?code={poll_code}")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("access_token", response.json())
        self.assertNotEqual(response.json()["access_token"], poll_code)
        self.assertFalse(OidcPendingAuth.objects.filter(state="test-state").exists())

    def test_telemetry_requires_the_token_bound_to_that_device(self):
        response = self._post_json(
            "/api/heartbeat",
            {"id": "x" * 200, "uuid": DEFAULT_DEVICE_UUID},
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(RemoteDevice.objects.exists())

        self._device(owner=self.user)
        token = self._login("alice", "alice-pass")
        unauthenticated = self._post_json(
            "/api/sysinfo",
            {"id": "123456789", "uuid": DEFAULT_DEVICE_UUID, "hostname": "desktop"},
        )
        self.assertEqual(unauthenticated.status_code, 401)
        wrong_device = self._post_json(
            "/api/sysinfo",
            {"id": "987654321", "uuid": device_uuid("other-device"), "hostname": "desktop"},
            token=token,
        )
        self.assertEqual(wrong_device.status_code, 401)

        sysinfo = self._post_json(
            "/api/sysinfo",
            {"id": "123456789", "uuid": DEFAULT_DEVICE_UUID, "hostname": "desktop"},
            token=token,
        )
        self.assertEqual(sysinfo.status_code, 200, sysinfo.content)
        self.assertTrue(RemoteDevice.objects.filter(rid="123456789").exists())
        heartbeat = self._post_json(
            "/api/heartbeat",
            {"id": "123456789", "uuid": DEFAULT_DEVICE_UUID},
            token=token,
        )
        self.assertEqual(heartbeat.status_code, 200, heartbeat.content)

    def test_address_book_peers_match_flutter_client_contract(self):
        token = self._login("alice", "alice-pass")
        profile = self._personal_profile(self.user)
        peer = RemotePeer.objects.create(
            profile=profile,
            rid="765432100",
            username="mira",
            hostname="studio-mac",
            platform="Mac OS",
            alias="Design workstation",
            note="Primary workstation",
            device_group_name="Design",
            login_name="mira@example.test",
            same_server=True,
            rhash="personal-hash",
        )
        tags = [
            RemoteTag.objects.create(
                profile=profile,
                tag_name=name,
            )
            for name in ("studio", "trusted")
        ]
        peer.tags.set(tags)

        response = self._post_json(
            "/api/ab/peers?current=1&pageSize=100",
            {},
            token=token,
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["total"], 1)
        self.assertEqual(
            response.json()["data"][0],
            {
                "id": "765432100",
                "username": "mira",
                "hostname": "studio-mac",
                "platform": "Mac OS",
                "alias": "Design workstation",
                "tags": ["studio", "trusted"],
                "note": "Primary workstation",
                "device_group_name": "Design",
                "loginName": "mira@example.test",
                "same_server": True,
                "hash": "personal-hash",
                "password": "",
            },
        )

    def test_address_book_tag_relations_survive_merge_and_reject_cross_book_links(self):
        token = self._login("alice", "alice-pass")
        profile = self._personal_profile(self.user)
        peer = RemotePeer.objects.create(
            profile=profile,
            rid="765432100",
        )
        old_tag = RemoteTag.objects.create(
            profile=profile,
            tag_name="old",
        )
        target_tag = RemoteTag.objects.create(
            profile=profile,
            tag_name="target",
        )
        peer.tags.add(old_tag)

        renamed = self._put_json(
            f"/api/ab/tag/rename/{profile.guid}",
            {"old": "old", "new": "target"},
            token=token,
        )

        self.assertEqual(renamed.status_code, 200, renamed.content)
        self.assertFalse(RemoteTag.objects.filter(profile=profile, tag_name="old").exists())
        self.assertEqual(
            list(peer.tags.values_list("tag_name", flat=True)),
            ["target"],
        )

        other_profile = AddressBookProfile.objects.create(
            owner=self.user,
            guid="separate-address-book",
            name="Separate",
            rule=3,
        )
        foreign_tag = RemoteTag.objects.create(
            profile=other_profile,
            tag_name="foreign",
        )
        with self.assertRaises(ValidationError):
            with transaction.atomic():
                peer.tags.add(foreign_tag)

        deleted = self._delete_json(
            f"/api/ab/tag/{profile.guid}",
            ["target"],
            token=token,
        )
        self.assertEqual(deleted.status_code, 200, deleted.content)
        self.assertFalse(peer.tags.exists())
        self.assertFalse(RemoteTag.objects.filter(pk=target_tag.pk).exists())

    def test_address_book_credentials_are_authenticated_encrypted_at_rest(self):
        profile = self._personal_profile(self.user)
        first = RemotePeer.objects.create(
            profile=profile,
            rid="765432100",
            rhash="same-sensitive-value",
            password="same-sensitive-value",
        )
        second = RemotePeer.objects.create(
            profile=profile,
            rid="765432101",
            rhash="same-sensitive-value",
        )
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT rhash, password FROM api_remotepeer WHERE id = %s",
                [first.pk],
            )
            raw_rhash, raw_password = cursor.fetchone()
            cursor.execute(
                "SELECT rhash FROM api_remotepeer WHERE id = %s",
                [second.pk],
            )
            second_raw_rhash = cursor.fetchone()[0]
        self.assertTrue(raw_rhash.startswith("secretbox:v1:"))
        self.assertTrue(raw_password.startswith("secretbox:v1:"))
        self.assertNotIn("same-sensitive-value", raw_rhash)
        self.assertNotEqual(raw_rhash, raw_password)
        self.assertNotEqual(raw_rhash, second_raw_rhash)

        first.refresh_from_db()
        self.assertEqual(first.rhash, "same-sensitive-value")
        self.assertEqual(first.password, "same-sensitive-value")

        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE api_remotepeer SET rhash = %s WHERE id = %s",
                ["secretbox:v1:AAAA", first.pk],
            )
        with self.assertRaises(ValidationError):
            first.refresh_from_db()

    def test_admin_can_manage_users_and_disabled_users_cannot_login(self):
        admin_token = self._login(
            "admin",
            "admin-pass",
            rid="900000001",
            uuid=device_uuid("admin-device"),
        )

        created = self._post_json(
            "/api/users",
            {
                "name": "bob",
                "password": "Bob-API-test-4e!9",
                "email": "bob@example.test",
                "group_name": "ops",
            },
            token=admin_token,
        )
        self.assertEqual(created.status_code, 200, created.content)
        user_guid = created.json()["guid"]

        duplicate = self._post_json(
            "/api/users",
            {"name": "bob", "password": "Bob-API-test-4e!9"},
            token=admin_token,
        )
        self.assertEqual(duplicate.status_code, 409)

        listed = self.client.get("/api/users?name=bob", **self._auth_headers(admin_token))
        self.assertEqual(listed.status_code, 200, listed.content)
        self.assertEqual(listed.json()["total"], 1)
        self.assertEqual(listed.json()["data"][0]["group_name"], "ops")
        self.assertEqual(listed.json()["data"][0]["group_names"], ["ops"])
        self.assertEqual(
            list(UserProfile.objects.get(username="bob").groups.values_list("name", flat=True)),
            ["ops"],
        )

        disabled = self._post_json(f"/api/users/{user_guid}/disable", {}, token=admin_token)
        self.assertEqual(disabled.status_code, 200, disabled.content)
        denied = self._post_json(
            "/api/login",
            {
                "username": "bob",
                "password": "Bob-API-test-4e!9",
                "id": "800000001",
                "uuid": device_uuid("bob-device"),
            },
        )
        # Inactive and unknown accounts deliberately share the same response so
        # the login endpoint does not become an account-status oracle.
        self.assertEqual(denied.status_code, 401)

        enabled = self._post_json(f"/api/users/{user_guid}/enable", {}, token=admin_token)
        self.assertEqual(enabled.status_code, 200, enabled.content)
        self.assertTrue(enabled.json()["status"])

    def test_real_user_group_membership_grants_address_book_rule_access(self):
        group = Group.objects.create(name="design")
        recipient = UserProfile.objects.create_user(
            username="bob",
            password="bob-pass",
        )
        recipient.groups.add(group)
        profile = AddressBookProfile.objects.create(
            owner=self.user,
            guid="team-design",
            name="Design team",
            rule=3,
        )
        AddressBookRule.objects.create(
            profile=profile,
            group=group,
            rule=1,
        )
        RemotePeer.objects.create(
            profile=profile,
            rid="765432100",
            alias="Design workstation",
        )
        token = self._login(
            "bob",
            "bob-pass",
            rid="800000001",
            uuid=device_uuid("bob-device"),
        )

        profiles = self._post_json(
            "/api/ab/shared/profiles",
            {},
            token=token,
        )
        peers = self._post_json(
            f"/api/ab/peers?ab={profile.guid}",
            {},
            token=token,
        )

        self.assertEqual(profiles.status_code, 200, profiles.content)
        self.assertEqual(
            profiles.json()["data"],
            [
                {
                    "guid": "team-design",
                    "name": "Design team",
                    "owner": "alice",
                    "note": "",
                    "info": {},
                    "rule": 1,
                }
            ],
        )
        self.assertEqual(peers.status_code, 200, peers.content)
        self.assertEqual(peers.json()["data"][0]["id"], "765432100")

    def test_accessible_inventory_never_joins_an_unowned_device_by_id(self):
        foreign_owner = UserProfile.objects.create_user(
            username="bob",
            password="bob-pass",
        )
        foreign_group = DeviceGroup.objects.create(name="foreign-group")
        self._device(
            owner=foreign_owner,
            rid="765432100",
            uuid=device_uuid("foreign-device"),
            hostname="private-hostname",
            username="private-user",
            device_group=foreign_group,
        )
        personal_profile = self._personal_profile(self.user)
        RemotePeer.objects.create(
            profile=personal_profile,
            rid="765432100",
            hostname="address-book-hostname",
            username="address-book-user",
            device_group_name="local-label",
        )
        token = self._login("alice", "alice-pass")
        own_group = DeviceGroup.objects.create(name="own-group")
        own_device = RemoteDevice.objects.get(rid="123456789")
        own_device.device_group = own_group
        own_device.save(update_fields=["device_group"])
        RemoteDevice.objects.filter(pk=own_device.pk).update(
            update_time=timezone.now() - datetime.timedelta(days=1),
        )

        peers = self.client.get(
            "/api/peers?status=1",
            **self._auth_headers(token),
        )
        groups = self.client.get(
            "/api/device-group/accessible",
            **self._auth_headers(token),
        )

        self.assertEqual(peers.status_code, 200, peers.content)
        peer_items = {item["id"]: item for item in peers.json()["data"]}
        self.assertEqual(
            set(peer_items),
            {"123456789", "765432100"},
        )
        self.assertEqual(
            peer_items["765432100"]["info"],
            {
                "username": "address-book-user",
                "os": "",
                "device_name": "address-book-hostname",
            },
        )
        self.assertEqual(
            peer_items["765432100"]["device_group_name"],
            "local-label",
        )
        self.assertEqual(peer_items["765432100"]["user"], "alice")
        self.assertEqual(groups.status_code, 200, groups.content)
        self.assertEqual(
            [item["name"] for item in groups.json()["data"]],
            ["own-group"],
        )

    def test_device_groups_and_strategies_drive_heartbeat_contract(self):
        admin_token = self._login(
            "admin",
            "admin-pass",
            rid="900000001",
            uuid=device_uuid("admin-device"),
        )
        self._device(owner=self.user)
        device_token = self._login("alice", "alice-pass")

        created_group = self._post_json(
            "/api/device-groups",
            {
                "name": "ops",
                "note": "Operations devices",
                "allowed_incomings": ["admin"],
            },
            token=admin_token,
        )
        self.assertEqual(created_group.status_code, 200, created_group.content)
        group_guid = created_group.json()["guid"]

        assigned_devices = self._post_json(
            f"/api/device-groups/{group_guid}",
            ["123456789"],
            token=admin_token,
        )
        self.assertEqual(assigned_devices.status_code, 200, assigned_devices.content)
        self.assertEqual(assigned_devices.json()["updated"], 1)

        strategy = StrategyProfile.objects.create(
            name="high-quality",
            config_options={"quality": "best", "enable-audio": "Y"},
        )
        assigned_strategy = self._post_json(
            "/api/strategies/assign",
            {"strategy": str(strategy.guid), "groups": [group_guid]},
            token=admin_token,
        )
        self.assertEqual(assigned_strategy.status_code, 200, assigned_strategy.content)
        self.assertEqual(assigned_strategy.json()["groups"], 1)

        heartbeat = self._post_json(
            "/api/heartbeat",
            {"id": "123456789", "uuid": DEFAULT_DEVICE_UUID, "modified_at": 0},
            token=device_token,
        )
        self.assertEqual(heartbeat.status_code, 200, heartbeat.content)
        self.assertEqual(heartbeat.json()["strategy"]["config_options"]["quality"], "best")

        disabled = self._put_json(
            f"/api/strategies/{strategy.guid}/status",
            {"enabled": False},
            token=admin_token,
        )
        self.assertEqual(disabled.status_code, 200, disabled.content)
        self.assertFalse(disabled.json()["enabled"])

        heartbeat = self._post_json(
            "/api/heartbeat",
            {"id": "123456789", "uuid": DEFAULT_DEVICE_UUID, "modified_at": 0},
            token=device_token,
        )
        self.assertEqual(heartbeat.status_code, 200, heartbeat.content)
        self.assertNotIn("strategy", heartbeat.json())

    def test_strategy_precedence_and_device_policy_is_admin_only(self):
        admin_token = self._login(
            "admin",
            "admin-pass",
            rid="900000001",
            uuid=device_uuid("admin-device"),
        )
        device = self._device(owner=self.user)
        device_token = self._login("alice", "alice-pass")
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
        group = DeviceGroup.objects.create(
            name="ops",
            strategy=group_strategy,
        )
        device.device_group = group
        device.strategy = direct_strategy
        device.save(update_fields=["device_group", "strategy"])
        self.user.strategy = user_strategy
        self.user.save(update_fields=["strategy"])

        heartbeat = self._post_json(
            "/api/heartbeat",
            {
                "id": device.rid,
                "uuid": device.uuid,
                "modified_at": 0,
            },
            token=device_token,
        )
        self.assertEqual(
            heartbeat.json()["strategy"]["config_options"]["source"],
            "device",
        )

        cleared = self._post_json(
            f"/api/devices/{device.pk}/assign",
            {"type": "strategy_name", "value": ""},
            token=admin_token,
        )
        self.assertEqual(cleared.status_code, 200, cleared.content)
        heartbeat = self._post_json(
            "/api/heartbeat",
            {
                "id": device.rid,
                "uuid": device.uuid,
                "modified_at": 0,
            },
            token=device_token,
        )
        self.assertEqual(
            heartbeat.json()["strategy"]["config_options"]["source"],
            "group",
        )

        group.strategy = None
        group.save(update_fields=["strategy"])
        heartbeat = self._post_json(
            "/api/heartbeat",
            {
                "id": device.rid,
                "uuid": device.uuid,
                "modified_at": 0,
            },
            token=device_token,
        )
        self.assertEqual(
            heartbeat.json()["strategy"]["config_options"]["source"],
            "user",
        )

        ignored = self._post_json(
            "/api/sysinfo",
            {
                "id": device.rid,
                "uuid": device.uuid,
                "strategy_name": direct_strategy.name,
                "device_group_name": "other",
            },
            token=device_token,
        )
        self.assertEqual(ignored.status_code, 200, ignored.content)
        device.refresh_from_db()
        self.assertIsNone(device.strategy_id)
        self.assertEqual(device.device_group_id, group.id)

    def test_disabled_devices_are_blocked_by_login_and_heartbeat(self):
        device = self._device(owner=self.user)
        token = self._login("alice", "alice-pass")
        device.is_active = False
        device.save(update_fields=["is_active"])

        login = self._post_json(
            "/api/login",
            {
                "username": "alice",
                "password": "alice-pass",
                "id": "123456789",
                "uuid": DEFAULT_DEVICE_UUID,
            },
        )
        self.assertEqual(login.status_code, 403)

        heartbeat = self._post_json(
            "/api/heartbeat",
            {"id": "123456789", "uuid": DEFAULT_DEVICE_UUID},
            token=token,
        )
        self.assertEqual(heartbeat.status_code, 403)

    @override_settings(DEVICE_VERIFICATION_TOKEN="v" * 48)
    def test_device_deployment_is_bound_to_uuid_key_and_active_owner(self):
        managed_uuid = base64.b64encode(b"managed-device").decode()
        token = self._login("alice", "alice-pass", uuid=managed_uuid)
        public_key = base64.b64encode(bytes(range(32))).decode()
        deployed = self._post_json(
            "/api/devices/deploy",
            {"id": "123456789", "uuid": managed_uuid, "pk": public_key},
            token=token,
        )
        self.assertEqual(deployed.status_code, 200, deployed.content)
        device = RemoteDevice.objects.get(rid="123456789")
        self.assertEqual(device.uuid, managed_uuid)
        self.assertEqual(device.public_key_hash, hashlib.sha256(bytes(range(32))).hexdigest())

        payload = {
            "id": device.rid,
            "uuid": device.uuid,
            "public_key_hash": device.public_key_hash,
        }
        self.assertEqual(self._post_json("/api/devices/verify-deployment", payload).status_code, 401)
        verified = self._post_json(
            "/api/devices/verify-deployment",
            payload,
            token="v" * 48,
        )
        self.assertEqual(verified.status_code, 204, verified.content)

        payload["public_key_hash"] = "0" * 64
        denied = self._post_json(
            "/api/devices/verify-deployment",
            payload,
            token="v" * 48,
        )
        self.assertEqual(denied.status_code, 404)

        admin_token = self._login(
            "admin",
            "admin-pass",
            rid="900000001",
            uuid=device_uuid("admin-device"),
        )
        disabled = self._post_json(f"/api/devices/{device.pk}/disable", {}, token=admin_token)
        self.assertEqual(disabled.status_code, 200, disabled.content)
        payload["public_key_hash"] = device.public_key_hash
        revoked = self._post_json(
            "/api/devices/verify-deployment",
            payload,
            token="v" * 48,
        )
        self.assertEqual(revoked.status_code, 404)
        self.assertFalse(RemoteToken.objects.filter(access_token=hashlib.sha256(token.encode()).hexdigest()).exists())

    @override_settings(DEVICE_VERIFICATION_TOKEN="v" * 48)
    def test_device_deployment_rejects_noncanonical_identity_and_id_takeover(self):
        first_uuid = base64.b64encode(b"first-device").decode()
        token = self._login("alice", "alice-pass", uuid=first_uuid)
        public_key = base64.b64encode(bytes(range(32))).decode()
        malformed = self._post_json(
            "/api/devices/deploy",
            {"id": "123456789", "uuid": "not-base64", "pk": public_key},
            token=token,
        )
        self.assertEqual(malformed.status_code, 400)

        first = self._post_json(
            "/api/devices/deploy",
            {"id": "123456789", "uuid": first_uuid, "pk": public_key},
            token=token,
        )
        self.assertEqual(first.status_code, 200, first.content)

        bob = UserProfile.objects.create_user(username="bob", password="bob-pass")
        second_uuid = base64.b64encode(b"second-device").decode()
        bob_token = self._login(
            bob.username,
            "bob-pass",
            rid="777777777",
            uuid=second_uuid,
        )
        takeover = self._post_json(
            "/api/devices/deploy",
            {
                "id": "123456789",
                "uuid": second_uuid,
                "pk": base64.b64encode(bytes(reversed(range(32)))).decode(),
            },
            token=bob_token,
        )
        self.assertEqual(takeover.status_code, 409)

    def test_administrator_cannot_impersonate_an_owned_device(self):
        device = self._device(owner=self.user)

        login = self._post_json(
            "/api/login",
            {
                "username": "admin",
                "password": "admin-pass",
                "id": device.rid,
                "uuid": device.uuid,
            },
        )
        self.assertEqual(login.status_code, 403, login.content)
        self.assertFalse(
            RemoteToken.objects.filter(
                device__owner=self.admin,
                device__rid=device.rid,
                device__uuid=device.uuid,
            ).exists()
        )

    def test_inactive_owner_invalidates_device_heartbeat(self):
        device = self._device(owner=self.user)
        token = self._login("alice", "alice-pass")
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        response = self._post_json(
            "/api/heartbeat",
            {"id": device.rid, "uuid": device.uuid},
            token=token,
        )
        self.assertEqual(response.status_code, 401, response.content)
        self.assertFalse(RemoteToken.objects.filter(device__owner=self.user).exists())

    def test_plugin_sign_requires_configured_signing_key(self):
        admin_token = self._login(
            "admin",
            "admin-pass",
            rid="900000001",
            uuid=device_uuid("admin-device"),
        )
        response = self._post_json(
            "/lic/web/api/plugin-sign",
            {"msg": [1, 2, 3], "plugin_id": "sample", "version": "1.0.0"},
            token=admin_token,
        )
        self.assertEqual(response.status_code, 503)

    @override_settings(ALLOW_REGISTRATION=True)
    def test_first_public_registration_never_bootstraps_an_administrator(self):
        UserProfile.objects.all().delete()
        response = self.client.post(
            "/api/user_action?action=register",
            {
                "user": "first-user",
                "pwd": "strong-pass",
                "repassword": "strong-pass",
            },
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["code"], 1)
        user = UserProfile.objects.get(username="first-user")
        self.assertFalse(user.is_admin)
        self.assertFalse(user.is_superuser)

        mismatch = self.client.post(
            "/api/user_action?action=register",
            {
                "user": "second-user",
                "pwd": "strong-pass",
                "repassword": "different-pass",
            },
        )
        self.assertEqual(mismatch.status_code, 400, mismatch.content)
        self.assertEqual(mismatch.json()["code"], 0)
        self.assertFalse(UserProfile.objects.filter(username="second-user").exists())

    @override_settings(PLUGIN_SIGNING_KEY=SigningKey.generate().encode().hex())
    def test_plugin_sign_is_an_admin_only_operation(self):
        user_token = self._login("alice", "alice-pass")
        admin_token = self._login(
            "admin",
            "admin-pass",
            rid="900000001",
            uuid=device_uuid("admin-device"),
        )
        payload = {"msg": [1, 2, 3], "plugin_id": "sample", "version": "1.0.0"}

        self.assertEqual(self._post_json("/lic/web/api/plugin-sign", payload).status_code, 401)
        self.assertEqual(
            self._post_json("/lic/web/api/plugin-sign", payload, token=user_token).status_code,
            403,
        )
        signed = self._post_json("/lic/web/api/plugin-sign", payload, token=admin_token)
        self.assertEqual(signed.status_code, 200, signed.content)
        self.assertEqual(len(signed.json()["signed_msg"]), 67)

    def test_device_group_delete_detaches_devices(self):
        admin_token = self._login(
            "admin",
            "admin-pass",
            rid="900000001",
            uuid=device_uuid("admin-device"),
        )
        group = DeviceGroup.objects.create(name="ops")
        device = self._device(owner=self.user, device_group=group)

        response = self._delete_json(f"/api/device-groups/{group.guid}", token=admin_token)
        self.assertEqual(response.status_code, 200, response.content)
        device.refresh_from_db()
        self.assertIsNone(device.device_group_id)

    @override_settings(
        STORAGES={
            "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
            "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
        }
    )
    def test_front_device_page_uses_modern_device_owner_relation(self):
        self._device(
            owner=self.user,
            rid="765432100",
            uuid=device_uuid("owned-device"),
        )
        self.client.force_login(self.user)

        response = self.client.get("/api/work")

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.context["page_obj"].paginator.count, 1)
        self.assertContains(response, "765432100")

    @override_settings(
        STORAGES={
            "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
            "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
        }
    )
    def test_front_device_pages_merge_legacy_metadata_and_expose_unknown_state(self):
        self._device(
            owner=self.user,
            rid="765432100",
            uuid=device_uuid("owned-device"),
        )
        personal_profile = self._personal_profile(self.user)
        work_tag = RemoteTag.objects.create(
            profile=personal_profile,
            tag_name="work",
        )
        mobile_tag = RemoteTag.objects.create(
            profile=personal_profile,
            tag_name="mobile",
        )
        primary_peer = RemotePeer.objects.create(
            profile=personal_profile,
            rid="765432100",
            username="desktop-user",
            hostname="desktop",
            alias="Primary desktop",
            platform="Linux",
            rhash="secret-hash",
        )
        address_book_peer = RemotePeer.objects.create(
            profile=personal_profile,
            rid="765432101",
            username="address-book-user",
            hostname="unknown",
            alias="Address book only",
            platform="Android",
            rhash="",
        )
        primary_peer.tags.add(work_tag)
        address_book_peer.tags.add(mobile_tag)
        self.client.force_login(self.user)

        work_response = self.client.get("/api/work")
        home_response = self.client.get("/api/home")

        self.assertEqual(work_response.status_code, 200, work_response.content)
        items = {item["rid"]: item for item in work_response.context["page_obj"]}
        self.assertEqual(set(items), {"765432100", "765432101"})
        self.assertEqual(items["765432100"]["alias"], "Primary desktop")
        self.assertEqual(items["765432100"]["platform"], "Linux")
        self.assertEqual(items["765432101"]["status"], "未知状态")
        self.assertEqual(home_response.context["summary"], {"total": 2, "online": 1, "offline": 0, "unknown": 1})

    @override_settings(
        STORAGES={
            "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
            "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
        }
    )
    def test_share_link_is_hashed_preview_only_and_single_use(self):
        profile = self._personal_profile(self.user)
        peer = RemotePeer.objects.create(
            profile=profile,
            rid="765432100",
            alias="Studio",
            rhash="shared-credential",
        )
        source_tag = RemoteTag.objects.create(
            profile=profile,
            tag_name="studio",
        )
        peer.tags.add(source_tag)
        self.client.force_login(self.user)
        created = self.client.post(
            "/api/share",
            {"data": json.dumps([{"value": str(peer.pk), "title": "ignored"}])},
        )
        self.assertEqual(created.status_code, 200, created.content)
        raw_token = created.json()["token"]
        link = ShareLink.objects.get()
        self.assertNotEqual(link.shash, raw_token)
        self.assertEqual(link.shash, hashlib.sha256(raw_token.encode()).hexdigest())
        self.assertEqual(
            list(link.peers.values_list("pk", flat=True)),
            [peer.pk],
        )

        recipient = UserProfile.objects.create_user(username="bob", password="bob-pass")
        self.client.force_login(recipient)
        preview = self.client.get(f"/api/share/{raw_token}")
        self.assertEqual(preview.status_code, 200, preview.content)
        link.refresh_from_db()
        self.assertFalse(link.is_used)
        self.assertFalse(
            RemotePeer.objects.filter(
                profile__owner=recipient,
                rid=peer.rid,
            ).exists()
        )

        accepted = self.client.post(f"/api/share/{raw_token}")
        self.assertEqual(accepted.status_code, 200, accepted.content)
        link.refresh_from_db()
        self.assertTrue(link.is_used)
        self.assertEqual(link.used_by, recipient)
        imported = RemotePeer.objects.get(
            profile__owner=recipient,
            rid=peer.rid,
        )
        self.assertEqual(imported.rhash, "shared-credential")
        imported_tag = imported.tags.get()
        self.assertEqual(imported_tag.tag_name, "studio")
        self.assertEqual(imported_tag.profile.owner, recipient)

        replay = self.client.post(f"/api/share/{raw_token}")
        self.assertEqual(replay.status_code, 404)


class SessionIntegrityTests(ApiTestMixin, TestCase):
    """Regressions for defects that let a session outlive its owner's intent."""

    def test_logout_revokes_the_device_that_asked(self):
        desktop_uuid = device_uuid("desktop")
        phone_uuid = device_uuid("phone")
        desktop = self._login("alice", "alice-pass", rid="111111111", uuid=desktop_uuid)
        phone = self._login("alice", "alice-pass", rid="222222222", uuid=phone_uuid)
        self.assertEqual(
            RemoteToken.objects.filter(device__owner=self.user).count(),
            2,
        )

        logout = self._post_json(
            "/api/logout",
            {"id": "111111111", "uuid": desktop_uuid},
            token=desktop,
        )
        self.assertEqual(logout.status_code, 200, logout.content)

        # The desktop is signed out ...
        self.assertEqual(self._post_json("/api/currentUser", {}, token=desktop).status_code, 401)
        # ... and the phone, which never asked, is still signed in.
        self.assertEqual(self._post_json("/api/currentUser", {}, token=phone).status_code, 200)

    def test_logout_cannot_revoke_a_device_by_public_identifiers(self):
        desktop_uuid = device_uuid("desktop")
        token = self._login("alice", "alice-pass", rid="111111111", uuid=desktop_uuid)
        denied = self._post_json(
            "/api/logout",
            {"id": "111111111", "uuid": desktop_uuid},
        )
        self.assertEqual(denied.status_code, 401)
        self.assertEqual(self._post_json("/api/currentUser", {}, token=token).status_code, 200)

    def test_one_token_row_per_device(self):
        desktop_uuid = device_uuid("desktop")
        first = self._login("alice", "alice-pass", rid="111111111", uuid=desktop_uuid)
        second = self._login("alice", "alice-pass", rid="111111111", uuid=desktop_uuid)

        # Re-login rotates in place instead of leaving an unrevokable second row.
        self.assertEqual(
            RemoteToken.objects.filter(
                device__owner=self.user,
                device__rid="111111111",
                device__uuid=desktop_uuid,
            ).count(),
            1,
        )
        self.assertEqual(self._post_json("/api/currentUser", {}, token=first).status_code, 401)
        self.assertEqual(self._post_json("/api/currentUser", {}, token=second).status_code, 200)

    def test_auth_body_carries_the_info_the_desktop_client_requires(self):
        response = self._post_json(
            "/api/login",
            {
                "username": "alice",
                "password": "alice-pass",
                "id": "123456789",
                "uuid": DEFAULT_DEVICE_UUID,
            },
        )
        user = response.json()["user"]
        # UserPayload has no default for `info`; omitting it makes the whole body
        # fail to deserialise and silently discards a successful OIDC login.
        self.assertIn("info", user)
        self.assertIn("login_device_whitelist", user["info"])

    @override_settings(TRUST_PROXY_HEADERS=False)
    def test_forwarded_headers_cannot_choose_the_rate_limit_bucket(self):
        # Every attempt claims a different forwarded address; with the header
        # untrusted they all land in the same bucket and still trip the lockout.
        for spoofed in range(10):
            self.client.post(
                "/api/login",
                data=json.dumps(
                    {
                        "username": "alice",
                        "password": "wrong",
                        "id": "123456",
                        "uuid": DEFAULT_DEVICE_UUID,
                    }
                ),
                content_type="application/json",
                HTTP_X_FORWARDED_FOR=f"198.51.100.{spoofed}",
            )
        locked = self.client.post(
            "/api/login",
            data=json.dumps(
                {
                    "username": "alice",
                    "password": "alice-pass",
                    "id": "123456",
                    "uuid": DEFAULT_DEVICE_UUID,
                }
            ),
            content_type="application/json",
            HTTP_X_FORWARDED_FOR="203.0.113.9",
        )
        self.assertEqual(locked.status_code, 429)

    def test_out_of_range_pagination_is_clamped(self):
        token = self._login("alice", "alice-pass")
        for query in ("current=0", "current=-5", "pageSize=-1", "current=0&pageSize=0"):
            response = self._post_json(
                f"/api/ab/peers?{query}",
                {},
                token=token,
            )
            self.assertEqual(response.status_code, 200, f"{query}: {response.content}")


class SensitiveIngestionTests(ApiTestMixin, TestCase):
    def _raw_record(self, query, body, token=None):
        return self.client.post(
            f"/api/record?{query}",
            data=body,
            content_type="application/octet-stream",
            **self._auth_headers(token),
        )

    def test_record_upload_is_authenticated_sequential_and_device_isolated(self):
        self._device(owner=self.user)
        token = self._login("alice", "alice-pass")
        with tempfile.TemporaryDirectory() as upload_root:
            with self.settings(
                RECORD_UPLOAD_ROOT=Path(upload_root),
                RECORD_UPLOAD_MAX_CHUNK_BYTES=1024,
                RECORD_UPLOAD_MAX_FILE_BYTES=2048,
                DATA_UPLOAD_MAX_MEMORY_SIZE=1024,
            ):
                self.assertEqual(
                    self._raw_record("type=new&file=session.webm", b"").status_code,
                    401,
                )
                created = self._raw_record("type=new&file=session.webm", b"", token)
                self.assertEqual(created.status_code, 200, created.content)
                traversal = self._raw_record("type=new&file=../session.webm", b"", token)
                self.assertEqual(traversal.status_code, 400)

                from api.views_api import _record_file_lock

                recording = next(Path(upload_root).glob("*/session.webm"))
                with _record_file_lock(recording.parent, "session.webm"):
                    busy = self._raw_record(
                        "type=part&file=session.webm&offset=0&length=4",
                        b"data",
                        token,
                    )
                self.assertEqual(busy.status_code, 423)

                first = self._raw_record(
                    "type=part&file=session.webm&offset=0&length=4",
                    b"data",
                    token,
                )
                self.assertEqual(first.status_code, 200, first.content)
                conflict = self._raw_record(
                    "type=part&file=session.webm&offset=0&length=4",
                    b"evil",
                    token,
                )
                self.assertEqual(conflict.status_code, 409)

                files = list(Path(upload_root).glob("*/session.webm"))
                self.assertEqual(len(files), 1)
                self.assertEqual(files[0].read_bytes(), b"data")

    def test_audit_ingestion_and_notes_are_scoped_to_authenticated_participants(self):
        host_uuid = device_uuid("host-device")
        self._device(owner=self.user, rid="111111111", uuid=host_uuid)
        host_token = self._login("alice", "alice-pass", rid="111111111", uuid=host_uuid)
        controller = UserProfile.objects.create_user(
            username="bob",
            password="bob-pass",
        )
        controller_uuid = device_uuid("controller-device")
        self._device(owner=controller, rid="222222222", uuid=controller_uuid)
        controller_token = self._login(
            "bob",
            "bob-pass",
            rid="222222222",
            uuid=controller_uuid,
        )
        outsider = UserProfile.objects.create_user(
            username="mallory",
            password="mallory-pass",
        )
        outsider_uuid = device_uuid("outsider-device")
        self._device(owner=outsider, rid="333333333", uuid=outsider_uuid)
        outsider_token = self._login(
            "mallory",
            "mallory-pass",
            rid="333333333",
            uuid=outsider_uuid,
        )
        new_event = {
            "action": "new",
            "id": "111111111",
            "uuid": host_uuid,
            "conn_id": 7,
            "session_id": 99,
            "ip": "192.0.2.10",
            "type": 0,
        }

        self.assertEqual(self._post_json("/api/audit/conn", new_event).status_code, 401)
        created = self._post_json("/api/audit/conn", new_event, token=host_token)
        self.assertEqual(created.status_code, 200, created.content)
        replayed = self._post_json("/api/audit/conn", new_event, token=host_token)
        self.assertEqual(replayed.status_code, 200, replayed.content)
        self.assertEqual(ConnLog.objects.count(), 1)
        updated = self._post_json(
            "/api/audit/conn",
            {
                "id": "111111111",
                "uuid": host_uuid,
                "conn_id": 7,
                "session_id": 99,
                "peer": ["222222222", "bob"],
                "type": 0,
                "primary_auth": 3,
                "two_factor": 1,
            },
            token=host_token,
        )
        self.assertEqual(updated.status_code, 200, updated.content)
        connection_log = ConnLog.objects.get()
        self.assertEqual(connection_log.from_id, "222222222")
        self.assertEqual(connection_log.primary_auth, 3)
        self.assertEqual(connection_log.two_factor, 1)

        active = self.client.get(
            "/api/audit/conn/active?id=111111111&session_id=99&conn_type=0",
            **self._auth_headers(controller_token),
        )
        self.assertEqual(active.status_code, 200, active.content)
        guid = active.json()
        self.assertTrue(guid)
        connection_log.refresh_from_db()
        self.assertEqual(str(connection_log.guid), guid)
        self.assertEqual(connection_log.actor_id, controller.id)

        direct_note = self._post_json(
            "/api/audit/conn",
            {"id": "111111111", "session_id": 99, "note": "during session"},
            token=controller_token,
        )
        self.assertEqual(direct_note.status_code, 200, direct_note.content)
        denied = self._put_json(
            "/api/audit",
            {"guid": guid, "note": "tampered"},
            token=outsider_token,
        )
        self.assertEqual(denied.status_code, 404)
        allowed = self._put_json(
            "/api/audit",
            {"guid": guid, "note": "approved"},
            token=controller_token,
        )
        self.assertEqual(allowed.status_code, 200, allowed.content)
        connection_log.refresh_from_db()
        self.assertEqual(connection_log.note, "approved")

        close_event = {
            "action": "close",
            "id": "111111111",
            "uuid": host_uuid,
            "conn_id": 7,
            "session_id": 99,
        }
        self.assertEqual(
            self._post_json("/api/audit/conn", close_event, token=host_token).status_code,
            200,
        )
        self.assertEqual(
            self._post_json("/api/audit/conn", close_event, token=host_token).status_code,
            200,
        )

        restarted_process_event = {
            **new_event,
            "session_id": 100,
        }
        self.assertEqual(
            self._post_json(
                "/api/audit/conn",
                restarted_process_event,
                token=host_token,
            ).status_code,
            200,
        )
        self.assertEqual(ConnLog.objects.count(), 2)

        file_event = {
            "id": "111111111",
            "uuid": host_uuid,
            "peer_id": "222222222",
            "conn_id": 7,
            "type": 0,
            "path": "/documents",
            "is_file": False,
            "info": json.dumps(
                {
                    "ip": "192.0.2.10",
                    "name": "bob",
                    "files": [["report.pdf", 4096]],
                }
            ),
        }
        self.assertEqual(
            self._post_json("/api/audit/file", file_event, token=host_token).status_code,
            200,
        )
        file_log = FileLog.objects.get()
        self.assertEqual(file_log.filesize, 4096)
        self.assertEqual(file_log.details["files"], [["report.pdf", 4096]])

        alarm_event = {
            "id": "111111111",
            "uuid": host_uuid,
            "typ": AlarmLog.TYPE_SESSION_SCOPE_VIOLATION,
            "conn_id": 7,
            "info": json.dumps({"message": "scope mismatch"}),
        }
        self.assertEqual(
            self._post_json("/api/audit/alarm", alarm_event, token=host_token).status_code,
            200,
        )
        alarm = AlarmLog.objects.get()
        self.assertEqual(alarm.reporter_device_id, "111111111")
        self.assertEqual(alarm.info, {"message": "scope mismatch"})


class OperationalEndpointTests(TestCase):
    @override_settings(
        DEVICE_VERIFICATION_TOKEN="v" * 48,
        SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
        SECURE_SSL_REDIRECT=True,
    )
    def test_tls_readiness_probe_requires_trusted_https_marker(self):
        insecure = self.client.get("/health/ready")
        self.assertEqual(insecure.status_code, 301)
        self.assertTrue(insecure["Location"].startswith("https://"))

        secure = self.client.get(
            "/health/ready",
            HTTP_X_FORWARDED_PROTO="https",
        )
        self.assertEqual(secure.status_code, 200)
        self.assertEqual(secure.json(), {"status": "ready"})

    @override_settings(
        DEVICE_VERIFICATION_TOKEN="",
        SECURE_SSL_REDIRECT=False,
    )
    def test_readiness_rejects_missing_device_verification_secret(self):
        response = self.client.get("/health/ready")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"status": "not_ready"})

    @override_settings(SECURE_SSL_REDIRECT=False)
    def test_liveness_does_not_depend_on_database_readiness(self):
        response = self.client.get("/health/live")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "live"})
