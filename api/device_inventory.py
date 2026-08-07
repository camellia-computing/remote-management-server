from collections import deque
from dataclasses import dataclass, replace
from datetime import timedelta

from django.core import signing
from django.db.models import (
    BooleanField,
    Case,
    CharField,
    Count,
    DateTimeField,
    Exists,
    F,
    IntegerField,
    OuterRef,
    Q,
    Subquery,
    TextField,
    Value,
    When,
)
from django.db.models.functions import Cast, Coalesce, Concat
from django.utils import timezone
from django.utils.translation import gettext as _

from api.models import AddressBookProfile, RemoteDevice, RemotePeer

INVENTORY_CURSOR_SALT = "api.device-inventory.cursor.v1"
INVENTORY_COLUMNS = (
    "inventory_rid",
    "inventory_source",
    "inventory_owner_id",
    "inventory_owner_name",
    "inventory_username",
    "inventory_peer_username",
    "inventory_hostname",
    "inventory_os",
    "inventory_platform",
    "inventory_cpu",
    "inventory_memory",
    "inventory_ip_address",
    "inventory_version",
    "inventory_device_note",
    "inventory_peer_note",
    "inventory_device_group_name",
    "inventory_peer_group_name",
    "inventory_strategy_name",
    "inventory_alias",
    "inventory_has_rhash",
    "inventory_is_active",
    "inventory_create_time",
    "inventory_update_time",
)


class InvalidInventoryCursor(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class DeviceInventoryRow:
    rid: str
    source: str
    owner_id: int | None
    owner_name: str
    username: str
    peer_username: str
    hostname: str
    os: str
    platform: str
    cpu: str
    memory: str
    ip_address: str
    version: str
    device_note: str
    peer_note: str
    device_group_name: str
    peer_group_name: str
    strategy_name: str
    alias: str
    has_rhash: bool
    is_active: bool
    create_time: object | None
    update_time: object | None

    @classmethod
    def from_projection(cls, item):
        return cls(
            rid=str(item["inventory_rid"] or ""),
            source=str(item["inventory_source"] or ""),
            owner_id=item["inventory_owner_id"],
            owner_name=str(item["inventory_owner_name"] or ""),
            username=str(item["inventory_username"] or ""),
            peer_username=str(item["inventory_peer_username"] or ""),
            hostname=str(item["inventory_hostname"] or ""),
            os=str(item["inventory_os"] or ""),
            platform=str(item["inventory_platform"] or ""),
            cpu=str(item["inventory_cpu"] or ""),
            memory=str(item["inventory_memory"] or ""),
            ip_address=str(item["inventory_ip_address"] or ""),
            version=str(item["inventory_version"] or ""),
            device_note=str(item["inventory_device_note"] or ""),
            peer_note=str(item["inventory_peer_note"] or ""),
            device_group_name=str(item["inventory_device_group_name"] or ""),
            peer_group_name=str(item["inventory_peer_group_name"] or ""),
            strategy_name=str(item["inventory_strategy_name"] or ""),
            alias=str(item["inventory_alias"] or ""),
            has_rhash=bool(item["inventory_has_rhash"]),
            is_active=bool(item["inventory_is_active"]),
            create_time=item["inventory_create_time"],
            update_time=item["inventory_update_time"],
        )

    @property
    def identity(self):
        return self.rid, self.source, self.owner_id

    def as_api_dict(self):
        is_device = self.source == "device"
        owner_name = self.owner_name
        username = self.username
        device_group_name = self.device_group_name
        if is_device:
            username = username or self.peer_username
            device_group_name = device_group_name or self.peer_group_name
        else:
            device_group_name = self.peer_group_name
        return {
            "id": self.rid,
            "info": {
                "username": username,
                "os": self.os if is_device else self.platform,
                "device_name": self.hostname,
            },
            "status": 1 if not is_device or self.is_active else 0,
            "user": owner_name,
            "user_name": owner_name,
            "device_group_name": device_group_name,
            "note": self.device_note if is_device else self.peer_note,
        }

    def as_front_dict(self, *, viewer_username, now):
        is_device = self.source == "device"
        if is_device:
            status = _("在线") if self.update_time and self.update_time >= now - timedelta(seconds=120) else _("离线")
            device_group_name = self.device_group_name or self.peer_group_name
            note = self.device_note or self.peer_note
            rust_user = self.owner_name or _("未登录")
        else:
            status = _("未知状态")
            device_group_name = self.peer_group_name
            note = self.peer_note
            rust_user = viewer_username
        return {
            "rid": self.rid,
            "alias": self.alias,
            "device_group_name": device_group_name,
            "note": note,
            "version": self.version,
            "username": self.username,
            "hostname": self.hostname,
            "platform": self.platform,
            "os": self.os,
            "cpu": self.cpu,
            "memory": self.memory,
            "ip_address": self.ip_address,
            "create_time": _format_datetime(self.create_time),
            "update_time": _format_datetime(self.update_time),
            "status": status,
            "owner_name": self.owner_name,
            "rust_user": rust_user,
            "strategy_name": self.strategy_name,
            "has_rhash": _("是") if self.has_rhash else _("否"),
            "_inventory_source": self.source,
            "_inventory_owner_id": self.owner_id,
        }


def _format_datetime(value):
    return timezone.localtime(value).strftime("%Y-%m-%d %H:%M") if value else ""


def _device_queryset(*, owner_id=None, status_filter="", rid_after="", rids=None):
    devices = RemoteDevice.objects.all()
    if owner_id is not None:
        devices = devices.filter(owner_id=owner_id)
    if status_filter == "1":
        devices = devices.filter(is_active=True)
    elif status_filter == "0":
        devices = devices.filter(is_active=False)
    if rid_after:
        devices = devices.filter(rid__gt=rid_after)
    if rids is not None:
        devices = devices.filter(rid__in=rids)
    return devices.order_by()


def _device_projection(*, owner_id=None, status_filter="", rid_after="", rids=None):
    devices = _device_queryset(
        owner_id=owner_id,
        status_filter=status_filter,
        rid_after=rid_after,
        rids=rids,
    )

    return devices.annotate(
        inventory_rid=F("rid"),
        inventory_source=Value("device", output_field=CharField()),
        inventory_owner_id=F("owner_id"),
        inventory_owner_name=Coalesce("owner__username", Value(""), output_field=CharField()),
        inventory_username=F("username"),
        inventory_peer_username=Value("", output_field=CharField()),
        inventory_hostname=F("hostname"),
        inventory_os=F("os"),
        inventory_platform=Value("", output_field=CharField()),
        inventory_cpu=F("cpu"),
        inventory_memory=F("memory"),
        inventory_ip_address=Coalesce(
            Cast("ip_address", output_field=CharField()),
            Value(""),
            output_field=CharField(),
        ),
        inventory_version=F("version"),
        inventory_device_note=F("note"),
        inventory_peer_note=Value("", output_field=TextField()),
        inventory_device_group_name=Coalesce("device_group__name", Value(""), output_field=CharField()),
        inventory_peer_group_name=Value("", output_field=CharField()),
        inventory_strategy_name=Coalesce(
            "strategy__name",
            "device_group__strategy__name",
            "owner__strategy__name",
            Value(""),
            output_field=CharField(),
        ),
        inventory_alias=Value("", output_field=CharField()),
        inventory_has_rhash=Value(False, output_field=BooleanField()),
        inventory_is_active=F("is_active"),
        inventory_create_time=F("create_time"),
        inventory_update_time=F("update_time"),
    ).values(*INVENTORY_COLUMNS)


def _peer_only_queryset(*, owner_id, status_filter="", rid_after=""):
    personal_profile_id = AddressBookProfile.objects.filter(
        owner_id=owner_id,
        guid=f"personal-{owner_id}",
    ).values("pk")[:1]
    peers = RemotePeer.objects.filter(profile_id=Subquery(personal_profile_id)).annotate(
        owned_device_exists=Exists(RemoteDevice.objects.filter(owner_id=owner_id, rid=OuterRef("rid")))
    )
    peers = peers.filter(owned_device_exists=False)
    if status_filter == "0":
        peers = peers.none()
    if rid_after:
        peers = peers.filter(rid__gt=rid_after)
    return peers.order_by()


def _personal_peer_queryset(*, owner_id, status_filter="", rid_after="", rids=None):
    personal_profile_id = AddressBookProfile.objects.filter(
        owner_id=owner_id,
        guid=f"personal-{owner_id}",
    ).values("pk")[:1]
    peers = RemotePeer.objects.filter(profile_id=Subquery(personal_profile_id))
    if status_filter == "0":
        peers = peers.none()
    if rid_after:
        peers = peers.filter(rid__gt=rid_after)
    if rids is not None:
        peers = peers.filter(rid__in=rids)
    return peers.order_by()


def _peer_projection(*, owner_id, owner_name="", status_filter="", rid_after="", rids=None):
    peers = _personal_peer_queryset(
        owner_id=owner_id,
        status_filter=status_filter,
        rid_after=rid_after,
        rids=rids,
    )
    return peers.annotate(
        inventory_rid=F("rid"),
        inventory_source=Value("peer", output_field=CharField()),
        inventory_owner_id=Value(owner_id, output_field=IntegerField()),
        inventory_owner_name=Value(owner_name, output_field=CharField()),
        inventory_username=F("username"),
        inventory_peer_username=Value("", output_field=CharField()),
        inventory_hostname=F("hostname"),
        inventory_os=Value("", output_field=CharField()),
        inventory_platform=F("platform"),
        inventory_cpu=Value("", output_field=CharField()),
        inventory_memory=Value("", output_field=CharField()),
        inventory_ip_address=Value("", output_field=CharField()),
        inventory_version=Value("", output_field=CharField()),
        inventory_device_note=Value("", output_field=TextField()),
        inventory_peer_note=F("note"),
        inventory_device_group_name=Value("", output_field=CharField()),
        inventory_peer_group_name=F("device_group_name"),
        inventory_strategy_name=Value("", output_field=CharField()),
        inventory_alias=F("alias"),
        inventory_has_rhash=Case(
            When(rhash="", then=Value(False)),
            default=Value(True),
            output_field=BooleanField(),
        ),
        inventory_is_active=Value(True, output_field=BooleanField()),
        inventory_create_time=Value(None, output_field=DateTimeField()),
        inventory_update_time=Value(None, output_field=DateTimeField()),
    ).values(*INVENTORY_COLUMNS)


def _peer_only_projection(*, owner_id, owner_name="", status_filter="", rid_after=""):
    peer_only_rids = _peer_only_queryset(
        owner_id=owner_id,
        status_filter=status_filter,
        rid_after=rid_after,
    ).values("rid")
    return _peer_projection(
        owner_id=owner_id,
        owner_name=owner_name,
        status_filter=status_filter,
        rid_after=rid_after,
        rids=Subquery(peer_only_rids),
    )


def _device_identity_queryset(*, owner_id, status_filter="", rid_after=""):
    return (
        _device_queryset(
            owner_id=owner_id,
            status_filter=status_filter,
            rid_after=rid_after,
        )
        .annotate(
            inventory_rid=F("rid"),
            inventory_owned_device=Value(True, output_field=BooleanField()),
        )
        .values("inventory_rid", "inventory_owned_device")
    )


def _peer_identity_queryset(*, owner_id, status_filter="", rid_after=""):
    return (
        _personal_peer_queryset(
            owner_id=owner_id,
            status_filter=status_filter,
            rid_after=rid_after,
        )
        .annotate(
            inventory_rid=F("rid"),
            inventory_owned_device=Value(False, output_field=BooleanField()),
        )
        .values("inventory_rid", "inventory_owned_device")
    )


class _IdentityBatchStream:
    def __init__(self, queryset, *, batch_size, rid_after="", prepare_batch=None):
        self.queryset = queryset
        self.batch_size = batch_size
        self.rid_after = rid_after
        self.prepare_batch = prepare_batch
        self.buffer = deque()
        self.exhausted = False

    def peek(self):
        if not self.buffer and not self.exhausted:
            batch = list(
                self.queryset.filter(inventory_rid__gt=self.rid_after).order_by("inventory_rid")[: self.batch_size]
            )
            if not batch:
                self.exhausted = True
            else:
                if self.prepare_batch is not None:
                    batch = self.prepare_batch(batch)
                self.rid_after = str(batch[-1]["inventory_rid"])
                self.buffer.extend(batch)
        return self.buffer[0] if self.buffer else None

    def advance(self):
        if not self.buffer:
            raise IndexError("identity stream is empty")
        return self.buffer.popleft()


class DeviceInventory:
    def __init__(self, user, *, admin_scope=None):
        self.user_id = user.pk
        self.username = user.username
        self.is_admin = bool(user.is_admin) if admin_scope is None else bool(admin_scope and user.is_admin)
        self._count_cache = {}

    def _branch_counts(self, status_filter):
        cached = self._count_cache.get(status_filter)
        if cached is not None:
            return cached
        owner_id = None if self.is_admin else self.user_id
        device_count = _device_queryset(owner_id=owner_id, status_filter=status_filter).count()
        peer_count = 0
        if not self.is_admin and status_filter != "0":
            peer_count = _peer_only_queryset(owner_id=self.user_id, status_filter=status_filter).count()
        counts = device_count, peer_count
        self._count_cache[status_filter] = counts
        return counts

    def _projection(self, *, status_filter="", rid_after=""):
        owner_id = None if self.is_admin else self.user_id
        devices = _device_projection(
            owner_id=owner_id,
            status_filter=status_filter,
            rid_after=rid_after,
        )
        return devices.order_by("inventory_rid")

    def count(self, *, status_filter=""):
        return sum(self._branch_counts(status_filter))

    def _identity_page(self, *, offset, limit, status_filter, rid_after):
        device_batch_size = limit if offset == 0 else min(500, max(limit, offset + limit))
        peer_batch_size = max(64, device_batch_size)
        devices = _IdentityBatchStream(
            _device_identity_queryset(
                owner_id=self.user_id,
                status_filter=status_filter,
                rid_after=rid_after,
            ),
            batch_size=device_batch_size,
            rid_after=rid_after,
        )

        def mark_owned_peers(batch):
            batch_rids = [str(item["inventory_rid"]) for item in batch]
            owned_rids = set(
                RemoteDevice.objects.filter(
                    owner_id=self.user_id,
                    rid__in=batch_rids,
                ).values_list("rid", flat=True)
            )
            return [
                {
                    **item,
                    "inventory_owned_device": str(item["inventory_rid"]) in owned_rids,
                }
                for item in batch
            ]

        peers = _IdentityBatchStream(
            _peer_identity_queryset(
                owner_id=self.user_id,
                status_filter=status_filter,
                rid_after=rid_after,
            ),
            batch_size=peer_batch_size,
            rid_after=rid_after,
            prepare_batch=mark_owned_peers,
        )
        skipped = 0
        selected = []
        while len(selected) < limit:
            device = devices.peek()
            peer = peers.peek()
            if device is None and peer is None:
                break

            identity = None
            if peer is not None and (device is None or str(peer["inventory_rid"]) <= str(device["inventory_rid"])):
                peer = peers.advance()
                same_device = device is not None and str(peer["inventory_rid"]) == str(device["inventory_rid"])
                if not same_device and not peer["inventory_owned_device"]:
                    identity = ("peer", str(peer["inventory_rid"]))
            else:
                device = devices.advance()
                identity = ("device", str(device["inventory_rid"]))

            if identity is None:
                continue
            if skipped < offset:
                skipped += 1
                continue
            selected.append(identity)
        return selected

    def _rows_for_identities(self, identities, *, status_filter):
        device_rids = [rid for source, rid in identities if source == "device"]
        peer_rids = [rid for source, rid in identities if source == "peer"]
        projected = []
        if device_rids:
            projected.extend(
                DeviceInventoryRow.from_projection(item)
                for item in _device_projection(
                    owner_id=self.user_id,
                    status_filter=status_filter,
                    rids=device_rids,
                )
            )
        if peer_rids:
            projected.extend(
                DeviceInventoryRow.from_projection(item)
                for item in _peer_projection(
                    owner_id=self.user_id,
                    owner_name=self.username,
                    status_filter=status_filter,
                    rids=peer_rids,
                )
            )
        by_identity = {(row.source, row.rid): row for row in projected}
        ordered = [by_identity[identity] for identity in identities if identity in by_identity]
        return self._attach_personal_peer_metadata(ordered)

    def _attach_personal_peer_metadata(self, rows):
        device_rows = [row for row in rows if row.source == "device" and row.owner_id is not None]
        if not device_rows:
            return rows
        owner_ids = {row.owner_id for row in device_rows}
        rids = {row.rid for row in device_rows}
        peers = RemotePeer.objects.filter(
            profile__owner_id__in=owner_ids,
            rid__in=rids,
        )
        if self.is_admin:
            peers = peers.annotate(
                inventory_expected_guid=Concat(
                    Value("personal-"),
                    Cast("profile__owner_id", output_field=CharField()),
                )
            ).filter(profile__guid=F("inventory_expected_guid"))
        else:
            peers = peers.filter(
                profile__owner_id=self.user_id,
                profile__guid=f"personal-{self.user_id}",
            )
        metadata = {
            (item["profile__owner_id"], item["rid"]): item
            for item in peers.annotate(
                inventory_has_rhash=Case(
                    When(rhash="", then=Value(False)),
                    default=Value(True),
                    output_field=BooleanField(),
                )
            ).values(
                "profile__owner_id",
                "rid",
                "username",
                "platform",
                "note",
                "device_group_name",
                "alias",
                "inventory_has_rhash",
            )
        }
        enriched = []
        for row in rows:
            peer = metadata.get((row.owner_id, row.rid))
            if row.source != "device" or peer is None:
                enriched.append(row)
                continue
            enriched.append(
                replace(
                    row,
                    peer_username=str(peer["username"] or ""),
                    platform=str(peer["platform"] or ""),
                    peer_note=str(peer["note"] or ""),
                    peer_group_name=str(peer["device_group_name"] or ""),
                    alias=str(peer["alias"] or ""),
                    has_rhash=bool(peer["inventory_has_rhash"]),
                )
            )
        return enriched

    def rows(self, *, offset=0, limit=100, status_filter="", rid_after=""):
        if offset < 0 or limit < 1:
            raise ValueError("invalid inventory page")
        if self.is_admin:
            projection = self._projection(status_filter=status_filter, rid_after=rid_after)
            rows = [DeviceInventoryRow.from_projection(item) for item in projection[offset : offset + limit]]
            return self._attach_personal_peer_metadata(rows)
        identities = self._identity_page(
            offset=offset,
            limit=limit,
            status_filter=status_filter,
            rid_after=rid_after,
        )
        return self._rows_for_identities(identities, status_filter=status_filter)

    def front_rows(self, *, offset=0, limit=15):
        now = timezone.now()
        return [
            row.as_front_dict(viewer_username=self.username, now=now) for row in self.rows(offset=offset, limit=limit)
        ]

    def summary(self):
        devices = RemoteDevice.objects.all() if self.is_admin else RemoteDevice.objects.filter(owner_id=self.user_id)
        cutoff = timezone.now() - timedelta(seconds=120)
        aggregate = devices.aggregate(
            total=Count("pk"),
            online=Count("pk", filter=Q(update_time__gte=cutoff)),
        )
        unknown = 0
        if not self.is_admin:
            unknown = _peer_only_queryset(owner_id=self.user_id).count()
        online = aggregate["online"]
        return {
            "total": aggregate["total"] + unknown,
            "online": online,
            "offline": aggregate["total"] - online,
            "unknown": unknown,
        }

    def recent(self, *, limit=6):
        owner_id = None if self.is_admin else self.user_id
        device_items = list(
            _device_projection(owner_id=owner_id).order_by(
                "-inventory_update_time",
                "inventory_rid",
            )[:limit]
        )
        rows = self._attach_personal_peer_metadata([DeviceInventoryRow.from_projection(item) for item in device_items])
        if not self.is_admin and len(rows) < limit:
            peer_items = _peer_only_projection(
                owner_id=self.user_id,
                owner_name=self.username,
            ).order_by("inventory_rid")[: limit - len(rows)]
            rows.extend(DeviceInventoryRow.from_projection(item) for item in peer_items)
        now = timezone.now()
        return [row.as_front_dict(viewer_username=self.username, now=now) for row in rows]


class InventoryPageSource:
    ordered = True

    def __init__(self, inventory):
        self.inventory = inventory

    def count(self):
        return self.inventory.count()

    def __getitem__(self, key):
        if isinstance(key, slice):
            if key.step not in (None, 1):
                raise ValueError("inventory pages do not support stepped slices")
            start = 0 if key.start is None else key.start
            stop = start if key.stop is None else key.stop
            if stop <= start:
                return []
            return self.inventory.front_rows(offset=start, limit=max(0, stop - start))
        if key < 0:
            raise IndexError("negative inventory indexes are not supported")
        rows = self.inventory.front_rows(offset=key, limit=1)
        if not rows:
            raise IndexError("inventory index out of range")
        return rows[0]


def dump_inventory_cursor(row, user, status_filter):
    return signing.dumps(
        {
            "v": 1,
            "rid": row.rid,
            "source": row.source,
            "owner_id": row.owner_id,
            "viewer_id": user.pk,
            "admin": bool(user.is_admin),
            "status": status_filter,
        },
        salt=INVENTORY_CURSOR_SALT,
        compress=True,
    )


def load_inventory_cursor(value, user, status_filter):
    try:
        payload = signing.loads(value, salt=INVENTORY_CURSOR_SALT, max_age=3600)
        rid = str(payload["rid"])
        if (
            payload.get("v") != 1
            or payload.get("source") not in ("device", "peer")
            or payload.get("viewer_id") != user.pk
            or payload.get("admin") is not bool(user.is_admin)
            or payload.get("status") != status_filter
            or not 1 <= len(rid) <= RemoteDevice._meta.get_field("rid").max_length
            or any(ord(character) < 33 or ord(character) > 126 for character in rid)
        ):
            raise InvalidInventoryCursor("cursor does not match the inventory scope")
    except (KeyError, TypeError, ValueError, signing.BadSignature, signing.SignatureExpired) as exc:
        raise InvalidInventoryCursor("invalid inventory cursor") from exc
    return rid
