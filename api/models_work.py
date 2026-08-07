import datetime
import uuid

from django.conf import settings
from django.contrib import admin
from django.contrib.auth.models import Group
from django.contrib.postgres.indexes import GinIndex, OpClass
from django.core.exceptions import ValidationError
from django.db import models, router, transaction
from django.db.models.functions import Cast, Upper
from django.db.models.signals import m2m_changed, pre_delete
from django.dispatch import receiver
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .address_book_errors import AuthorizationGenerationExhausted
from .audit_expressions import audit_search_document
from .encrypted_fields import EncryptedTextField
from .recording_crypto import FORMAT_VERSION as RECORDING_ENCRYPTION_VERSION
from .recording_crypto import HEADER_SIZE as RECORDING_HEADER_SIZE

ALARM_TYPES = (0, 1, 2, 6, 7, 8, 9)
POLICY_ASSIGNMENT_FIELDS = frozenset(
    ("owner", "owner_id", "device_group", "device_group_id", "strategy", "strategy_id")
)
POLICY_CONTENT_FIELDS = frozenset(("config_options", "enabled"))


class RemoteDeviceQuerySet(models.QuerySet):
    def update(self, **kwargs):
        if "policy_generation" in kwargs:
            raise ValueError("policy_generation is managed internally")
        if not POLICY_ASSIGNMENT_FIELDS.intersection(kwargs):
            return super().update(**kwargs)
        from api.policy_generation import bump_device_policy_generations

        with transaction.atomic(using=self.db):
            device_ids = list(
                self.select_related(None).select_for_update(of=("self",)).order_by("pk").values_list("pk", flat=True)
            )
            updated = super().update(**kwargs)
            bump_device_policy_generations(device_ids, using=self.db)
            return updated


class StrategyProfileQuerySet(models.QuerySet):
    def update(self, **kwargs):
        if not POLICY_CONTENT_FIELDS.intersection(kwargs):
            return super().update(**kwargs)
        from api.policy_generation import (
            bump_device_policy_generations,
            device_ids_affected_by_strategies,
        )

        with transaction.atomic(using=self.db):
            strategy_ids = list(
                self.select_related(None).select_for_update().order_by("pk").values_list("pk", flat=True)
            )
            device_ids = device_ids_affected_by_strategies(strategy_ids, using=self.db)
            updated = super().update(**kwargs)
            bump_device_policy_generations(device_ids, using=self.db)
            return updated

    def delete(self):
        from api.policy_generation import (
            bump_device_policy_generations,
            device_ids_affected_by_strategies,
        )

        with transaction.atomic(using=self.db):
            strategy_ids = list(
                self.select_related(None).select_for_update().order_by("pk").values_list("pk", flat=True)
            )
            device_ids = device_ids_affected_by_strategies(strategy_ids, using=self.db)
            result = super().delete()
            bump_device_policy_generations(device_ids, using=self.db)
            return result


class DeviceGroupQuerySet(models.QuerySet):
    def update(self, **kwargs):
        if not {"strategy", "strategy_id"}.intersection(kwargs):
            return super().update(**kwargs)
        from api.policy_generation import (
            bump_device_policy_generations,
            device_ids_affected_by_groups,
        )

        with transaction.atomic(using=self.db):
            group_ids = list(self.select_related(None).select_for_update().order_by("pk").values_list("pk", flat=True))
            device_ids = device_ids_affected_by_groups(group_ids, using=self.db)
            updated = super().update(**kwargs)
            bump_device_policy_generations(device_ids, using=self.db)
            return updated

    def delete(self):
        from api.policy_generation import (
            bump_device_policy_generations,
            device_ids_affected_by_groups,
        )

        with transaction.atomic(using=self.db):
            group_ids = list(self.select_related(None).select_for_update().order_by("pk").values_list("pk", flat=True))
            device_ids = device_ids_affected_by_groups(group_ids, using=self.db)
            result = super().delete()
            bump_device_policy_generations(device_ids, using=self.db)
            return result


class DataEncryptionKeyState(models.Model):
    """Database-side inventory of keys required to decrypt retained rows."""

    key_id = models.CharField(max_length=32, primary_key=True)
    key_fingerprint = models.CharField(max_length=64, unique=True)
    encrypted_canary = models.TextField()
    is_primary = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("key_id",)
        constraints = [
            models.UniqueConstraint(
                fields=("is_primary",),
                condition=models.Q(is_primary=True),
                name="one_primary_data_encryption_key",
            ),
        ]

    def __str__(self):
        return self.key_id


class RemoteToken(models.Model):
    """A single rotating session token bound to one device and immutable subject."""

    device = models.OneToOneField(
        "RemoteDevice",
        on_delete=models.CASCADE,
        related_name="session_token",
    )
    subject_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="remote_tokens",
        editable=False,
    )
    access_token = models.CharField(
        verbose_name=_("access_token"),
        max_length=64,
        unique=True,
        editable=False,
    )
    credential_hash = models.CharField(max_length=64, default="", editable=False)
    create_time = models.DateTimeField(verbose_name=_("登录时间"), auto_now_add=True)
    expires_at = models.DateTimeField(verbose_name=_("过期时间"), db_index=True)

    class Meta:
        ordering = ("-create_time",)
        verbose_name = _("令牌")
        verbose_name_plural = _("令牌列表")


class DeviceProofChallenge(models.Model):
    """Short-lived, one-use challenge for device key possession proofs."""

    PURPOSE_LOGIN = "login"
    PURPOSE_OIDC = "oidc"
    PURPOSE_DEPLOY = "deploy"
    PURPOSE_CHOICES = (
        (PURPOSE_LOGIN, "Password login"),
        (PURPOSE_OIDC, "OIDC login"),
        (PURPOSE_DEPLOY, "Deployment"),
    )

    code_hash = models.CharField(max_length=64, unique=True, editable=False)
    purpose = models.CharField(max_length=16, choices=PURPOSE_CHOICES)
    rid = models.CharField(max_length=16)
    device_uuid = models.CharField(max_length=344)
    public_key_hash = models.CharField(max_length=64)
    deployment_generation = models.PositiveBigIntegerField(default=0)
    device = models.ForeignKey(
        "RemoteDevice",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="proof_challenges",
    )
    subject_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="device_proof_challenges",
    )
    request_ip = models.GenericIPAddressField(
        default="0.0.0.0",  # noqa: S104 - non-routable rate-limit sentinel, not a bind address
        db_index=True,
    )
    expires_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [models.Index(fields=("request_ip", "expires_at"), name="device_proof_ip_exp_idx")]


class DeviceRecoveryApproval(models.Model):
    """Administrator approval for one lost-key replacement."""

    device = models.ForeignKey(
        "RemoteDevice",
        on_delete=models.CASCADE,
        related_name="recovery_approvals",
    )
    public_key_hash = models.CharField(max_length=64)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="approved_device_recoveries",
    )
    expires_at = models.DateTimeField(db_index=True)
    consumed_at = models.DateTimeField(null=True, blank=True, default=None)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(
                fields=("device", "public_key_hash", "expires_at"),
                name="device_recovery_lookup_idx",
            )
        ]


class RemoteTokenAdmin(admin.ModelAdmin):
    list_display = ("device", "subject_user", "device_owner", "expires_at")
    search_fields = ("subject_user__username", "device__owner__username", "device__rid")
    list_filter = ("create_time", "expires_at")  # 过滤器

    @admin.display(description=_("归属用户"), ordering="device__owner__username")
    def device_owner(self, obj):
        return obj.device.owner if obj.device_id else None


class RemoteTag(models.Model):
    """Tag scoped to exactly one address book."""

    profile = models.ForeignKey(
        "AddressBookProfile",
        on_delete=models.CASCADE,
        related_name="tags",
        verbose_name=_("地址簿"),
    )
    tag_name = models.CharField(verbose_name=_("标签名称"), max_length=64)
    tag_color = models.CharField(verbose_name=_("标签颜色"), max_length=32, blank=True)

    class Meta:
        ordering = ("profile_id", "tag_name")
        verbose_name = _("标签")
        verbose_name_plural = _("标签列表")
        constraints = [
            models.UniqueConstraint(
                fields=["profile", "tag_name"],
                name="unique_tag_per_address_book",
            ),
        ]


class RemoteTagAdmin(admin.ModelAdmin):
    list_display = ("tag_name", "profile", "tag_color")
    search_fields = ("tag_name", "profile__guid", "profile__owner__username")
    list_filter = ("profile",)


class RemotePeer(models.Model):
    """Peer entry scoped to exactly one address book."""

    profile = models.ForeignKey(
        "AddressBookProfile",
        on_delete=models.CASCADE,
        related_name="peers",
        verbose_name=_("地址簿"),
    )
    rid = models.CharField(verbose_name=_("客户端ID"), max_length=16)
    username = models.CharField(verbose_name=_("系统用户名"), max_length=100, blank=True, default="")
    hostname = models.CharField(verbose_name=_("操作系统名"), max_length=100, blank=True, default="")
    alias = models.CharField(verbose_name=_("别名"), max_length=100, blank=True, default="")
    platform = models.CharField(verbose_name=_("平台"), max_length=100, blank=True, default="")
    tags = models.ManyToManyField(
        RemoteTag,
        related_name="peers",
        blank=True,
        verbose_name=_("标签"),
    )
    rhash = EncryptedTextField(verbose_name=_("设备链接密码"), max_length=256, blank=True, default="")
    note = models.TextField(verbose_name=_("备注"), blank=True, default="")
    password = EncryptedTextField(verbose_name=_("共享密码"), max_length=60, blank=True, default="")
    device_group_name = models.CharField(verbose_name=_("设备组"), max_length=60, blank=True, default="")
    login_name = models.CharField(verbose_name=_("登录账号"), max_length=60, blank=True, default="")
    same_server = models.BooleanField(verbose_name=_("同服务器"), default=False)

    class Meta:
        ordering = ("profile_id", "rid")
        verbose_name = _("客户端")
        verbose_name_plural = _("客户端列表")
        constraints = [
            models.UniqueConstraint(
                fields=["profile", "rid"],
                name="unique_peer_per_address_book",
            ),
        ]


class RemotePeerAdmin(admin.ModelAdmin):
    list_display = (
        "rid",
        "profile",
        "username",
        "hostname",
        "platform",
        "alias",
        "tag_names",
    )
    search_fields = ("rid", "alias", "profile__guid", "profile__owner__username")
    list_filter = ("profile", "platform")

    def get_queryset(self, request):
        return super().get_queryset(request).prefetch_related("tags")

    @admin.display(description=_("标签"))
    def tag_names(self, obj):
        return ", ".join(sorted(tag.tag_name for tag in obj.tags.all()))


@receiver(m2m_changed, sender=RemotePeer.tags.through)
def validate_peer_tag_profile(sender, instance, action, reverse, pk_set, **kwargs):
    """Reject peer/tag links that cross address-book boundaries."""
    if action != "pre_add" or not pk_set:
        return
    if reverse:
        has_mismatch = (
            RemotePeer.objects.filter(pk__in=pk_set)
            .exclude(
                profile_id=instance.profile_id,
            )
            .exists()
        )
    else:
        has_mismatch = (
            RemoteTag.objects.filter(pk__in=pk_set)
            .exclude(
                profile_id=instance.profile_id,
            )
            .exists()
        )
    if has_mismatch:
        raise ValidationError(_("设备和标签必须属于同一个地址簿。"))


class RemoteDevice(models.Model):
    objects = RemoteDeviceQuerySet.as_manager()

    rid = models.CharField(verbose_name=_("客户端ID"), max_length=16, unique=True)
    cpu = models.CharField(verbose_name="CPU", max_length=100)
    hostname = models.CharField(verbose_name=_("主机名"), max_length=100)
    memory = models.CharField(verbose_name=_("内存"), max_length=100)
    os = models.CharField(verbose_name=_("操作系统"), max_length=100)
    uuid = models.CharField(verbose_name="uuid", max_length=344, unique=True)
    public_key_hash = models.CharField(
        verbose_name=_("设备公钥哈希"),
        max_length=64,
        null=True,
        blank=True,
        default=None,
        unique=True,
    )
    deployment_generation = models.PositiveBigIntegerField(default=0, editable=False)
    policy_generation = models.PositiveBigIntegerField(default=0, editable=False)
    username = models.CharField(verbose_name=_("系统用户名"), max_length=100, blank=True)
    version = models.CharField(verbose_name=_("客户端版本"), max_length=100)
    ip_address = models.GenericIPAddressField(
        verbose_name=_("IP"),
        null=True,
        blank=True,
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="devices"
    )
    device_group = models.ForeignKey(
        "DeviceGroup",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="devices",
        verbose_name=_("设备组"),
    )
    note = models.TextField(verbose_name=_("备注"), blank=True, default="")
    strategy = models.ForeignKey(
        "StrategyProfile",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="devices",
        verbose_name=_("直接分配策略"),
    )
    address_book_name = models.CharField(verbose_name=_("地址簿名称"), max_length=60, blank=True, default="")
    address_book_tag = models.CharField(verbose_name=_("地址簿标签"), max_length=60, blank=True, default="")
    address_book_alias = models.CharField(verbose_name=_("地址簿别名"), max_length=60, blank=True, default="")
    address_book_password = EncryptedTextField(verbose_name=_("地址簿密码"), max_length=128, blank=True, default="")
    address_book_note = models.TextField(verbose_name=_("地址簿备注"), blank=True, default="")
    is_active = models.BooleanField(verbose_name=_("是否启用"), default=True)
    create_time = models.DateTimeField(verbose_name=_("设备注册时间"), auto_now_add=True)
    update_time = models.DateTimeField(
        verbose_name=("设备更新时间"),
        auto_now=True,
        db_index=True,
    )

    class Meta:
        ordering = ("-rid",)
        verbose_name = _("设备")
        verbose_name_plural = _("设备列表")
        indexes = [
            models.Index(fields=("owner", "rid"), name="device_owner_rid_idx"),
            models.Index(fields=("owner", "is_active", "rid"), name="device_owner_active_rid_idx"),
            models.Index(fields=("is_active", "rid"), name="device_active_rid_idx"),
            models.Index(
                fields=("owner", "-update_time", "rid"),
                name="device_owner_updated_rid_idx",
            ),
        ]

    def effective_strategy(self):
        if self.strategy_id:
            return self.strategy
        if self.device_group_id and self.device_group.strategy_id:
            return self.device_group.strategy
        if self.owner_id and self.owner.strategy_id:
            return self.owner.strategy
        return None

    def save(self, *args, **kwargs):
        if not self.pk:
            self.policy_generation = 0
            return super().save(*args, **kwargs)
        update_fields = kwargs.get("update_fields")
        if update_fields is not None and not (POLICY_ASSIGNMENT_FIELDS | {"policy_generation"}).intersection(
            update_fields
        ):
            return super().save(*args, **kwargs)
        database = kwargs.get("using") or router.db_for_write(type(self), instance=self)
        from api.policy_generation import bump_device_policy_generations

        with transaction.atomic(using=database):
            previous = (
                type(self)
                ._base_manager.using(database)
                .select_for_update()
                .filter(pk=self.pk)
                .values(
                    "owner_id",
                    "device_group_id",
                    "strategy_id",
                    "policy_generation",
                )
                .first()
            )
            if previous is None:
                return super().save(*args, **kwargs)
            self.policy_generation = previous["policy_generation"]
            result = super().save(*args, **kwargs)
            assignment_fields = {
                "owner_id": {"owner", "owner_id"},
                "device_group_id": {"device_group", "device_group_id"},
                "strategy_id": {"strategy", "strategy_id"},
            }
            assignment_changed = (
                update_fields is None and any(previous[field] != getattr(self, field) for field in assignment_fields)
            ) or (
                update_fields is not None
                and any(
                    aliases.intersection(update_fields) and previous[field] != getattr(self, field)
                    for field, aliases in assignment_fields.items()
                )
            )
            if assignment_changed:
                generations = bump_device_policy_generations((self.pk,), using=database)
                self.policy_generation = generations[self.pk]
            return result


class RemoteDeviceAdmin(admin.ModelAdmin):
    list_display = (
        "rid",
        "hostname",
        "memory",
        "uuid",
        "version",
        "owner",
        "device_group",
        "strategy",
        "policy_generation",
        "create_time",
        "update_time",
    )
    search_fields = ("rid", "hostname", "memory", "owner__username", "device_group__name")
    list_filter = ("is_active", "device_group", "strategy")


class ConnLog(models.Model):
    STATE_STARTING = "starting"
    STATE_ACTIVE = "active"
    STATE_CLOSED = "closed"
    STATE_ABORTED = "aborted"
    STATE_EXPIRED = "expired"
    OPEN_STATES = (STATE_STARTING, STATE_ACTIVE)
    TERMINAL_STATES = (STATE_CLOSED, STATE_ABORTED, STATE_EXPIRED)
    STATES = (
        (STATE_STARTING, "Starting"),
        (STATE_ACTIVE, "Active"),
        (STATE_CLOSED, "Closed"),
        (STATE_ABORTED, "Aborted"),
        (STATE_EXPIRED, "Expired"),
    )

    id = models.AutoField(verbose_name="ID", primary_key=True)
    guid = models.UUIDField(
        verbose_name="GUID",
        default=uuid.uuid4,
        editable=False,
        unique=True,
    )
    audit_version = models.PositiveSmallIntegerField(default=1, editable=False)
    create_id = models.UUIDField(null=True, blank=True, editable=False)
    host_device = models.ForeignKey(
        "RemoteDevice",
        null=True,
        blank=True,
        editable=False,
        on_delete=models.SET_NULL,
        related_name="connection_audits",
    )
    host_device_id_at_create = models.PositiveBigIntegerField(null=True, blank=True, editable=False)
    host_device_generation = models.PositiveBigIntegerField(default=0, editable=False)
    host_device_name_at_create = models.CharField(max_length=100, blank=True, default="", editable=False)
    owner_id_at_create = models.PositiveBigIntegerField(null=True, blank=True, editable=False)
    controller_device = models.ForeignKey(
        "RemoteDevice",
        null=True,
        blank=True,
        editable=False,
        on_delete=models.SET_NULL,
        related_name="controlled_connection_audits",
    )
    controller_device_id_at_bind = models.PositiveBigIntegerField(null=True, blank=True, editable=False)
    controller_device_generation = models.PositiveBigIntegerField(null=True, blank=True, editable=False)
    controller_device_name_at_bind = models.CharField(max_length=100, blank=True, default="", editable=False)
    controller_owner_id_at_bind = models.PositiveBigIntegerField(null=True, blank=True, editable=False)
    event_revision = models.PositiveBigIntegerField(default=0, editable=False)
    state = models.CharField(max_length=12, choices=STATES, default=STATE_EXPIRED, editable=False)
    state_revision = models.PositiveBigIntegerField(default=0, editable=False)
    last_seen_at = models.DateTimeField(null=True, blank=True, editable=False)
    lease_expires_at = models.DateTimeField(null=True, blank=True, editable=False)
    heartbeat_revision = models.PositiveBigIntegerField(default=0, editable=False)
    last_heartbeat_id = models.UUIDField(null=True, blank=True, editable=False)
    terminal_at = models.DateTimeField(null=True, blank=True, editable=False)
    terminal_reason = models.CharField(max_length=64, blank=True, default="", editable=False)
    terminal_source = models.CharField(max_length=32, blank=True, default="", editable=False)
    retention_hold = models.BooleanField(default=False, db_index=True, editable=False)
    retention_hold_reason = models.CharField(max_length=512, blank=True, default="", editable=False)
    retention_hold_at = models.DateTimeField(null=True, blank=True, editable=False)
    conn_id = models.PositiveIntegerField(verbose_name="Connection ID")
    from_ip = models.GenericIPAddressField(verbose_name="From IP")
    from_id = models.CharField(verbose_name="From ID", max_length=16, blank=True, default="")
    rid = models.CharField(verbose_name="To ID", max_length=16)
    conn_start = models.DateTimeField(verbose_name="Connected", default=timezone.now)
    conn_end = models.DateTimeField(
        verbose_name="Disconnected",
        null=True,
        blank=True,
    )
    session_id = models.CharField(verbose_name="Session ID", max_length=60)
    uuid = models.CharField(verbose_name="uuid", max_length=344)
    conn_type = models.IntegerField(
        verbose_name="Conn Type",
        null=True,
        blank=True,
    )
    primary_auth = models.PositiveSmallIntegerField(
        verbose_name="Primary Authentication",
        null=True,
        blank=True,
    )
    two_factor = models.PositiveSmallIntegerField(
        verbose_name="Second Factor",
        null=True,
        blank=True,
    )
    audit_ref = models.CharField(
        verbose_name="Audit Reference",
        max_length=256,
        blank=True,
        default="",
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="controlled_connection_logs",
    )
    note = models.TextField(verbose_name="Note", blank=True, default="")
    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reported_connection_logs",
    )

    class Meta:
        ordering = ("-conn_start",)
        verbose_name = _("连接日志")
        verbose_name_plural = _("连接日志列表")
        constraints = [
            models.UniqueConstraint(
                fields=["rid", "uuid", "session_id"],
                name="unique_connection_session",
            ),
            models.CheckConstraint(
                condition=models.Q(conn_end__isnull=True) | models.Q(conn_end__gte=models.F("conn_start")),
                name="connection_end_after_start",
            ),
            models.CheckConstraint(
                condition=models.Q(conn_id__gte=1),
                name="positive_connection_id",
            ),
            models.CheckConstraint(
                condition=models.Q(primary_auth__isnull=True) | models.Q(primary_auth__gte=1, primary_auth__lte=4),
                name="valid_primary_auth_method",
            ),
            models.CheckConstraint(
                condition=models.Q(two_factor__isnull=True) | models.Q(two_factor__gte=1, two_factor__lte=2),
                name="valid_second_factor_method",
            ),
            models.CheckConstraint(
                condition=models.Q(conn_type__isnull=True) | models.Q(conn_type__gte=0, conn_type__lte=4),
                name="valid_connection_type",
            ),
            models.UniqueConstraint(
                fields=["host_device", "create_id"],
                condition=models.Q(audit_version__in=(2, 3)),
                name="unique_connection_audit_create",
            ),
            models.CheckConstraint(
                condition=models.Q(audit_version=1)
                | models.Q(
                    audit_version__in=(2, 3),
                    create_id__isnull=False,
                    host_device_id_at_create__isnull=False,
                    owner_id_at_create__isnull=False,
                    event_revision__gte=1,
                ),
                name="valid_connection_audit_authority",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(
                        state__in=("starting", "active"),
                        state_revision__gte=1,
                        last_seen_at__isnull=False,
                        lease_expires_at__isnull=False,
                        terminal_at__isnull=True,
                        terminal_reason="",
                        terminal_source="",
                        conn_end__isnull=True,
                    )
                    | models.Q(
                        state__in=("closed", "aborted"),
                        state_revision__gte=1,
                        last_seen_at__isnull=False,
                        lease_expires_at__isnull=False,
                        terminal_at__isnull=False,
                        terminal_reason__gt="",
                        terminal_source__gt="",
                        conn_end__isnull=False,
                    )
                    | models.Q(
                        state="expired",
                        state_revision__gte=1,
                        last_seen_at__isnull=False,
                        lease_expires_at__isnull=False,
                        terminal_at__isnull=False,
                        terminal_reason__gt="",
                        terminal_source__gt="",
                        conn_end__isnull=True,
                    )
                ),
                name="valid_connection_audit_lifecycle",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(heartbeat_revision=0, last_heartbeat_id__isnull=True)
                    | models.Q(heartbeat_revision__gte=1, last_heartbeat_id__isnull=False)
                ),
                name="valid_connection_heartbeat_identity",
            ),
        ]
        indexes = [
            models.Index(
                fields=["rid", "session_id", "from_id"],
                name="connection_participant_lookup",
            ),
            models.Index(
                fields=["-conn_start"],
                name="connection_started_lookup",
            ),
            models.Index(
                fields=["state", "lease_expires_at"],
                name="connection_lease_idx",
            ),
            models.Index(
                fields=["retention_hold", "terminal_at"],
                name="connection_terminal_idx",
            ),
        ]


class ConnectionAuditEvent(models.Model):
    KIND_OPENED = "opened"
    KIND_AUTHORIZED = "authorized"
    KIND_CONTROLLER_BOUND = "controller_bound"
    KIND_NOTE = "note"
    KIND_FILE = "file"
    KIND_ALARM = "alarm"
    KIND_CLOSED = "closed"
    KIND_ABORTED = "aborted"
    KIND_EXPIRED = "expired"
    KINDS = (
        (KIND_OPENED, "Opened"),
        (KIND_AUTHORIZED, "Authorized"),
        (KIND_CONTROLLER_BOUND, "Controller bound"),
        (KIND_NOTE, "Note"),
        (KIND_FILE, "File"),
        (KIND_ALARM, "Alarm"),
        (KIND_CLOSED, "Closed"),
        (KIND_ABORTED, "Aborted"),
        (KIND_EXPIRED, "Expired"),
    )

    id = models.AutoField(verbose_name="ID", primary_key=True)
    event_id = models.UUIDField(editable=False, unique=True)
    connection = models.ForeignKey(
        ConnLog,
        editable=False,
        on_delete=models.CASCADE,
        related_name="events",
    )
    sequence = models.PositiveBigIntegerField(editable=False)
    kind = models.CharField(max_length=24, choices=KINDS, editable=False)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        editable=False,
        on_delete=models.SET_NULL,
        related_name="connection_audit_events",
    )
    actor_id_at_event = models.PositiveBigIntegerField(editable=False)
    reporter_device_uuid = models.CharField(max_length=344, blank=True, default="", editable=False)
    reporter_device_id_at_event = models.PositiveBigIntegerField(null=True, blank=True, editable=False)
    reporter_device_generation = models.PositiveBigIntegerField(null=True, blank=True, editable=False)
    reporter_sequence = models.PositiveBigIntegerField(null=True, blank=True, editable=False)
    payload_digest = models.CharField(max_length=64, blank=True, default="", editable=False)
    acknowledgement = models.JSONField(blank=True, default=dict, editable=False)
    details = models.JSONField(blank=True, default=dict, editable=False)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        ordering = ("connection_id", "sequence")
        constraints = [
            models.UniqueConstraint(
                fields=["connection", "sequence"],
                name="unique_connection_audit_sequence",
            ),
            models.CheckConstraint(
                condition=models.Q(sequence__gte=1),
                name="positive_connection_audit_sequence",
            ),
            models.CheckConstraint(
                condition=models.Q(reporter_sequence__isnull=True) | models.Q(reporter_sequence__gte=1),
                name="positive_audit_reporter_sequence",
            ),
            models.UniqueConstraint(
                fields=["connection", "reporter_sequence"],
                condition=models.Q(reporter_sequence__isnull=False),
                name="unique_audit_reporter_sequence",
            ),
        ]


class ConnLogAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "guid",
        "conn_id",
        "from_ip",
        "from_id",
        "rid",
        "conn_type",
        "primary_auth",
        "two_factor",
        "host_device",
        "host_device_name_at_create",
        "controller_device",
        "controller_device_name_at_bind",
        "state",
        "last_seen_at",
        "terminal_at",
        "conn_start",
        "conn_end",
    )
    search_fields = ("guid", "from_ip", "from_id", "rid", "session_id", "audit_ref")
    list_filter = ("state", "conn_type", "primary_auth", "two_factor", "conn_start", "terminal_at")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class ConnectionAuditEventAdmin(admin.ModelAdmin):
    list_display = (
        "connection",
        "sequence",
        "reporter_sequence",
        "kind",
        "actor_id_at_event",
        "reporter_device_id_at_event",
        "reporter_device_generation",
        "actor",
        "created_at",
    )
    search_fields = ("event_id", "payload_digest", "connection__guid", "actor__username")
    list_filter = ("kind", "created_at")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class FileLog(models.Model):
    STATE_STARTED = "started"
    STATE_PROGRESS = "progress"
    STATE_COMPLETED = "completed"
    STATE_FAILED = "failed"
    STATE_CANCELLED = "cancelled"
    STATE_UNKNOWN = "unknown"
    STATES = (
        (STATE_STARTED, "Started"),
        (STATE_PROGRESS, "Progress"),
        (STATE_COMPLETED, "Completed"),
        (STATE_FAILED, "Failed"),
        (STATE_CANCELLED, "Cancelled"),
        (STATE_UNKNOWN, "Unknown"),
    )
    OPEN_STATES = (STATE_STARTED, STATE_PROGRESS)
    TERMINAL_STATES = (STATE_COMPLETED, STATE_FAILED, STATE_CANCELLED, STATE_UNKNOWN)

    SOURCE_FILE_TRANSFER = "file_transfer"
    SOURCE_CLIPBOARD = "clipboard"
    SOURCE_PRINTER = "printer"
    SOURCE_KINDS = (
        (SOURCE_FILE_TRANSFER, "File transfer"),
        (SOURCE_CLIPBOARD, "Clipboard"),
        (SOURCE_PRINTER, "Printer"),
    )

    id = models.AutoField(verbose_name="ID", primary_key=True)
    file = models.CharField(verbose_name="Path", max_length=500)
    remote_id = models.CharField(verbose_name="Remote ID", max_length=16, default="0")
    user_id = models.CharField(verbose_name="User ID", max_length=16, default="0")
    user_ip = models.GenericIPAddressField(verbose_name="User IP")
    filesize = models.PositiveBigIntegerField(verbose_name="Filesize", default=0)
    direction = models.IntegerField(verbose_name="Direction", default=0)
    logged_at = models.DateTimeField(
        verbose_name="Logged At",
        default=timezone.now,
        db_index=True,
    )
    details = models.JSONField(verbose_name="Details", blank=True, default=dict)
    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reported_file_logs",
    )
    reporter_device_uuid = models.CharField(
        verbose_name="Reporter Device UUID",
        max_length=344,
        blank=True,
        default="",
    )
    audit_version = models.PositiveSmallIntegerField(default=1, editable=False)
    connection = models.ForeignKey(
        ConnLog,
        null=True,
        blank=True,
        editable=False,
        on_delete=models.PROTECT,
        related_name="file_logs",
    )
    event = models.OneToOneField(
        ConnectionAuditEvent,
        null=True,
        blank=True,
        editable=False,
        on_delete=models.PROTECT,
        related_name="file_log",
    )
    transfer_id = models.UUIDField(null=True, blank=True, editable=False, unique=True)
    transfer_revision = models.PositiveBigIntegerField(default=0, editable=False)
    state = models.CharField(
        max_length=12,
        choices=STATES,
        default=STATE_UNKNOWN,
        editable=False,
    )
    is_file = models.BooleanField(default=False, editable=False)
    planned_file_count = models.PositiveBigIntegerField(default=0, editable=False)
    planned_bytes = models.PositiveBigIntegerField(default=0, editable=False)
    transferred_bytes = models.PositiveBigIntegerField(default=0, editable=False)
    sample_files = models.JSONField(blank=True, default=list, editable=False)
    source_kind = models.CharField(
        max_length=16,
        choices=SOURCE_KINDS,
        default=SOURCE_FILE_TRANSFER,
        editable=False,
    )
    started_at = models.DateTimeField(null=True, blank=True, editable=False)
    terminal_at = models.DateTimeField(null=True, blank=True, editable=False)
    terminal_reason = models.CharField(max_length=256, blank=True, default="", editable=False)

    class Meta:
        ordering = ("-logged_at",)
        verbose_name = _("文件传输日志")
        verbose_name_plural = _("文件传输日志列表")
        constraints = [
            models.CheckConstraint(
                condition=models.Q(direction__in=(0, 1)),
                name="valid_file_transfer_direction",
            ),
            models.CheckConstraint(
                condition=models.Q(audit_version=1)
                | models.Q(audit_version__in=(2, 3), connection__isnull=False, event__isnull=False)
                | models.Q(
                    audit_version=4,
                    connection__isnull=False,
                    event__isnull=False,
                    transfer_id__isnull=False,
                    transfer_revision__gte=1,
                    started_at__isnull=False,
                    transferred_bytes__lte=models.F("planned_bytes"),
                ),
                name="valid_file_audit_binding",
            ),
            models.CheckConstraint(
                condition=~models.Q(audit_version=4)
                | models.Q(
                    state__in=("started", "progress"),
                    terminal_at__isnull=True,
                    terminal_reason="",
                )
                | models.Q(
                    state="completed",
                    terminal_at__isnull=False,
                    terminal_reason="",
                )
                | models.Q(
                    state__in=("failed", "cancelled", "unknown"),
                    terminal_at__isnull=False,
                    terminal_reason__gt="",
                ),
                name="valid_file_transfer_lifecycle",
            ),
        ]
        indexes = [
            models.Index(
                fields=["connection", "logged_at"],
                name="file_legacy_retention_idx",
            ),
            models.Index(
                fields=["connection", "state"],
                name="file_transfer_state_idx",
            ),
        ]


class FileLogAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "file",
        "remote_id",
        "user_id",
        "user_ip",
        "filesize",
        "planned_bytes",
        "transferred_bytes",
        "state",
        "direction",
        "logged_at",
    )
    search_fields = ("transfer_id", "file", "remote_id", "user_id", "user_ip")
    list_filter = ("state", "source_kind", "direction", "logged_at")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class FileTransferAuditEvent(models.Model):
    id = models.AutoField(verbose_name="ID", primary_key=True)
    transfer = models.ForeignKey(
        FileLog,
        editable=False,
        on_delete=models.CASCADE,
        related_name="transfer_events",
    )
    connection_event = models.ForeignKey(
        ConnectionAuditEvent,
        editable=False,
        on_delete=models.PROTECT,
        related_name="file_transfer_events",
    )
    revision = models.PositiveBigIntegerField(editable=False)
    state = models.CharField(max_length=12, choices=FileLog.STATES, editable=False)
    transferred_bytes = models.PositiveBigIntegerField(default=0, editable=False)
    terminal_reason = models.CharField(max_length=256, blank=True, default="", editable=False)
    source_kind = models.CharField(
        max_length=16,
        choices=FileLog.SOURCE_KINDS,
        default=FileLog.SOURCE_FILE_TRANSFER,
        editable=False,
    )
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        ordering = ("transfer_id", "revision")
        constraints = [
            models.UniqueConstraint(
                fields=["transfer", "revision"],
                name="unique_file_transfer_revision",
            ),
            models.CheckConstraint(
                condition=models.Q(revision__gte=1),
                name="positive_file_transfer_revision",
            ),
            models.CheckConstraint(
                condition=models.Q(
                    state__in=(FileLog.STATE_STARTED, FileLog.STATE_PROGRESS, FileLog.STATE_COMPLETED),
                    terminal_reason="",
                )
                | models.Q(
                    state__in=(FileLog.STATE_FAILED, FileLog.STATE_CANCELLED, FileLog.STATE_UNKNOWN),
                    terminal_reason__gt="",
                ),
                name="valid_file_transfer_event_state",
            ),
        ]


class FileTransferAuditEventAdmin(admin.ModelAdmin):
    list_display = (
        "transfer",
        "revision",
        "state",
        "transferred_bytes",
        "source_kind",
        "created_at",
    )
    search_fields = ("transfer__transfer_id", "connection_event__event_id")
    list_filter = ("state", "source_kind", "created_at")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


def share_link_expiry():
    return timezone.now() + datetime.timedelta(minutes=15)


class ShareLink(models.Model):
    """分享链接"""

    creator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="created_share_links",
    )
    shash = models.CharField(verbose_name=_("链接Key哈希"), max_length=64, unique=True)
    token_prefix = models.CharField(verbose_name=_("链接前缀"), max_length=12)
    peers = models.ManyToManyField(
        RemotePeer,
        related_name="share_links",
        verbose_name=_("机器列表"),
    )
    is_used = models.BooleanField(verbose_name=_("是否使用"), default=False)
    is_expired = models.BooleanField(verbose_name=_("是否过期"), default=False)
    create_time = models.DateTimeField(verbose_name=_("生成时间"), auto_now_add=True)
    expires_at = models.DateTimeField(
        verbose_name=_("过期时间"),
        default=share_link_expiry,
        db_index=True,
    )
    used_at = models.DateTimeField(verbose_name=_("使用时间"), null=True, blank=True)
    used_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="accepted_share_links",
    )

    class Meta:
        ordering = ("-create_time",)
        verbose_name = _("分享链接")
        verbose_name_plural = _("链接列表")
        indexes = [
            models.Index(
                fields=["creator", "is_used", "is_expired", "expires_at"],
                name="share_link_active_lookup",
            ),
        ]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(
                        is_used=True,
                        used_at__isnull=False,
                        used_by__isnull=False,
                    )
                    | models.Q(
                        is_used=False,
                        used_at__isnull=True,
                        used_by__isnull=True,
                    )
                ),
                name="consistent_share_link_consumption",
            ),
        ]


@receiver(m2m_changed, sender=ShareLink.peers.through)
def validate_share_link_peer_owner(
    sender,
    instance,
    action,
    reverse,
    pk_set,
    **kwargs,
):
    """A share link may disclose only peers owned by its creator."""
    if action != "pre_add" or not pk_set:
        return
    if reverse:
        has_mismatch = (
            ShareLink.objects.filter(pk__in=pk_set)
            .exclude(
                creator_id=instance.profile.owner_id,
            )
            .exists()
        )
    else:
        has_mismatch = (
            RemotePeer.objects.filter(pk__in=pk_set)
            .exclude(
                profile__owner_id=instance.creator_id,
            )
            .exists()
        )
    if has_mismatch:
        raise ValidationError(_("分享链接只能包含创建者拥有的设备。"))


class StrategyProfile(models.Model):
    objects = StrategyProfileQuerySet.as_manager()

    guid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    name = models.CharField(verbose_name=_("策略名称"), max_length=60, unique=True)
    config_options = models.JSONField(verbose_name=_("配置项"), blank=True, default=dict)
    enabled = models.BooleanField(verbose_name=_("是否启用"), default=True)
    updated_at = models.DateTimeField(verbose_name=_("更新时间"), auto_now=True)

    class Meta:
        ordering = ("name",)
        verbose_name = _("策略")
        verbose_name_plural = _("策略列表")

    def __str__(self):
        return self.name or f"Strategy {self.pk}"

    def clean(self):
        super().clean()
        if not isinstance(self.config_options, dict) or any(
            not isinstance(key, str) or not isinstance(value, str) for key, value in self.config_options.items()
        ):
            raise ValidationError(_("策略配置必须是字符串键值映射。"))

    def save(self, *args, **kwargs):
        update_fields = kwargs.get("update_fields")
        if not self.pk or (update_fields is not None and not POLICY_CONTENT_FIELDS.intersection(update_fields)):
            return super().save(*args, **kwargs)
        database = kwargs.get("using") or router.db_for_write(type(self), instance=self)
        from api.policy_generation import (
            bump_device_policy_generations,
            device_ids_affected_by_strategies,
        )

        with transaction.atomic(using=database):
            previous = (
                type(self)
                ._base_manager.using(database)
                .select_for_update()
                .filter(pk=self.pk)
                .values("config_options", "enabled")
                .first()
            )
            result = super().save(*args, **kwargs)
            changed_fields = (
                POLICY_CONTENT_FIELDS if update_fields is None else POLICY_CONTENT_FIELDS.intersection(update_fields)
            )
            if previous is not None and any(previous[field] != getattr(self, field) for field in changed_fields):
                device_ids = device_ids_affected_by_strategies(
                    (self.pk,),
                    using=database,
                )
                bump_device_policy_generations(device_ids, using=database)
            return result

    def delete(self, *args, **kwargs):
        if not self.pk:
            return super().delete(*args, **kwargs)
        database = kwargs.get("using") or router.db_for_write(type(self), instance=self)
        from api.policy_generation import (
            bump_device_policy_generations,
            device_ids_affected_by_strategies,
        )

        with transaction.atomic(using=database):
            type(self)._base_manager.using(database).select_for_update().get(pk=self.pk)
            device_ids = device_ids_affected_by_strategies((self.pk,), using=database)
            result = super().delete(*args, **kwargs)
            bump_device_policy_generations(device_ids, using=database)
            return result


class DeviceGroup(models.Model):
    objects = DeviceGroupQuerySet.as_manager()

    guid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    name = models.CharField(verbose_name=_("设备组名称"), max_length=120, unique=True)
    note = models.TextField(verbose_name=_("备注"), blank=True, default="")
    allowed_incomings = models.JSONField(
        verbose_name=_("允许来源"),
        blank=True,
        default=list,
    )
    strategy = models.ForeignKey(
        StrategyProfile,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="device_groups",
        verbose_name=_("策略"),
    )
    created_at = models.DateTimeField(verbose_name=_("创建时间"), default=timezone.now)
    updated_at = models.DateTimeField(verbose_name=_("更新时间"), auto_now=True)

    class Meta:
        ordering = ("name",)
        verbose_name = _("设备组")
        verbose_name_plural = _("设备组列表")

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        update_fields = kwargs.get("update_fields")
        if not self.pk or (update_fields is not None and not {"strategy", "strategy_id"}.intersection(update_fields)):
            return super().save(*args, **kwargs)
        database = kwargs.get("using") or router.db_for_write(type(self), instance=self)
        from api.policy_generation import (
            bump_device_policy_generations,
            device_ids_affected_by_groups,
        )

        with transaction.atomic(using=database):
            previous_strategy_id = (
                type(self)
                ._base_manager.using(database)
                .select_for_update()
                .filter(pk=self.pk)
                .values_list("strategy_id", flat=True)
                .first()
            )
            result = super().save(*args, **kwargs)
            if previous_strategy_id != self.strategy_id:
                device_ids = device_ids_affected_by_groups((self.pk,), using=database)
                bump_device_policy_generations(device_ids, using=database)
            return result

    def delete(self, *args, **kwargs):
        if not self.pk:
            return super().delete(*args, **kwargs)
        database = kwargs.get("using") or router.db_for_write(type(self), instance=self)
        from api.policy_generation import (
            bump_device_policy_generations,
            device_ids_affected_by_groups,
        )

        with transaction.atomic(using=database):
            type(self)._base_manager.using(database).select_for_update().get(pk=self.pk)
            device_ids = device_ids_affected_by_groups((self.pk,), using=database)
            result = super().delete(*args, **kwargs)
            bump_device_policy_generations(device_ids, using=database)
            return result


class AddressBookProfile(models.Model):
    guid = models.CharField(verbose_name=_("地址簿GUID"), max_length=60, unique=True)
    name = models.CharField(verbose_name=_("地址簿名称"), max_length=60)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="address_book_profiles")
    note = models.TextField(verbose_name=_("备注"), blank=True, default="")
    rule = models.IntegerField(verbose_name=_("共享权限"), default=1)
    info = models.JSONField(verbose_name=_("扩展信息"), blank=True, default=dict)
    default_password = EncryptedTextField(verbose_name=_("默认共享密码"), max_length=60, blank=True, default="")
    authorization_generation = models.PositiveBigIntegerField(default=0, editable=False)
    created_at = models.DateTimeField(verbose_name=_("创建时间"), default=timezone.now)
    updated_at = models.DateTimeField(verbose_name=_("更新时间"), auto_now=True)

    class Meta:
        ordering = ("name",)
        verbose_name = _("地址簿")
        verbose_name_plural = _("地址簿列表")
        constraints = [
            models.UniqueConstraint(
                fields=["owner", "name"],
                name="unique_address_book_name_per_owner",
            ),
            models.CheckConstraint(
                condition=models.Q(rule__gte=1, rule__lte=3),
                name="valid_address_book_profile_rule",
            ),
        ]

    def __str__(self):
        owner = getattr(self.owner, "username", "") or self.owner_id or "-"
        return f"{self.name} ({owner})"

    def save(self, *args, **kwargs):
        if not self.pk:
            self.authorization_generation = 0
            return super().save(*args, **kwargs)
        update_fields = kwargs.get("update_fields")
        database = kwargs.get("using") or router.db_for_write(type(self), instance=self)
        with transaction.atomic(using=database):
            previous = (
                type(self)
                ._base_manager.using(database)
                .select_for_update()
                .filter(pk=self.pk)
                .values("owner_id", "authorization_generation")
                .first()
            )
            if previous is None:
                return super().save(*args, **kwargs)
            current_generation = previous["authorization_generation"]
            requested_generation = self.authorization_generation
            if update_fields is not None and "authorization_generation" in update_fields:
                if not isinstance(requested_generation, int) or requested_generation != current_generation + 1:
                    raise ValueError("authorization_generation is managed internally")
                if requested_generation > (1 << 63) - 1:
                    raise AuthorizationGenerationExhausted("Address-book authorization generation exhausted")
            else:
                requested_generation = current_generation
            if previous["owner_id"] != self.owner_id:
                if current_generation >= (1 << 63) - 1:
                    raise AuthorizationGenerationExhausted("Address-book authorization generation exhausted")
                requested_generation = current_generation + 1
                if update_fields is not None:
                    kwargs["update_fields"] = tuple({*update_fields, "authorization_generation"})
            self.authorization_generation = requested_generation
            return super().save(*args, **kwargs)


class AddressBookShare(models.Model):
    guid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    profile = models.ForeignKey(AddressBookProfile, on_delete=models.CASCADE, related_name="shares")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="address_book_shares")
    rule = models.IntegerField(verbose_name=_("共享权限"), default=1)
    created_at = models.DateTimeField(verbose_name=_("创建时间"), default=timezone.now)

    class Meta:
        verbose_name = _("地址簿共享")
        verbose_name_plural = _("地址簿共享列表")
        constraints = [
            models.UniqueConstraint(
                fields=["profile", "user"],
                name="unique_address_book_share_user",
            ),
            models.CheckConstraint(
                condition=models.Q(rule__gte=1, rule__lte=3),
                name="valid_address_book_share_rule",
            ),
        ]

    def __str__(self):
        profile = getattr(self.profile, "name", "") or self.profile_id or "-"
        user = getattr(self.user, "username", "") or self.user_id or "-"
        return f"{profile} -> {user}"


class AddressBookRule(models.Model):
    guid = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    profile = models.ForeignKey(AddressBookProfile, on_delete=models.CASCADE, related_name="rules")
    rule = models.IntegerField(verbose_name=_("共享权限"), default=1)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True, related_name="address_book_rules"
    )
    group = models.ForeignKey(Group, on_delete=models.CASCADE, null=True, blank=True, related_name="address_book_rules")
    is_everyone = models.BooleanField(default=False)
    target_key = models.CharField(max_length=32, editable=False)
    created_at = models.DateTimeField(verbose_name=_("创建时间"), default=timezone.now)
    updated_at = models.DateTimeField(verbose_name=_("更新时间"), auto_now=True)

    class Meta:
        verbose_name = _("地址簿规则")
        verbose_name_plural = _("地址簿规则列表")
        constraints = [
            models.UniqueConstraint(
                fields=["profile", "target_key"],
                name="unique_address_book_rule_target",
            ),
            models.CheckConstraint(
                condition=models.Q(rule__gte=1, rule__lte=3),
                name="valid_address_book_rule",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(is_everyone=True, user__isnull=True, group__isnull=True)
                    | models.Q(is_everyone=False, user__isnull=False, group__isnull=True)
                    | models.Q(is_everyone=False, user__isnull=True, group__isnull=False)
                ),
                name="one_address_book_rule_target",
            ),
        ]

    def save(self, *args, **kwargs):
        if self.is_everyone and not self.user_id and not self.group_id:
            self.target_key = "everyone"
        elif not self.is_everyone and self.user_id and not self.group_id:
            self.target_key = f"user:{self.user_id}"
        elif not self.is_everyone and self.group_id and not self.user_id:
            self.target_key = f"group:{self.group_id}"
        else:
            raise ValueError("Address-book rule must have exactly one target")
        super().save(*args, **kwargs)

    def __str__(self):
        if self.is_everyone:
            return "Everyone"
        if self.user_id:
            return getattr(self.user, "username", "") or f"User {self.user_id}"
        if self.group_id:
            return getattr(self.group, "name", "") or f"Group {self.group_id}"
        return self.guid or f"Rule {self.pk}"


class AddressBookRuleAudit(models.Model):
    profile = models.ForeignKey(
        AddressBookProfile,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="rule_audits",
    )
    profile_guid = models.CharField(max_length=60, default="", db_index=True)
    profile_name = models.CharField(max_length=60, default="")
    profile_owner_name = models.CharField(max_length=150, default="")
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="address_book_rule_audits",
    )
    action = models.CharField(max_length=32)
    target_type = models.CharField(max_length=16)
    target_name = models.CharField(max_length=150, blank=True, default="")
    rule = models.IntegerField(verbose_name=_("共享权限"), default=1)
    details = models.JSONField(blank=True, default=dict)
    created_at = models.DateTimeField(verbose_name=_("创建时间"), default=timezone.now)

    class Meta:
        ordering = ("-created_at", "-id")
        verbose_name = _("地址簿规则审计")
        verbose_name_plural = _("地址簿规则审计列表")
        indexes = [
            models.Index(
                fields=["-created_at", "-id"],
                name="ab_audit_created_pk_idx",
            ),
            GinIndex(
                OpClass(
                    Upper(
                        Cast(
                            audit_search_document(
                                "profile_name",
                                "profile_guid",
                                "profile_owner_name",
                                "target_name",
                                "action",
                            ),
                            models.TextField(),
                        )
                    ),
                    name="gin_trgm_ops",
                ),
                name="ab_audit_search_trgm_idx",
            ),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(rule__gte=1, rule__lte=3),
                name="valid_address_book_audit_rule",
            ),
            models.CheckConstraint(
                condition=models.Q(target_type__in=("user", "group", "everyone", "profile")),
                name="valid_address_book_audit_target",
            ),
        ]

    def __str__(self):
        return f"{self.action} {self.target_type}:{self.target_name}"


@receiver(pre_delete, sender=AddressBookProfile)
def _preserve_address_book_audit(sender, instance, using, **kwargs):
    """Write a profile tombstone before the profile FK is nulled."""

    from api.address_book_authorization import record_profile_tombstone

    record_profile_tombstone(instance, actor=getattr(instance, "_audit_actor", None), using=using)


class AlarmLog(models.Model):
    TYPE_IP_WHITELIST = 0
    TYPE_EXCESSIVE_ATTEMPTS = 1
    TYPE_RAPID_ATTEMPTS = 2
    TYPE_IPV6_PREFIX_ATTEMPTS = 6
    TYPE_OS_LOGIN_BACKOFF = 7
    TYPE_OS_LOGIN_CONCURRENCY = 8
    TYPE_SESSION_SCOPE_VIOLATION = 9
    TYPES = ALARM_TYPES

    typ = models.IntegerField(verbose_name="Type", default=0)
    info = models.JSONField(verbose_name="Info", blank=True, default=dict)
    reporter_device_id = models.CharField(
        verbose_name="Reporter Device ID",
        max_length=16,
    )
    created_at = models.DateTimeField(verbose_name="Created At", default=timezone.now)
    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reported_alarm_logs",
    )
    reporter_device_uuid = models.CharField(
        verbose_name="Reporter Device UUID",
        max_length=344,
        blank=True,
        default="",
    )
    conn_id = models.PositiveIntegerField(
        verbose_name="Connection ID",
        null=True,
        blank=True,
    )
    audit_ref = models.CharField(
        verbose_name="Audit Reference",
        max_length=256,
        blank=True,
        default="",
    )
    audit_version = models.PositiveSmallIntegerField(default=1, editable=False)
    connection = models.ForeignKey(
        ConnLog,
        null=True,
        blank=True,
        editable=False,
        on_delete=models.PROTECT,
        related_name="alarm_logs",
    )
    event = models.OneToOneField(
        ConnectionAuditEvent,
        null=True,
        blank=True,
        editable=False,
        on_delete=models.PROTECT,
        related_name="alarm_log",
    )

    class Meta:
        ordering = ("-created_at", "-id")
        verbose_name = _("告警日志")
        verbose_name_plural = _("告警日志列表")
        constraints = [
            models.CheckConstraint(
                condition=models.Q(typ__in=ALARM_TYPES),
                name="valid_alarm_type",
            ),
            models.CheckConstraint(
                condition=models.Q(audit_version=1)
                | models.Q(audit_version__in=(2, 3), connection__isnull=False, event__isnull=False),
                name="valid_alarm_audit_binding",
            ),
        ]
        indexes = [
            models.Index(
                fields=["-created_at", "-id"],
                name="alarm_created_pk_idx",
            ),
            models.Index(
                fields=["typ", "-created_at", "-id"],
                name="alarm_type_created_pk_idx",
            ),
            GinIndex(
                OpClass(
                    Upper(
                        Cast(
                            audit_search_document(
                                "reporter_device_id",
                                "reporter_device_uuid",
                                "audit_ref",
                            ),
                            models.TextField(),
                        )
                    ),
                    name="gin_trgm_ops",
                ),
                name="alarm_search_trgm_idx",
            ),
            models.Index(
                fields=["connection", "created_at"],
                name="alarm_legacy_ret_idx",
            ),
        ]

    def __str__(self):
        return f"Alarm {self.typ} #{self.pk}"


class OidcPendingAuth(models.Model):
    """Pending OIDC authorization state, shared across workers."""

    STATUS_PENDING = "pending"
    STATUS_DONE = "done"
    STATUS_ERROR = "error"

    state = models.CharField(verbose_name="State", max_length=64, primary_key=True)
    poll_code_hash = models.CharField(
        verbose_name="Poll Code Hash",
        max_length=64,
        unique=True,
        db_index=True,
    )
    provider = models.CharField(verbose_name="Provider", max_length=64)
    request_ip = models.GenericIPAddressField(
        verbose_name="Request IP",
        default="0.0.0.0",  # noqa: S104 - non-routable audit sentinel, not a bind address
        db_index=True,
    )
    rid = models.CharField(verbose_name="Camellia ID", max_length=16, blank=True, default="")
    device_uuid = models.CharField(verbose_name="Device UUID", max_length=344, blank=True, default="")
    device_info = models.JSONField(
        verbose_name="Device Info",
        blank=True,
        default=dict,
    )
    device_proof = models.JSONField(blank=True, default=dict)
    nonce = EncryptedTextField(verbose_name="OIDC Nonce", max_length=64)
    code_verifier = EncryptedTextField(verbose_name="PKCE Code Verifier", max_length=128)
    status = models.CharField(verbose_name="Status", max_length=16, default=STATUS_PENDING, db_index=True)
    error_code = models.CharField(verbose_name="Error Code", max_length=64, blank=True, default="")
    authenticated_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="completed_oidc_authorizations",
    )
    created_at = models.DateTimeField(verbose_name="Created At", auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at",)
        verbose_name = _("OIDC待处理授权")
        verbose_name_plural = _("OIDC待处理授权列表")
        constraints = [
            models.CheckConstraint(
                condition=models.Q(
                    status__in=(
                        "pending",
                        "done",
                        "error",
                    ),
                ),
                name="valid_oidc_pending_status",
            ),
        ]

    def __str__(self):
        return f"{self.provider}:{self.state[:8]}…"


class OidcIdentity(models.Model):
    """Stable OIDC identity binding.

    Human-readable usernames and email addresses can be renamed or reused.
    Only the issuer and subject pair is an OIDC account identifier.
    """

    issuer = models.URLField(verbose_name="Issuer", max_length=512)
    subject = models.CharField(verbose_name="Subject", max_length=255)
    provider = models.CharField(verbose_name="Provider", max_length=64)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="oidc_identities",
    )
    is_auto_provisioned = models.BooleanField(verbose_name="Policy-managed auto provision", default=False)
    last_username = models.CharField(verbose_name="Last Username", max_length=255, blank=True, default="")
    last_email = models.EmailField(verbose_name="Last Email", max_length=254, blank=True, default="")
    created_at = models.DateTimeField(verbose_name="Created At", default=timezone.now)
    updated_at = models.DateTimeField(verbose_name="Updated At", auto_now=True)

    class Meta:
        ordering = ("issuer", "subject")
        constraints = [
            models.UniqueConstraint(
                fields=["issuer", "subject"],
                name="unique_oidc_issuer_subject",
            ),
        ]
        verbose_name = _("OIDC身份")
        verbose_name_plural = _("OIDC身份列表")

    def __str__(self):
        return f"{self.issuer}#{self.subject}"


class LoginAttempt(models.Model):
    """Failed credential login, kept briefly for IP rate limiting."""

    ip = models.GenericIPAddressField(verbose_name="IP")
    username = models.CharField(verbose_name="用户名", max_length=150, blank=True, default="")
    scope_hash = models.CharField(verbose_name="Rate Scope Hash", max_length=64, default="")
    created_at = models.DateTimeField(verbose_name="Created At", auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at",)
        verbose_name = _("失败登录")
        verbose_name_plural = _("失败登录列表")
        indexes = [
            models.Index(
                fields=["ip", "username", "-created_at"],
                name="login_attempt_scope_lookup",
            ),
            models.Index(
                fields=["ip", "scope_hash", "-created_at"],
                name="login_attempt_atomic_scope",
            ),
        ]

    def __str__(self):
        return f"{self.ip} {self.username}"


class LoginAdmissionLock(models.Model):
    """One database row serializes all login budgets for an IP address."""

    ip = models.GenericIPAddressField(primary_key=True, verbose_name="IP")
    updated_at = models.DateTimeField(auto_now=True, db_index=True)

    class Meta:
        verbose_name = _("登录准入锁")
        verbose_name_plural = _("登录准入锁列表")

    def __str__(self):
        return self.ip


class RequestRateBucket(models.Model):
    """Hashed, fixed-window request budget shared by every replica."""

    key_hash = models.CharField(max_length=64, primary_key=True, editable=False)
    scope = models.CharField(max_length=24, editable=False)
    group = models.CharField(max_length=32, editable=False)
    window_seconds = models.PositiveSmallIntegerField(editable=False)
    used = models.PositiveBigIntegerField(default=0, editable=False)
    expires_at = models.DateTimeField(db_index=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        ordering = ("expires_at", "key_hash")
        constraints = [
            models.CheckConstraint(
                condition=models.Q(window_seconds__gte=1, window_seconds__lte=3600),
                name="valid_rate_bucket_window",
            ),
        ]

    def __str__(self):
        return f"{self.scope}:{self.group}:{self.key_hash[:12]}"


class RequestRateLease(models.Model):
    """Short-lived cross-replica concurrency claim; never stores raw identity."""

    request_id = models.CharField(max_length=32, editable=False)
    key_hash = models.CharField(max_length=64, editable=False)
    scope = models.CharField(max_length=24, editable=False)
    group = models.CharField(max_length=32, editable=False)
    expires_at = models.DateTimeField(db_index=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)

    class Meta:
        ordering = ("expires_at", "pk")
        constraints = [
            models.UniqueConstraint(
                fields=("request_id", "key_hash"),
                name="unique_rate_lease_request_key",
            ),
        ]
        indexes = [
            models.Index(
                fields=("key_hash", "expires_at"),
                name="rate_lease_key_exp_idx",
            ),
        ]

    def __str__(self):
        return f"{self.scope}:{self.group}:{self.request_id}"


class RecordingUpload(models.Model):
    """Durable authority for one versioned recording upload."""

    STATE_ACTIVE = "active"
    STATE_FINALIZED = "finalized"
    STATE_ABORTED = "aborted"
    STATE_CHOICES = (
        (STATE_ACTIVE, "Active"),
        (STATE_FINALIZED, "Finalized"),
        (STATE_ABORTED, "Aborted"),
    )

    upload_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    create_id = models.UUIDField(editable=False)
    device = models.ForeignKey(
        RemoteDevice,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="recording_uploads",
        editable=False,
    )
    device_id_at_create = models.PositiveBigIntegerField(editable=False)
    owner_id_at_create = models.PositiveBigIntegerField(editable=False)
    deployment_generation = models.PositiveBigIntegerField(editable=False)
    device_rid_at_create = models.CharField(max_length=16, editable=False)
    device_uuid_at_create = models.CharField(max_length=344, editable=False)
    storage_object_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    storage_version = models.PositiveSmallIntegerField(default=2, editable=False)
    storage_namespace = models.CharField(max_length=64, editable=False, unique=True)
    filename = models.CharField(max_length=255, editable=False)
    state = models.CharField(max_length=12, choices=STATE_CHOICES, default=STATE_ACTIVE, editable=False)
    encryption_version = models.PositiveSmallIntegerField(editable=False)
    data_key_kek_id = models.CharField(max_length=32, editable=False)
    encrypted_data_key = EncryptedTextField(max_length=44, editable=False)
    committed_offset = models.PositiveBigIntegerField(default=0, editable=False)
    storage_offset = models.PositiveBigIntegerField(editable=False)
    ciphertext_size = models.PositiveBigIntegerField(null=True, blank=True, editable=False)
    ciphertext_digest = models.CharField(max_length=64, blank=True, default="", editable=False)
    revision = models.PositiveBigIntegerField(default=0, editable=False)
    expected_size = models.PositiveBigIntegerField(null=True, blank=True, editable=False)
    expected_digest = models.CharField(max_length=64, blank=True, default="", editable=False)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    heartbeat_at = models.DateTimeField(default=timezone.now, db_index=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    finalized_at = models.DateTimeField(null=True, blank=True, editable=False)
    aborted_at = models.DateTimeField(null=True, blank=True, editable=False)
    retention_hold = models.BooleanField(default=False, db_index=True, editable=False)
    retention_hold_reason = models.CharField(max_length=512, blank=True, default="", editable=False)
    retention_hold_at = models.DateTimeField(null=True, blank=True, editable=False)

    class Meta:
        ordering = ("created_at", "upload_id")
        constraints = [
            models.UniqueConstraint(
                fields=("device", "create_id"),
                name="unique_recording_create_id",
            ),
            models.UniqueConstraint(
                fields=("device", "filename"),
                name="unique_recording_filename",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(
                        state="active",
                        finalized_at__isnull=True,
                        aborted_at__isnull=True,
                        expected_size__isnull=True,
                        expected_digest="",
                    )
                    | models.Q(
                        state="finalized",
                        finalized_at__isnull=False,
                        aborted_at__isnull=True,
                        expected_size__isnull=False,
                    )
                    & ~models.Q(expected_digest="")
                    | models.Q(
                        state="aborted",
                        finalized_at__isnull=True,
                        aborted_at__isnull=False,
                        expected_size__isnull=True,
                        expected_digest="",
                    )
                ),
                name="valid_recording_upload_state",
            ),
            models.CheckConstraint(
                condition=models.Q(expected_size__isnull=True) | models.Q(committed_offset=models.F("expected_size")),
                name="recording_final_size_committed",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(revision=0, committed_offset=0) | models.Q(revision__gte=1, committed_offset__gte=1)
                ),
                name="valid_recording_upload_position",
            ),
            models.CheckConstraint(
                condition=models.Q(encryption_version=RECORDING_ENCRYPTION_VERSION) & ~models.Q(encrypted_data_key=""),
                name="valid_recording_crypto_format",
            ),
            models.CheckConstraint(
                condition=models.Q(storage_offset__gte=RECORDING_HEADER_SIZE)
                & models.Q(storage_offset__gt=models.F("committed_offset")),
                name="recording_ciphertext_offset",
            ),
            models.CheckConstraint(
                condition=models.Q(storage_version=2),
                name="valid_recording_storage_version",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(
                        state="finalized",
                        ciphertext_size=models.F("storage_offset"),
                    )
                    & ~models.Q(ciphertext_digest="")
                    | ~models.Q(state="finalized") & models.Q(ciphertext_size__isnull=True, ciphertext_digest="")
                ),
                name="valid_recording_ciphertext_inventory",
            ),
        ]
        indexes = [
            models.Index(
                fields=["state", "retention_hold", "heartbeat_at"],
                name="recording_active_ret_idx",
            ),
            models.Index(
                fields=["state", "retention_hold", "finalized_at"],
                name="recording_final_ret_idx",
            ),
            models.Index(
                fields=["state", "retention_hold", "aborted_at"],
                name="recording_abort_ret_idx",
            ),
        ]

    def __str__(self):
        return f"{self.device_id_at_create}:{self.filename}:{self.state}"


class RecordingUploadChunk(models.Model):
    """Committed chunk receipt used to answer ambiguous retries."""

    upload = models.ForeignKey(
        RecordingUpload,
        on_delete=models.CASCADE,
        related_name="chunks",
        editable=False,
    )
    chunk_id = models.UUIDField(editable=False)
    offset = models.PositiveBigIntegerField(editable=False)
    length = models.PositiveIntegerField(editable=False)
    digest = models.CharField(max_length=64, editable=False)
    revision = models.PositiveBigIntegerField(editable=False)
    committed_at = models.DateTimeField(auto_now_add=True, editable=False)

    class Meta:
        ordering = ("upload_id", "revision")
        constraints = [
            models.UniqueConstraint(
                fields=("upload", "chunk_id"),
                name="unique_recording_chunk_id",
            ),
            models.UniqueConstraint(
                fields=("upload", "revision"),
                name="unique_recording_chunk_revision",
            ),
            models.UniqueConstraint(
                fields=("upload", "offset"),
                name="unique_recording_chunk_offset",
            ),
            models.CheckConstraint(
                condition=models.Q(length__gte=1),
                name="positive_recording_chunk_length",
            ),
            models.CheckConstraint(
                condition=models.Q(revision__gte=1),
                name="positive_recording_chunk_revision",
            ),
        ]

    def __str__(self):
        return f"{self.upload_id}:{self.revision}:{self.offset}+{self.length}"


class RecordingBackupEpoch(models.Model):
    """Immutable recording inventory captured for one database/volume backup epoch."""

    STATE_PREPARING = "preparing"
    STATE_READY = "ready"
    STATE_COMPLETE = "complete"
    STATE_RESTORED = "restored"
    STATE_CHOICES = (
        (STATE_PREPARING, "Preparing"),
        (STATE_READY, "Ready"),
        (STATE_COMPLETE, "Complete"),
        (STATE_RESTORED, "Restored"),
    )

    epoch_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    backup_id = models.CharField(max_length=32, unique=True, editable=False)
    manifest_version = models.PositiveSmallIntegerField(default=1, editable=False)
    state = models.CharField(max_length=12, choices=STATE_CHOICES, default=STATE_PREPARING, editable=False)
    requested_at = models.DateTimeField(editable=False)
    prepared_at = models.DateTimeField(null=True, blank=True, editable=False)
    completed_at = models.DateTimeField(null=True, blank=True, editable=False)
    inventory_count = models.PositiveBigIntegerField(default=0, editable=False)
    object_count = models.PositiveBigIntegerField(default=0, editable=False)
    inventory_digest = models.CharField(max_length=64, blank=True, default="", editable=False)

    class Meta:
        ordering = ("-requested_at", "epoch_id")
        constraints = [
            models.CheckConstraint(
                condition=models.Q(manifest_version=1),
                name="valid_recording_backup_manifest_version",
            ),
        ]


class RecordingBackupObject(models.Model):
    """One immutable upload/object mapping in a recording backup manifest."""

    epoch = models.ForeignKey(
        RecordingBackupEpoch,
        on_delete=models.CASCADE,
        related_name="inventory_objects",
        editable=False,
    )
    upload_id = models.UUIDField(editable=False)
    storage_object_id = models.UUIDField(editable=False)
    storage_version = models.PositiveSmallIntegerField(editable=False)
    storage_relative_path = models.CharField(max_length=192, blank=True, default="", editable=False)
    object_present = models.BooleanField(editable=False)
    state = models.CharField(max_length=12, editable=False)
    owner_id_at_create = models.PositiveBigIntegerField(editable=False)
    device_id_at_create = models.PositiveBigIntegerField(editable=False)
    device_rid_at_create = models.CharField(max_length=16, editable=False)
    device_uuid_at_create = models.CharField(max_length=344, editable=False)
    deployment_generation = models.PositiveBigIntegerField(editable=False)
    encryption_version = models.PositiveSmallIntegerField(editable=False)
    data_key_kek_id = models.CharField(max_length=32, editable=False)
    plaintext_size = models.PositiveBigIntegerField(editable=False)
    plaintext_digest = models.CharField(max_length=64, blank=True, default="", editable=False)
    ciphertext_size = models.PositiveBigIntegerField(editable=False)
    ciphertext_digest = models.CharField(max_length=64, blank=True, default="", editable=False)
    retention_hold = models.BooleanField(editable=False)
    retention_hold_reason = models.CharField(max_length=512, blank=True, default="", editable=False)
    retention_hold_at = models.DateTimeField(null=True, blank=True, editable=False)
    created_at = models.DateTimeField(editable=False)
    finalized_at = models.DateTimeField(null=True, blank=True, editable=False)
    aborted_at = models.DateTimeField(null=True, blank=True, editable=False)

    class Meta:
        ordering = ("epoch_id", "upload_id")
        constraints = [
            models.UniqueConstraint(
                fields=("epoch", "upload_id"),
                name="unique_recording_backup_upload",
            ),
            models.UniqueConstraint(
                fields=("epoch", "storage_object_id"),
                name="unique_recording_backup_object",
            ),
            models.UniqueConstraint(
                fields=("epoch", "storage_relative_path"),
                condition=~models.Q(storage_relative_path=""),
                name="unique_recording_backup_path",
            ),
        ]


class RecordingBackupControl(models.Model):
    """Singleton row serializing recording mutations with consistent backups."""

    singleton = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    active_epoch = models.OneToOneField(
        RecordingBackupEpoch,
        null=True,
        blank=True,
        editable=False,
        on_delete=models.PROTECT,
        related_name="active_control",
    )
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=models.Q(singleton=1),
                name="recording_backup_control_singleton",
            ),
        ]


class PersistentIngestionUsage(models.Model):
    """Transactionally maintained retained-ingestion quota authority."""

    KIND_RECORDING = "recording"
    KIND_AUDIT = "audit"
    KIND_CHOICES = ((KIND_RECORDING, "Recording"), (KIND_AUDIT, "Audit"))
    SCOPE_GLOBAL = "global"
    SCOPE_OWNER = "owner"
    SCOPE_DEVICE = "device"
    SCOPE_CHOICES = ((SCOPE_GLOBAL, "Global"), (SCOPE_OWNER, "Owner"), (SCOPE_DEVICE, "Device"))

    kind = models.CharField(max_length=12, choices=KIND_CHOICES, editable=False)
    scope = models.CharField(max_length=8, choices=SCOPE_CHOICES, editable=False)
    subject_id = models.PositiveBigIntegerField(default=0, editable=False)
    items = models.PositiveBigIntegerField(default=0, editable=False)
    active_items = models.PositiveBigIntegerField(default=0, editable=False)
    committed_bytes = models.PositiveBigIntegerField(default=0, editable=False)
    events = models.PositiveBigIntegerField(default=0, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        ordering = ("kind", "scope", "subject_id")
        constraints = [
            models.UniqueConstraint(
                fields=("kind", "scope", "subject_id"),
                name="unique_ingestion_usage_scope",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(scope="global", subject_id=0) | models.Q(scope__in=("owner", "device"), subject_id__gte=1)
                ),
                name="valid_ingestion_usage_subject",
            ),
        ]

    def __str__(self):
        return f"{self.kind}:{self.scope}:{self.subject_id}"


class ShareLinkAdmin(admin.ModelAdmin):
    list_display = (
        "token_prefix",
        "creator",
        "peer_count",
        "is_used",
        "is_expired",
        "create_time",
    )
    search_fields = ("creator__username", "token_prefix")
    list_filter = ("is_used", "creator", "is_expired")

    @admin.display(description=_("设备数量"))
    def peer_count(self, obj):
        return obj.peers.count()
