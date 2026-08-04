import datetime
import uuid

from django.conf import settings
from django.contrib import admin
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.signals import m2m_changed
from django.dispatch import receiver
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .encrypted_fields import EncryptedTextField

ALARM_TYPES = (0, 1, 2, 6, 7, 8, 9)


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
    """A single rotating session token bound to one managed device."""

    device = models.OneToOneField(
        "RemoteDevice",
        on_delete=models.CASCADE,
        related_name="session_token",
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


class RemoteTokenAdmin(admin.ModelAdmin):
    list_display = ("device", "device_owner", "expires_at")
    search_fields = ("device__owner__username", "device__rid")
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

    def effective_strategy(self):
        if self.strategy_id:
            return self.strategy
        if self.device_group_id and self.device_group.strategy_id:
            return self.device_group.strategy
        if self.owner_id and self.owner.strategy_id:
            return self.owner.strategy
        return None


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
        "create_time",
        "update_time",
    )
    search_fields = ("rid", "hostname", "memory", "owner__username", "device_group__name")
    list_filter = ("is_active", "device_group", "strategy")


class ConnLog(models.Model):
    id = models.AutoField(verbose_name="ID", primary_key=True)
    guid = models.UUIDField(
        verbose_name="GUID",
        default=uuid.uuid4,
        editable=False,
        unique=True,
    )
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
        "conn_start",
        "conn_end",
    )
    search_fields = ("guid", "from_ip", "from_id", "rid", "session_id", "audit_ref")
    list_filter = ("conn_type", "primary_auth", "two_factor", "conn_start", "conn_end")


class FileLog(models.Model):
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

    class Meta:
        ordering = ("-logged_at",)
        verbose_name = _("文件传输日志")
        verbose_name_plural = _("文件传输日志列表")
        constraints = [
            models.CheckConstraint(
                condition=models.Q(direction__in=(0, 1)),
                name="valid_file_transfer_direction",
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
        "direction",
        "logged_at",
    )
    search_fields = ("file", "remote_id", "user_id", "user_ip")
    list_filter = ("direction", "logged_at")


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


class DeviceGroup(models.Model):
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


class AddressBookProfile(models.Model):
    guid = models.CharField(verbose_name=_("地址簿GUID"), max_length=60, unique=True)
    name = models.CharField(verbose_name=_("地址簿名称"), max_length=60)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="address_book_profiles")
    note = models.TextField(verbose_name=_("备注"), blank=True, default="")
    rule = models.IntegerField(verbose_name=_("共享权限"), default=1)
    info = models.JSONField(verbose_name=_("扩展信息"), blank=True, default=dict)
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
    profile = models.ForeignKey(AddressBookProfile, on_delete=models.CASCADE, related_name="rule_audits")
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="address_book_rule_audits",
    )
    action = models.CharField(max_length=32)
    target_type = models.CharField(max_length=16)
    target_name = models.CharField(max_length=120, blank=True, default="")
    rule = models.IntegerField(verbose_name=_("共享权限"), default=1)
    details = models.JSONField(blank=True, default=dict)
    created_at = models.DateTimeField(verbose_name=_("创建时间"), default=timezone.now)

    class Meta:
        ordering = ("-created_at",)
        verbose_name = _("地址簿规则审计")
        verbose_name_plural = _("地址簿规则审计列表")
        constraints = [
            models.CheckConstraint(
                condition=models.Q(rule__gte=1, rule__lte=3),
                name="valid_address_book_audit_rule",
            ),
            models.CheckConstraint(
                condition=models.Q(
                    target_type__in=("user", "group", "everyone"),
                ),
                name="valid_address_book_audit_target",
            ),
        ]

    def __str__(self):
        return f"{self.action} {self.target_type}:{self.target_name}"


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

    class Meta:
        ordering = ("-created_at",)
        verbose_name = _("告警日志")
        verbose_name_plural = _("告警日志列表")
        constraints = [
            models.CheckConstraint(
                condition=models.Q(typ__in=ALARM_TYPES),
                name="valid_alarm_type",
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
