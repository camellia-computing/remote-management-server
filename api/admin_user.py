from django import forms
from django.contrib import admin
from django.contrib.auth import password_validation
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.translation import gettext as _

from api import models
from api.address_book_authorization import bump_locked_authorization_generation
from api.credential_sessions import revoke_device_credentials, revoke_user_credentials


class UserCreationForm(forms.ModelForm):
    """A form for creating new users. Includes all the required
    fields, plus a repeated password."""

    password1 = forms.CharField(label=_("密码"), widget=forms.PasswordInput)
    password2 = forms.CharField(label=_("再次输入密码"), widget=forms.PasswordInput)

    class Meta:
        model = models.UserProfile
        fields = (
            "username",
            "email",
            "note",
            "is_active",
            "is_admin",
            "groups",
        )

    def clean_username(self):
        username = (self.cleaned_data.get("username") or "").strip()
        if not username:
            raise forms.ValidationError(_("用户名不能为空。"))
        return username

    def clean_password2(self):
        # Check that the two password entries match
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(_("密码校验失败，两次密码不一致。"))
        if password2:
            candidate = self.instance
            candidate.username = self.cleaned_data.get("username", "")
            candidate.email = self.cleaned_data.get("email", "")
            try:
                password_validation.validate_password(password2, user=candidate)
            except ValidationError as exc:
                raise forms.ValidationError(exc.messages) from exc
        return password2

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserChangeForm(forms.ModelForm):
    """A form for updating users. Includes all the fields on
    the user, but replaces the password field with admin's
    password hash display field.
    """

    password = ReadOnlyPasswordHashField(
        label=(_("密码Hash值")),
        help_text="",
    )

    class Meta:
        model = models.UserProfile
        fields = (
            "username",
            "email",
            "note",
            "is_active",
            "is_admin",
            "groups",
        )

    def clean_username(self):
        username = (self.cleaned_data.get("username") or "").strip()
        if not username:
            raise forms.ValidationError(_("用户名不能为空。"))
        return username

    def clean_password(self):
        # Regardless of what the user provides, return the initial value.
        # This is done here, rather than on the field, because the
        # field does not have access to the initial value
        return self.initial["password"]
        # return self.initial["password"]

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super().save(commit=False)

        if commit:
            user.save()
        return user


class UserAdmin(BaseUserAdmin):
    # The forms to add and change user instances
    form = UserChangeForm
    add_form = UserCreationForm
    password = ReadOnlyPasswordHashField(
        label=("密码Hash值"),
        help_text="",
    )
    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on auth.User.
    list_display = ("username", "email", "is_admin", "is_active")
    list_filter = ("is_admin", "is_active")
    fieldsets = (
        (_("基本信息"), {"fields": ("username", "password", "email", "note", "is_active", "is_admin", "groups")}),
    )
    readonly_fields = ()
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "username",
                    "is_active",
                    "is_admin",
                    "groups",
                    "password1",
                    "password2",
                ),
            },
        ),
    )

    search_fields = ("username",)
    ordering = ("username",)
    filter_horizontal = ("groups",)

    def save_model(self, request, obj, form, change):
        with transaction.atomic():
            was_active = (
                models.UserProfile.objects.select_for_update()
                .filter(pk=obj.pk)
                .values_list("is_active", flat=True)
                .first()
                if change and obj.pk
                else None
            )
            super().save_model(request, obj, form, change)
            if was_active and not obj.is_active:
                revoke_user_credentials((obj.pk,))
                obj.refresh_from_db(fields=("credential_generation",))


admin.site.register(models.UserProfile, UserAdmin)
admin.site.register(models.RemoteToken, models.RemoteTokenAdmin)


class OidcIdentityAdmin(admin.ModelAdmin):
    list_display = (
        "provider",
        "issuer",
        "subject",
        "user",
        "is_auto_provisioned",
        "updated_at",
    )
    list_filter = ("provider", "is_auto_provisioned", "updated_at")
    search_fields = ("issuer", "subject", "user__username", "last_username", "last_email")
    autocomplete_fields = ("user",)
    readonly_fields = ("last_username", "last_email", "created_at", "updated_at")

    @staticmethod
    def _authorization_state(identity):
        return (
            identity.provider,
            identity.issuer,
            identity.subject,
            identity.user_id,
            identity.is_auto_provisioned,
        )

    def save_model(self, request, obj, form, change):
        with transaction.atomic():
            previous = (
                models.OidcIdentity.objects.select_for_update().filter(pk=obj.pk).first() if change and obj.pk else None
            )
            super().save_model(request, obj, form, change)
            if previous and self._authorization_state(previous) != self._authorization_state(obj):
                revoke_user_credentials({previous.user_id, obj.user_id})

    def delete_model(self, request, obj):
        with transaction.atomic():
            identity = models.OidcIdentity.objects.select_for_update().filter(pk=obj.pk).first()
            user_id = identity.user_id if identity else obj.user_id
            super().delete_model(request, obj)
            revoke_user_credentials((user_id,))

    def delete_queryset(self, request, queryset):
        with transaction.atomic():
            locked_queryset = queryset.select_for_update().order_by("pk")
            user_ids = set(locked_queryset.values_list("user_id", flat=True))
            super().delete_queryset(request, locked_queryset)
            revoke_user_credentials(user_ids)


admin.site.register(models.OidcIdentity, OidcIdentityAdmin)


class SecretPreservingAdminForm(forms.ModelForm):
    """Keep encrypted values write-only in Django admin forms."""

    secret_field_names = ()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name in self.secret_field_names:
            field = self.fields.get(name)
            if field is None:
                continue
            field.widget = forms.PasswordInput(
                render_value=False,
                attrs={"autocomplete": "new-password"},
            )
            field.help_text = _("留空以保留现有值。")
            self.initial[name] = ""

    def clean(self):
        cleaned_data = super().clean()
        if self.instance.pk:
            for name in self.secret_field_names:
                if not cleaned_data.get(name):
                    cleaned_data[name] = getattr(self.instance, name)
        return cleaned_data


class RemotePeerAdminForm(SecretPreservingAdminForm):
    secret_field_names = ("rhash", "password")

    class Meta:
        model = models.RemotePeer
        fields = "__all__"

    def clean_tags(self):
        tags = self.cleaned_data.get("tags")
        profile = self.cleaned_data.get("profile")
        if profile and tags and tags.exclude(profile=profile).exists():
            raise forms.ValidationError(_("设备和标签必须属于同一个地址簿。"))
        return tags


class RemotePeerAdminCustom(models.RemotePeerAdmin):
    form = RemotePeerAdminForm


class RemoteDeviceAdminForm(SecretPreservingAdminForm):
    secret_field_names = ("address_book_password",)

    class Meta:
        model = models.RemoteDevice
        fields = "__all__"


class RemoteDeviceAdminCustom(models.RemoteDeviceAdmin):
    form = RemoteDeviceAdminForm
    readonly_fields = (
        "rid",
        "uuid",
        "public_key_hash",
        "deployment_generation",
        "policy_generation",
    )

    def has_add_permission(self, request):
        return False

    @staticmethod
    def _credential_state(device):
        return (
            device.owner_id,
            device.is_active,
            device.rid,
            device.uuid,
            device.public_key_hash,
        )

    def save_model(self, request, obj, form, change):
        with transaction.atomic():
            previous = (
                models.RemoteDevice.objects.select_for_update().filter(pk=obj.pk).first() if change and obj.pk else None
            )
            if previous and (
                previous.rid != obj.rid
                or previous.uuid != obj.uuid
                or previous.public_key_hash != obj.public_key_hash
                or previous.deployment_generation != obj.deployment_generation
            ):
                raise ValidationError(_("设备身份只能通过密钥证明或管理员恢复审批修改。"))
            super().save_model(request, obj, form, change)
            if previous and self._credential_state(previous) != self._credential_state(obj):
                models.DeviceProofChallenge.objects.filter(device=obj).delete()
                models.DeviceRecoveryApproval.objects.filter(
                    device=obj,
                    consumed_at__isnull=True,
                ).delete()
                revoke_device_credentials((obj.pk,))


class AddressBookProfileAdminForm(SecretPreservingAdminForm):
    secret_field_names = ("default_password",)

    class Meta:
        model = models.AddressBookProfile
        fields = "__all__"


admin.site.register(models.RemoteTag, models.RemoteTagAdmin)
admin.site.register(models.RemotePeer, RemotePeerAdminCustom)
admin.site.register(models.RemoteDevice, RemoteDeviceAdminCustom)
admin.site.register(models.ShareLink, models.ShareLinkAdmin)
admin.site.register(models.ConnLog, models.ConnLogAdmin)
admin.site.register(models.ConnectionAuditEvent, models.ConnectionAuditEventAdmin)
admin.site.register(models.FileLog, models.FileLogAdmin)
admin.site.register(models.FileTransferAuditEvent, models.FileTransferAuditEventAdmin)


class StrategyProfileAdmin(admin.ModelAdmin):
    list_display = ("name", "guid", "enabled", "updated_at")
    search_fields = ("name", "guid")
    list_filter = ("enabled", "updated_at")


class DeviceGroupAdmin(admin.ModelAdmin):
    list_display = ("name", "guid", "strategy", "updated_at")
    search_fields = ("name", "guid", "strategy__name")
    list_filter = ("strategy", "updated_at")


def _lock_address_book_profiles(profile_ids):
    return list(
        models.AddressBookProfile.objects.select_for_update()
        .filter(pk__in=sorted({profile_id for profile_id in profile_ids if profile_id is not None}))
        .order_by("pk")
    )


class AddressBookProfileAdmin(admin.ModelAdmin):
    form = AddressBookProfileAdminForm
    list_display = ("name", "guid", "owner", "rule", "created_at", "updated_at")
    search_fields = ("name", "guid", "owner__username")
    list_filter = ("rule", "created_at", "updated_at")

    def save_model(self, request, obj, form, change):
        with transaction.atomic():
            previous = (
                models.AddressBookProfile.objects.select_for_update().filter(pk=obj.pk).first() if change else None
            )
            if change and previous is None:
                raise ValidationError(_("地址簿已被并发删除，请重新加载。"))
            if previous:
                obj.authorization_generation = previous.authorization_generation
            super().save_model(request, obj, form, change)

    def delete_model(self, request, obj):
        with transaction.atomic():
            locked = models.AddressBookProfile.objects.select_for_update().filter(pk=obj.pk).first()
            if locked:
                locked._audit_actor = request.user
                super().delete_model(request, locked)

    def delete_queryset(self, request, queryset):
        with transaction.atomic():
            locked_profiles = _lock_address_book_profiles(queryset.values_list("pk", flat=True))
            for profile in locked_profiles:
                profile._audit_actor = request.user
                super().delete_model(request, profile)


class AddressBookShareAdmin(admin.ModelAdmin):
    list_display = ("profile", "user", "rule", "guid", "created_at")
    search_fields = ("profile__name", "user__username", "guid")
    list_filter = ("rule", "created_at")

    def save_model(self, request, obj, form, change):
        with transaction.atomic():
            old_profile_id = (
                models.AddressBookShare.objects.filter(pk=obj.pk).values_list("profile_id", flat=True).first()
                if change
                else None
            )
            profiles = _lock_address_book_profiles((old_profile_id, obj.profile_id))
            locked_profile_ids = {profile.pk for profile in profiles}
            if change:
                current = models.AddressBookShare.objects.select_for_update().filter(pk=obj.pk).first()
                if current is None or current.profile_id not in locked_profile_ids:
                    raise ValidationError(_("地址簿共享已被并发修改，请重新加载。"))
            super().save_model(request, obj, form, change)
            for profile in profiles:
                bump_locked_authorization_generation(profile)

    def delete_model(self, request, obj):
        with transaction.atomic():
            profiles = _lock_address_book_profiles((obj.profile_id,))
            locked_profile_ids = {profile.pk for profile in profiles}
            current = models.AddressBookShare.objects.select_for_update().filter(pk=obj.pk).first()
            if current is None:
                return
            if current.profile_id not in locked_profile_ids:
                raise ValidationError(_("地址簿共享已被并发修改，请重新加载。"))
            super().delete_model(request, current)
            for profile in profiles:
                bump_locked_authorization_generation(profile)

    def delete_queryset(self, request, queryset):
        with transaction.atomic():
            rows = list(queryset.values_list("pk", "profile_id"))
            profiles = _lock_address_book_profiles(profile_id for _pk, profile_id in rows)
            locked_profile_ids = {profile.pk for profile in profiles}
            locked_rows = list(
                models.AddressBookShare.objects.select_for_update()
                .filter(pk__in=[pk for pk, _profile_id in rows])
                .order_by("pk")
            )
            if any(row.profile_id not in locked_profile_ids for row in locked_rows):
                raise ValidationError(_("地址簿共享已被并发修改，请重新加载。"))
            super().delete_queryset(
                request,
                models.AddressBookShare.objects.filter(pk__in=[row.pk for row in locked_rows]),
            )
            for profile in profiles:
                bump_locked_authorization_generation(profile)


class AlarmLogAdmin(admin.ModelAdmin):
    list_display = (
        "typ",
        "reporter_device_id",
        "conn_id",
        "reporter",
        "created_at",
    )
    search_fields = (
        "reporter_device_id",
        "reporter_device_uuid",
        "audit_ref",
        "reporter__username",
    )
    list_filter = ("typ", "created_at")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


class AddressBookRuleAdmin(admin.ModelAdmin):
    list_display = ("profile", "rule", "user", "group", "is_everyone", "guid", "updated_at")
    search_fields = ("profile__name", "user__username", "group__name", "guid")
    list_filter = ("rule", "is_everyone", "updated_at")

    def save_model(self, request, obj, form, change):
        with transaction.atomic():
            old_profile_id = (
                models.AddressBookRule.objects.filter(pk=obj.pk).values_list("profile_id", flat=True).first()
                if change
                else None
            )
            profiles = _lock_address_book_profiles((old_profile_id, obj.profile_id))
            locked_profile_ids = {profile.pk for profile in profiles}
            if change:
                current = models.AddressBookRule.objects.select_for_update().filter(pk=obj.pk).first()
                if current is None or current.profile_id not in locked_profile_ids:
                    raise ValidationError(_("地址簿规则已被并发修改，请重新加载。"))
            super().save_model(request, obj, form, change)
            for profile in profiles:
                bump_locked_authorization_generation(profile)

    def delete_model(self, request, obj):
        with transaction.atomic():
            profiles = _lock_address_book_profiles((obj.profile_id,))
            locked_profile_ids = {profile.pk for profile in profiles}
            current = models.AddressBookRule.objects.select_for_update().filter(pk=obj.pk).first()
            if current is None:
                return
            if current.profile_id not in locked_profile_ids:
                raise ValidationError(_("地址簿规则已被并发修改，请重新加载。"))
            super().delete_model(request, current)
            for profile in profiles:
                bump_locked_authorization_generation(profile)

    def delete_queryset(self, request, queryset):
        with transaction.atomic():
            rows = list(queryset.values_list("pk", "profile_id"))
            profiles = _lock_address_book_profiles(profile_id for _pk, profile_id in rows)
            locked_profile_ids = {profile.pk for profile in profiles}
            locked_rows = list(
                models.AddressBookRule.objects.select_for_update()
                .filter(pk__in=[pk for pk, _profile_id in rows])
                .order_by("pk")
            )
            if any(row.profile_id not in locked_profile_ids for row in locked_rows):
                raise ValidationError(_("地址簿规则已被并发修改，请重新加载。"))
            super().delete_queryset(
                request,
                models.AddressBookRule.objects.filter(pk__in=[row.pk for row in locked_rows]),
            )
            for profile in profiles:
                bump_locked_authorization_generation(profile)


class AddressBookRuleAuditAdmin(admin.ModelAdmin):
    list_display = ("profile_label", "action", "target_type", "target_name", "rule", "actor", "created_at")
    search_fields = ("profile_name", "profile_guid", "profile_owner_name", "target_name", "actor__username")
    list_filter = ("action", "target_type", "rule", "created_at")
    readonly_fields = (
        "profile",
        "profile_guid",
        "profile_name",
        "profile_owner_name",
        "actor",
        "action",
        "target_type",
        "target_name",
        "rule",
        "details",
        "created_at",
    )

    @admin.display(description=_("地址簿"))
    def profile_label(self, obj):
        return obj.profile_name or (obj.profile.name if obj.profile else "-")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


admin.site.register(models.StrategyProfile, StrategyProfileAdmin)
admin.site.register(models.DeviceGroup, DeviceGroupAdmin)
admin.site.register(models.AddressBookProfile, AddressBookProfileAdmin)
admin.site.register(models.AddressBookShare, AddressBookShareAdmin)
admin.site.register(models.AddressBookRule, AddressBookRuleAdmin)
admin.site.register(models.AddressBookRuleAudit, AddressBookRuleAuditAdmin)
admin.site.register(models.AlarmLog, AlarmLogAdmin)
admin.site.unregister(Group)
admin.site.site_header = _("Camellia 管理后台")
admin.site.site_title = _("Camellia 管理后台")
