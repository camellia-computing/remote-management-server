from django import forms
from django.contrib import admin
from django.contrib.auth import password_validation
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

from api import models


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


admin.site.register(models.UserProfile, UserAdmin)
admin.site.register(models.RemoteToken, models.RemoteTokenAdmin)


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


admin.site.register(models.RemoteTag, models.RemoteTagAdmin)
admin.site.register(models.RemotePeer, RemotePeerAdminCustom)
admin.site.register(models.RemoteDevice, RemoteDeviceAdminCustom)
admin.site.register(models.ShareLink, models.ShareLinkAdmin)
admin.site.register(models.ConnLog, models.ConnLogAdmin)
admin.site.register(models.FileLog, models.FileLogAdmin)


class StrategyProfileAdmin(admin.ModelAdmin):
    list_display = ("name", "guid", "enabled", "updated_at")
    search_fields = ("name", "guid")
    list_filter = ("enabled", "updated_at")


class DeviceGroupAdmin(admin.ModelAdmin):
    list_display = ("name", "guid", "strategy", "updated_at")
    search_fields = ("name", "guid", "strategy__name")
    list_filter = ("strategy", "updated_at")


class AddressBookProfileAdmin(admin.ModelAdmin):
    list_display = ("name", "guid", "owner", "rule", "created_at", "updated_at")
    search_fields = ("name", "guid", "owner__username")
    list_filter = ("rule", "created_at", "updated_at")


class AddressBookShareAdmin(admin.ModelAdmin):
    list_display = ("profile", "user", "rule", "guid", "created_at")
    search_fields = ("profile__name", "user__username", "guid")
    list_filter = ("rule", "created_at")


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


class AddressBookRuleAdmin(admin.ModelAdmin):
    list_display = ("profile", "rule", "user", "group", "is_everyone", "guid", "updated_at")
    search_fields = ("profile__name", "user__username", "group__name", "guid")
    list_filter = ("rule", "is_everyone", "updated_at")


class AddressBookRuleAuditAdmin(admin.ModelAdmin):
    list_display = ("profile", "action", "target_type", "target_name", "rule", "actor", "created_at")
    search_fields = ("profile__name", "target_name", "actor__username")
    list_filter = ("action", "target_type", "rule", "created_at")


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
