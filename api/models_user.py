from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.db import models
from django.db.models.functions import Lower
from django.utils.translation import gettext_lazy as _


class MyUserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, username, password=None, **extra_fields):
        username = str(username or "").strip()
        if not username:
            raise ValueError("Users must have a username")
        email = extra_fields.get("email")
        if email is not None:
            extra_fields["email"] = self.normalize_email(email)
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.full_clean()
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password, **extra_fields):
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_admin", True)
        extra_fields.setdefault("is_superuser", True)
        if extra_fields.get("is_admin") is not True:
            raise ValueError("A superuser must have is_admin=True")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("A superuser must have is_superuser=True")
        return self.create_user(username, password=password, **extra_fields)


class UserProfile(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(
        _("用户名"),
        unique=True,
        max_length=50,
        validators=[UnicodeUsernameValidator()],
    )
    email = models.EmailField(_("邮箱"), max_length=254, blank=True, default="")
    note = models.TextField(_("备注"), blank=True, default="")
    strategy = models.ForeignKey(
        "api.StrategyProfile",
        verbose_name=_("策略"),
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="users",
    )
    is_active = models.BooleanField(_("是否激活"), default=True)
    is_admin = models.BooleanField(_("是否管理员"), default=False)

    objects = MyUserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = []

    def get_full_name(self):
        return self.username

    def get_short_name(self):
        return self.username

    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        return self.is_active and (self.is_admin or self.is_superuser)

    def has_module_perms(self, app_label):
        return self.is_active and (self.is_admin or self.is_superuser)

    @property
    def is_staff(self):
        return self.is_admin

    class Meta:
        verbose_name = _("用户")
        verbose_name_plural = _("用户列表")
        permissions = (
            ("view_task", "Can see available tasks"),
            ("change_task_status", "Can change the status of tasks"),
            ("close_task", "Can remove a task by setting its status as closed"),
        )
        constraints = (
            models.UniqueConstraint(
                Lower("username"),
                name="unique_username_case_insensitive",
            ),
        )
