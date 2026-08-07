from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.contrib.postgres.indexes import GinIndex, OpClass
from django.db import models, router, transaction
from django.db.models.functions import Cast, Lower, Upper
from django.utils.crypto import salted_hmac
from django.utils.translation import gettext_lazy as _


class UserProfileQuerySet(models.QuerySet):
    def update(self, **kwargs):
        if not {"strategy", "strategy_id"}.intersection(kwargs):
            return super().update(**kwargs)
        from api.policy_generation import (
            bump_device_policy_generations,
            device_ids_affected_by_users,
        )

        with transaction.atomic(using=self.db):
            user_ids = list(
                self.select_related(None).select_for_update(of=("self",)).order_by("pk").values_list("pk", flat=True)
            )
            device_ids = device_ids_affected_by_users(user_ids, using=self.db)
            updated = super().update(**kwargs)
            bump_device_policy_generations(device_ids, using=self.db)
            return updated

    def delete(self):
        from api.policy_generation import (
            bump_device_policy_generations,
            device_ids_affected_by_users,
        )

        with transaction.atomic(using=self.db):
            user_ids = list(
                self.select_related(None).select_for_update(of=("self",)).order_by("pk").values_list("pk", flat=True)
            )
            device_ids = device_ids_affected_by_users(user_ids, using=self.db)
            result = super().delete()
            bump_device_policy_generations(device_ids, using=self.db)
            return result


class MyUserManager(BaseUserManager.from_queryset(UserProfileQuerySet)):
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
    credential_generation = models.PositiveBigIntegerField(default=0, editable=False)

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

    def _get_session_auth_hash(self, secret=None):
        """Bind every Django session to the user's revocation generation."""

        return salted_hmac(
            "django.contrib.auth.models.AbstractBaseUser.get_session_auth_hash",
            f"{self.credential_generation}:{self.password}",
            secret=secret,
            algorithm="sha256",
        ).hexdigest()

    def save(self, *args, **kwargs):
        """Never let a stale model instance move credential generation backward."""

        if not self.pk:
            return super().save(*args, **kwargs)
        database = kwargs.get("using") or router.db_for_write(type(self), instance=self)
        from api.policy_generation import (
            bump_device_policy_generations,
            device_ids_affected_by_users,
        )

        with transaction.atomic(using=database):
            current = (
                type(self)
                .objects.using(database)
                .select_for_update()
                .filter(pk=self.pk)
                .values("credential_generation", "strategy_id")
                .first()
            )
            if current is None:
                return super().save(*args, **kwargs)
            self.credential_generation = current["credential_generation"]
            result = super().save(*args, **kwargs)
            update_fields = kwargs.get("update_fields")
            strategy_may_change = update_fields is None or bool({"strategy", "strategy_id"}.intersection(update_fields))
            if strategy_may_change and current["strategy_id"] != self.strategy_id:
                device_ids = device_ids_affected_by_users((self.pk,), using=database)
                bump_device_policy_generations(device_ids, using=database)
            return result

    def delete(self, *args, **kwargs):
        if not self.pk:
            return super().delete(*args, **kwargs)
        database = kwargs.get("using") or router.db_for_write(type(self), instance=self)
        from api.policy_generation import (
            bump_device_policy_generations,
            device_ids_affected_by_users,
        )

        with transaction.atomic(using=database):
            type(self).objects.using(database).select_for_update().get(pk=self.pk)
            device_ids = device_ids_affected_by_users((self.pk,), using=database)
            result = super().delete(*args, **kwargs)
            bump_device_policy_generations(device_ids, using=database)
            return result

    @property
    def is_staff(self):
        return self.is_admin

    class Meta:
        verbose_name = _("用户")
        verbose_name_plural = _("用户列表")
        indexes = (
            GinIndex(
                OpClass(
                    Upper(Cast("username", models.TextField())),
                    name="gin_trgm_ops",
                ),
                name="user_name_search_trgm_idx",
            ),
        )
        constraints = (
            models.UniqueConstraint(
                Lower("username"),
                name="unique_username_case_insensitive",
            ),
        )
