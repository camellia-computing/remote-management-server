from contextvars import ContextVar

from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.contrib.postgres.indexes import GinIndex, OpClass
from django.db import models, router, transaction
from django.db.models.functions import Cast, Upper
from django.utils.crypto import salted_hmac
from django.utils.translation import gettext_lazy as _

from api.username_identity import canonical_username_key, normalize_username

_USERNAME_BULK_UPDATE = ContextVar("username_bulk_update", default=False)


class UserProfileQuerySet(models.QuerySet):
    def by_username(self, username):
        try:
            key = canonical_username_key(username)
        except ValueError:
            return self.none()
        return self.filter(username_canonical=key)

    def bulk_create(self, objs, *args, **kwargs):
        for user in objs:
            user._sync_username_identity()
        return super().bulk_create(objs, *args, **kwargs)

    def bulk_update(self, objs, fields, *args, **kwargs):
        fields = list(fields)
        field_names = set(fields)
        if "username_canonical" in field_names and "username" not in field_names:
            raise ValueError("username_canonical cannot be updated independently")
        if "username" in field_names:
            for user in objs:
                user._sync_username_identity()
            if "username_canonical" not in field_names:
                fields.append("username_canonical")
        # Django implements bulk_update through Case expressions passed back
        # into QuerySet.update().  Authorize only that scoped internal path;
        # direct expression-based username updates remain rejected.
        token = _USERNAME_BULK_UPDATE.set(True)
        try:
            return super().bulk_update(objs, fields, *args, **kwargs)
        finally:
            _USERNAME_BULK_UPDATE.reset(token)

    def update(self, **kwargs):
        if "username_canonical" in kwargs and "username" not in kwargs:
            raise ValueError("username_canonical cannot be updated independently")
        if "username" in kwargs:
            if isinstance(kwargs["username"], str):
                username = normalize_username(kwargs["username"])
                kwargs["username"] = username
                kwargs["username_canonical"] = canonical_username_key(username)
            elif not _USERNAME_BULK_UPDATE.get() or "username_canonical" not in kwargs:
                raise ValueError("username expressions are not supported")
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

    def get_by_natural_key(self, username):
        try:
            key = canonical_username_key(username)
        except ValueError as exc:
            raise self.model.DoesNotExist from exc
        return self.get(username_canonical=key)

    def create_user(self, username, password=None, **extra_fields):
        try:
            username = normalize_username(username)
        except ValueError as exc:
            raise ValueError("Users must have a valid username") from exc
        email = extra_fields.get("email")
        if email is not None:
            extra_fields["email"] = self.normalize_email(email)
        user = self.model(username=username, **extra_fields)
        user._sync_username_identity()
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
    username_canonical = models.BinaryField(
        max_length=1024,
        unique=True,
        editable=False,
        blank=True,
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

    def _sync_username_identity(self):
        self.username = normalize_username(self.username)
        self.username_canonical = canonical_username_key(self.username)

    def clean(self):
        super().clean()
        self._sync_username_identity()

    def save(self, *args, **kwargs):
        """Never let a stale model instance move credential generation backward."""

        self._sync_username_identity()
        update_fields = kwargs.get("update_fields")
        if update_fields is not None and {"username", "username_canonical"}.intersection(update_fields):
            kwargs["update_fields"] = tuple(dict.fromkeys((*update_fields, "username", "username_canonical")))
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
