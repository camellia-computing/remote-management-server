from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db.models.signals import m2m_changed, pre_delete

from api.address_book_authorization import lock_and_bump_profiles_for_groups


def _serialize_address_book_group_membership(sender, instance, action, reverse, pk_set, using, **kwargs):
    if action not in {"pre_add", "pre_remove", "pre_clear"}:
        return
    if reverse:
        group_ids = (instance.pk,)
    elif action == "pre_clear":
        group_ids = instance.groups.using(using).values_list("pk", flat=True)
    else:
        group_ids = pk_set or ()
    lock_and_bump_profiles_for_groups(group_ids, using=using)


def _serialize_address_book_group_delete(sender, instance, using, **kwargs):
    lock_and_bump_profiles_for_groups((instance.pk,), using=using)


def connect_address_book_signals():
    m2m_changed.connect(
        _serialize_address_book_group_membership,
        sender=get_user_model().groups.through,
        dispatch_uid="api.serialize_address_book_group_membership",
    )
    pre_delete.connect(
        _serialize_address_book_group_delete,
        sender=Group,
        dispatch_uid="api.serialize_address_book_group_delete",
    )
