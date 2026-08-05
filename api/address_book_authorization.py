from django.core.exceptions import ObjectDoesNotExist
from django.db import connections, transaction

from api.address_book_errors import AuthorizationGenerationExhausted
from api.models_work import AddressBookProfile, AddressBookRule, AddressBookRuleAudit, AddressBookShare

MAX_AUTHORIZATION_GENERATION = (1 << 63) - 1


def rule_access(profile, user, *, using=None):
    """Return the current highest content capability for a non-owner."""

    database = using or profile._state.db or "default"
    rule = 0
    share_rule = (
        AddressBookShare.objects.using(database)
        .filter(profile_id=profile.pk, user_id=user.pk)
        .values_list("rule", flat=True)
        .first()
    )
    if share_rule:
        rule = max(rule, share_rule)
    rules = AddressBookRule.objects.using(database).filter(profile_id=profile.pk)
    everyone_rule = rules.filter(is_everyone=True).values_list("rule", flat=True).first()
    if everyone_rule:
        rule = max(rule, everyone_rule)
    group_ids = list(user.groups.using(database).values_list("pk", flat=True))
    if group_ids:
        for group_rule in rules.filter(group_id__in=group_ids).values_list("rule", flat=True):
            rule = max(rule, group_rule)
    user_rule = rules.filter(user_id=user.pk).values_list("rule", flat=True).first()
    if user_rule:
        rule = max(rule, user_rule)
    return rule


def lock_profile_access(user, profile_pk, *, using=None):
    """Lock the profile authority row and recompute access from current rows.

    Callers must keep the surrounding transaction open until their mutation is
    committed. Every authorization mutation uses the same profile row, so a
    completed revocation is a barrier for older content writers.
    """

    database = using or "default"
    if not connections[database].in_atomic_block:
        raise RuntimeError("Address-book profile access must be checked inside transaction.atomic")
    profile = AddressBookProfile.objects.using(database).select_for_update().filter(pk=profile_pk).first()
    if profile is None:
        return None, None, 0
    if user.is_admin or str(profile.owner_id) == str(user.pk):
        return profile, profile.owner, 3
    current_rule = rule_access(profile, user, using=database)
    if not current_rule:
        return profile, None, 0
    return profile, profile.owner, current_rule


def bump_locked_authorization_generation(profile, *, using=None):
    """Advance a profile generation while its authority row is locked."""

    database = using or profile._state.db or "default"
    if not connections[database].in_atomic_block:
        raise RuntimeError("Address-book authorization generation requires transaction.atomic")
    if profile.authorization_generation >= MAX_AUTHORIZATION_GENERATION:
        raise AuthorizationGenerationExhausted("Address-book authorization generation exhausted")
    profile.authorization_generation += 1
    profile.save(using=database, update_fields=("authorization_generation", "updated_at"))
    return profile.authorization_generation


def record_profile_tombstone(profile, actor=None, *, using=None):
    """Persist an immutable profile-deletion snapshot before its FK is nulled."""

    database = using or profile._state.db or "default"
    try:
        owner = profile.owner
    except ObjectDoesNotExist:
        owner = None
    owner_name = getattr(owner, "username", "") or ""
    return AddressBookRuleAudit.objects.using(database).create(
        profile=profile,
        profile_guid=str(profile.guid or ""),
        profile_name=str(profile.name or ""),
        profile_owner_name=owner_name,
        actor=actor if actor and getattr(actor, "id", None) else None,
        action="profile_delete",
        target_type="profile",
        target_name=str(profile.name or ""),
        rule=int(profile.rule or 1),
        details={
            "authorization_generation": profile.authorization_generation,
            "profile_guid": str(profile.guid or ""),
            "profile_name": str(profile.name or ""),
            "profile_owner_name": owner_name,
        },
    )


def lock_and_bump_profiles_for_groups(group_ids, *, using):
    """Serialize group-membership changes with affected profile writers."""

    normalized_ids = sorted({int(group_id) for group_id in group_ids if group_id is not None})
    if not normalized_ids:
        return ()
    with transaction.atomic(using=using):
        profile_ids = list(
            AddressBookRule.objects.using(using)
            .filter(group_id__in=normalized_ids)
            .order_by("profile_id")
            .values_list("profile_id", flat=True)
            .distinct()
        )
        profiles = list(
            AddressBookProfile.objects.using(using).select_for_update().filter(pk__in=profile_ids).order_by("pk")
        )
        if any(profile.authorization_generation >= MAX_AUTHORIZATION_GENERATION for profile in profiles):
            raise AuthorizationGenerationExhausted("Address-book authorization generation exhausted")
        for profile in profiles:
            bump_locked_authorization_generation(profile, using=using)
        return tuple(profile.pk for profile in profiles)
