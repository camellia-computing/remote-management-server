from django.db.models import Q

from api.audit_expressions import audit_search_document
from api.models import UserProfile

AUDIT_SEARCH_MIN_LENGTH = 3
AUDIT_SEARCH_MAX_LENGTH = 344
AUDIT_SEARCH_USER_MATCH_LIMIT = 1_000


def _matching_user_ids(search_term):
    user_ids = list(
        UserProfile.objects.filter(username__icontains=search_term)
        .order_by("pk")
        .values_list("pk", flat=True)[: AUDIT_SEARCH_USER_MATCH_LIMIT + 1]
    )
    return user_ids[:AUDIT_SEARCH_USER_MATCH_LIMIT], len(user_ids) > AUDIT_SEARCH_USER_MATCH_LIMIT


def filter_address_book_audits(queryset, search_term):
    actor_ids, too_broad = _matching_user_ids(search_term)
    if too_broad:
        return queryset.none(), True
    search = (
        Q(profile_name__icontains=search_term)
        | Q(profile_guid__icontains=search_term)
        | Q(profile_owner_name__icontains=search_term)
        | Q(target_name__icontains=search_term)
        | Q(action__icontains=search_term)
    )
    if actor_ids:
        search |= Q(actor_id__in=actor_ids)
    candidates = Q(_audit_search_document__icontains=search_term)
    if actor_ids:
        candidates |= Q(actor_id__in=actor_ids)
    queryset = queryset.alias(
        _audit_search_document=audit_search_document(
            "profile_name",
            "profile_guid",
            "profile_owner_name",
            "target_name",
            "action",
        )
    )
    return queryset.filter(candidates).filter(search), False


def filter_alarm_logs(queryset, search_term):
    reporter_ids, too_broad = _matching_user_ids(search_term)
    if too_broad:
        return queryset.none(), True
    search = (
        Q(reporter_device_id__icontains=search_term)
        | Q(reporter_device_uuid__icontains=search_term)
        | Q(audit_ref__icontains=search_term)
    )
    if reporter_ids:
        search |= Q(reporter_id__in=reporter_ids)
    candidates = Q(_audit_search_document__icontains=search_term)
    if reporter_ids:
        candidates |= Q(reporter_id__in=reporter_ids)
    queryset = queryset.alias(
        _audit_search_document=audit_search_document(
            "reporter_device_id",
            "reporter_device_uuid",
            "audit_ref",
        )
    )
    return queryset.filter(candidates).filter(search), False
