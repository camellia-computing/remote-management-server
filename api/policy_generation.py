import hashlib
import json

from django.db import DEFAULT_DB_ALIAS, transaction
from django.db.models import F, Q

MAX_POLICY_GENERATION = (1 << 63) - 1
MAX_POLICY_OPTIONS = 512
MAX_POLICY_OPTIONS_BYTES = 64 * 1024
MAX_POLICY_KEY_CHARACTERS = 128
MAX_POLICY_KEY_BYTES = 512
MAX_POLICY_VALUE_CHARACTERS = 4096
MAX_POLICY_VALUE_BYTES = 16 * 1024


class PolicyGenerationExhausted(RuntimeError):
    """The authoritative per-device policy sequence cannot advance safely."""


class InvalidManagedPolicy(ValueError):
    """A strategy cannot be represented by the managed-policy wire contract."""


def normalize_policy_options(value):
    if not isinstance(value, dict) or len(value) > MAX_POLICY_OPTIONS:
        raise InvalidManagedPolicy("policy options must be a bounded object")
    output = {}
    for key, option_value in value.items():
        if (
            not isinstance(key, str)
            or not key
            or len(key) > MAX_POLICY_KEY_CHARACTERS
            or len(key.encode("utf-8")) > MAX_POLICY_KEY_BYTES
            or any(ord(character) < 32 for character in key)
            or not isinstance(option_value, str)
            or len(option_value) > MAX_POLICY_VALUE_CHARACTERS
            or len(option_value.encode("utf-8")) > MAX_POLICY_VALUE_BYTES
        ):
            raise InvalidManagedPolicy("policy options contain an invalid entry")
        output[key] = option_value
    canonical = canonical_policy_options(output)
    if len(canonical) > MAX_POLICY_OPTIONS_BYTES:
        raise InvalidManagedPolicy("policy options exceed the wire budget")
    return output


def canonical_policy_options(options):
    try:
        return json.dumps(
            options,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise InvalidManagedPolicy("policy options are not canonical JSON") from exc


def managed_policy_document(device):
    strategy = device.effective_strategy()
    options = normalize_policy_options(strategy.config_options) if strategy and strategy.enabled else {}
    digest = hashlib.sha256(canonical_policy_options(options)).hexdigest()
    return {
        "version": 1,
        "id": device.rid,
        "uuid": device.uuid,
        "generation": device.policy_generation,
        "digest": digest,
        "config_options": options,
    }


def _device_manager(using):
    from api.models_work import RemoteDevice

    return RemoteDevice._base_manager.using(using)


def bump_device_policy_generations(device_ids, *, using=None):
    using = using or DEFAULT_DB_ALIAS
    normalized_ids = sorted({int(device_id) for device_id in device_ids if device_id is not None})
    if not normalized_ids:
        return {}
    manager = _device_manager(using)
    with transaction.atomic(using=using):
        rows = list(
            manager.select_for_update()
            .filter(pk__in=normalized_ids)
            .order_by("pk")
            .values_list("pk", "policy_generation")
        )
        if any(generation >= MAX_POLICY_GENERATION for _pk, generation in rows):
            raise PolicyGenerationExhausted("device policy generation is exhausted")
        locked_ids = [pk for pk, _generation in rows]
        if locked_ids:
            manager.filter(pk__in=locked_ids).update(policy_generation=F("policy_generation") + 1)
        return {pk: generation + 1 for pk, generation in rows}


def device_ids_affected_by_strategies(strategy_ids, *, using=None):
    using = using or DEFAULT_DB_ALIAS
    strategy_ids = {int(strategy_id) for strategy_id in strategy_ids if strategy_id is not None}
    if not strategy_ids:
        return []
    return list(
        _device_manager(using)
        .filter(
            Q(strategy_id__in=strategy_ids)
            | Q(
                strategy__isnull=True,
                device_group__strategy_id__in=strategy_ids,
            )
            | Q(
                strategy__isnull=True,
                device_group__strategy__isnull=True,
                owner__strategy_id__in=strategy_ids,
            )
        )
        .order_by("pk")
        .values_list("pk", flat=True)
    )


def device_ids_affected_by_groups(group_ids, *, using=None):
    using = using or DEFAULT_DB_ALIAS
    group_ids = {int(group_id) for group_id in group_ids if group_id is not None}
    if not group_ids:
        return []
    return list(
        _device_manager(using)
        .filter(device_group_id__in=group_ids, strategy__isnull=True)
        .order_by("pk")
        .values_list("pk", flat=True)
    )


def device_ids_affected_by_users(user_ids, *, using=None):
    using = using or DEFAULT_DB_ALIAS
    user_ids = {int(user_id) for user_id in user_ids if user_id is not None}
    if not user_ids:
        return []
    return list(
        _device_manager(using)
        .filter(
            owner_id__in=user_ids,
            strategy__isnull=True,
            device_group__strategy__isnull=True,
        )
        .order_by("pk")
        .values_list("pk", flat=True)
    )
