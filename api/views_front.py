import hashlib
import json
import logging
import secrets
import uuid
from io import StringIO
from itertools import chain
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import auth, messages
from django.contrib.auth import password_validation
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import Count, Model, Prefetch, Q
from django.db.models.fields import CharField, DateField, DateTimeField, TextField
from django.forms.models import model_to_dict
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.utils.translation import gettext as _

from api.formatting import format_bytes
from api.login_admission import REGISTER_SCOPE, complete_login_success, reserve_login_attempt
from api.models import (
    AddressBookProfile,
    AddressBookRule,
    AddressBookRuleAudit,
    AddressBookShare,
    ConnLog,
    FileLog,
    RemoteDevice,
    RemotePeer,
    RemoteTag,
    ShareLink,
    UserProfile,
)
from api.request_utils import client_ip
from api.tag_colors import normalize_tag_color, tag_color_css
from api.xlsx import safe_csv_writer, xlsx_response
from camellia_remote_management.access_logging import normalized_route

logger = logging.getLogger(__name__)
MAX_AB_PEERS = 10_000
MAX_AB_TAGS = 256
MAX_AB_TAGS_PER_PEER = 32


def _filename_stamp():
    return timezone.localtime(timezone.now()).strftime("%Y%m%d_%H%M")


def _client_ip(request):
    return client_ip(request)


def _log_event(request, event, level="info", **extra):
    user = getattr(request, "user", None)
    username = user.username if user and getattr(user, "is_authenticated", False) else "anonymous"
    payload = {
        "event": event,
        "user": username,
        "ip": _client_ip(request),
        "route": normalized_route(getattr(request, "resolver_match", None)),
        "method": getattr(request, "method", ""),
    }
    payload.update({k: v for k, v in extra.items() if v is not None})
    details = json.dumps(payload, ensure_ascii=False, default=str)
    log_fn = getattr(logger, level, logger.info)
    log_fn("event=%s details=%s", event, details)


def model_to_dict2(instance, fields=None, exclude=None, replace=None, default=None):
    """
    :params instance: 模型对象，不能是queryset数据集
    :params fields: 指定要展示的字段数据，('字段1','字段2')
    :params exclude: 指定排除掉的字段数据,('字段1','字段2')
    :params replace: 将字段名字修改成需要的名字，{'数据库字段名':'前端展示名'}
    :params default: 新增不存在的字段数据，{'字段':'数据'}
    """
    # 对传递进来的模型对象校验
    if not isinstance(instance, Model):
        raise Exception(_("model_to_dict接收的参数必须是模型对象"))
    # 对替换数据库字段名字校验
    if replace and type(replace) == dict:  # noqa
        for replace_field in replace.values():
            if hasattr(instance, replace_field):
                raise Exception(_(f"model_to_dict,要替换成{replace_field}字段已经存在了"))
    # 对要新增的默认值进行校验
    if default and type(default) == dict:  # noqa
        for default_key in default.keys():
            if hasattr(instance, default_key):
                raise Exception(_(f"model_to_dict,要新增默认值，但字段{default_key}已经存在了"))  # noqa
    opts = instance._meta
    data = {}
    for f in chain(opts.concrete_fields, opts.private_fields, opts.many_to_many):
        # 源码下：这块代码会将时间字段剔除掉，我加上一层判断，让其不再剔除时间字段
        if not getattr(f, "editable", False):
            if type(f) == DateField or type(f) == DateTimeField:  # noqa
                pass
            else:
                continue
        # 如果fields参数传递了，要进行判断
        if fields is not None and f.name not in fields:
            continue
        # 如果exclude 传递了，要进行判断
        if exclude and f.name in exclude:
            continue

        key = f.name
        # 获取字段对应的数据
        if type(f) == DateTimeField:  # noqa
            # 字段类型是，DateTimeFiled 使用自己的方式操作
            value = getattr(instance, key)
            value = timezone.localtime(value).strftime("%Y-%m-%d %H:%M") if value else ""
        elif type(f) == DateField:  # noqa
            # 字段类型是，DateFiled 使用自己的方式操作
            value = getattr(instance, key)
            value = value.strftime("%Y-%m-%d") if value else ""
        elif type(f) == CharField or type(f) == TextField:  # noqa
            value = getattr(instance, key)
        else:  # 其他类型的字段
            # value = getattr(instance, key)
            key = f.name
            value = f.value_from_object(instance)
            # data[f.name] = f.value_from_object(instance)
        # 1、替换字段名字
        if replace and key in replace.keys():
            key = replace.get(key)
        data[key] = value
    # 2、新增默认的字段数据
    if default:
        data.update(default)
    return data


DEVICE_DEFAULTS = {
    "rid": "",
    "alias": "",
    "device_group_name": "",
    "note": "",
    "version": "",
    "username": "",
    "hostname": "",
    "platform": "",
    "os": "",
    "cpu": "",
    "memory": "",
    "ip_address": "",
    "create_time": "",
    "update_time": "",
    "status": "",
    "owner_name": "",
    "rust_user": "",
    "strategy_name": "",
    "has_rhash": "",
}


def _normalize_device_item(item):
    for key, value in DEVICE_DEFAULTS.items():
        if key not in item:
            item[key] = value
    item["rid"] = str(item.get("rid") or "")
    return item


def index(request):
    if request.user and getattr(request.user, "is_authenticated", False):
        _log_event(request, "front_redirect_home", level="debug")
        return HttpResponseRedirect("/api/home")
    _log_event(request, "front_redirect_login", level="debug")
    return HttpResponseRedirect("/api/user_action?action=login")


def user_action(request):
    action = request.GET.get("action", "")
    if action == "login":
        return user_login(request)
    elif action == "register":
        return user_register(request)
    elif action == "logout":
        return user_logout(request)
    return JsonResponse({"error": _("未知操作。")}, status=404)


def user_login(request):
    if request.method == "GET":
        _log_event(request, "front_login_view", level="debug")
        return render(request, "login.html")
    if request.method != "POST":
        return JsonResponse({"code": 0, "msg": _("请求方式错误。")}, status=405)

    username = request.POST.get("account", "").strip()
    password = request.POST.get("password", "")
    if (
        not username
        or len(username) > UserProfile._meta.get_field("username").max_length
        or not password
        or len(password) > settings.MAX_PASSWORD_LENGTH
    ):
        return JsonResponse({"code": 0, "msg": _("登录信息无效。")}, status=400)

    client_ip = _client_ip(request)
    admission = reserve_login_attempt(client_ip, username)
    if admission is None:
        _log_event(request, "front_login_locked", level="warning", username=username)
        return JsonResponse({"code": 0, "msg": _("尝试次数过多，请稍后再试。")}, status=429)
    user = auth.authenticate(username=username, password=password)
    if not user:
        _log_event(request, "front_login_failed", level="warning", username=username)
        return JsonResponse({"code": 0, "msg": _("帐号或密码错误！")}, status=401)
    if user and not user.is_active:
        _log_event(request, "front_login_denied", level="warning", username=username, reason="inactive")
        return JsonResponse(
            {"code": 0, "msg": _("帐号未激活，请联系管理员。")},
            status=403,
        )
    if user:
        auth.login(request, user)
        complete_login_success(admission)
        _log_event(request, "front_login_success", username=username)
        return JsonResponse({"code": 1, "url": "/api/home"})
    return JsonResponse({"code": 0, "msg": _("帐号或密码错误！")})


def user_register(request):
    info = ""
    if request.method == "GET":
        _log_event(request, "front_register_view", level="debug")
        return render(request, "reg.html")
    if request.method != "POST":
        return JsonResponse({"code": 0, "msg": _("请求方式错误。")}, status=405)
    ALLOW_REGISTRATION = settings.ALLOW_REGISTRATION
    result = {"code": 0, "msg": ""}
    if not ALLOW_REGISTRATION:
        result["msg"] = _("当前未开放注册，请联系管理员！")
        _log_event(request, "front_register_denied", level="warning", reason="registration_disabled")
        return JsonResponse(result, status=403)

    username = request.POST.get("user", "").strip()
    password1 = request.POST.get("pwd", "")
    password2 = request.POST.get("repassword", "")
    client_ip = _client_ip(request)
    admission = reserve_login_attempt(client_ip, username, scope=REGISTER_SCOPE)
    if admission is None:
        return JsonResponse({"code": 0, "msg": _("尝试次数过多，请稍后再试。")}, status=429)

    if not 3 <= len(username) <= UserProfile._meta.get_field("username").max_length or any(
        ord(character) < 32 for character in username
    ):
        info = _("用户名长度或格式不符合要求。")
        result["msg"] = info
        _log_event(request, "front_register_failed", level="warning", username=username, reason="invalid_username")
        return JsonResponse(result, status=400)
    try:
        UserProfile._meta.get_field("username").run_validators(username)
    except ValidationError:
        result["msg"] = _("用户名长度或格式不符合要求。")
        _log_event(request, "front_register_failed", level="warning", username=username, reason="invalid_username")
        return JsonResponse(result, status=400)

    if (
        not isinstance(password1, str)
        or not isinstance(password2, str)
        or len(password1) > settings.MAX_PASSWORD_LENGTH
        or password1 != password2
    ):
        info = _("密码格式不符合要求。")
        result["msg"] = info
        _log_event(request, "front_register_failed", level="warning", username=username, reason="invalid_password")
        return JsonResponse(result, status=400)
    try:
        password_validation.validate_password(password1)
    except ValidationError:
        result["msg"] = _("密码强度不足，请使用更长且不常见的密码。")
        _log_event(request, "front_register_failed", level="warning", username=username, reason="weak_password")
        return JsonResponse(result, status=400)

    if UserProfile.objects.filter(username__iexact=username).exists():
        info = _("用户名已存在。")
        result["msg"] = info
        _log_event(request, "front_register_failed", level="warning", username=username, reason="username_exists")
        return JsonResponse(result, status=409)
    try:
        UserProfile.objects.create_user(
            username=username,
            password=password1,
            is_active=True,
        )
    except (IntegrityError, ValidationError):
        result["msg"] = _("用户名已存在。")
        _log_event(request, "front_register_failed", level="warning", username=username, reason="username_exists")
        return JsonResponse(result, status=409)
    result["msg"] = info
    result["code"] = 1
    _log_event(request, "front_register_success", username=username)
    return JsonResponse(result)


@login_required(login_url="/api/user_action?action=login")
def user_logout(request):
    if request.method != "POST":
        return JsonResponse({"error": _("请求方式错误。")}, status=405)
    auth.logout(request)
    _log_event(request, "front_logout")
    return HttpResponseRedirect("/api/user_action?action=login")


def get_single_info(uid):
    user = UserProfile.objects.filter(Q(id=uid)).first()
    personal_guid = _personal_guid(user) if user else ""
    address_book_peers = {
        peer.rid: model_to_dict(peer, exclude=("tags",))
        for peer in RemotePeer.objects.filter(
            profile__owner_id=uid,
            profile__guid=personal_guid,
        )
    }
    devices = (
        RemoteDevice.objects.filter(Q(owner_id=uid) | Q(rid__in=address_book_peers.keys()))
        .select_related(
            "owner__strategy",
            "device_group__strategy",
            "strategy",
        )
        .distinct()
    )
    now = timezone.now()
    items = {}
    for device in devices:
        item = model_to_dict2(device)
        item["owner_name"] = device.owner.username if device.owner else ""
        item["device_group_name"] = device.device_group.name if device.device_group_id else ""
        effective_strategy = device.effective_strategy()
        item["strategy_name"] = effective_strategy.name if effective_strategy else ""
        address_book_peer = address_book_peers.pop(device.rid, None)
        if address_book_peer:
            for key in ("alias", "platform", "rhash", "password"):
                if address_book_peer.get(key):
                    item[key] = address_book_peer[key]
            if not item.get("device_group_name"):
                item["device_group_name"] = address_book_peer.get("device_group_name", "")
            if not item.get("note"):
                item["note"] = address_book_peer.get("note", "")
        item["rust_user"] = item["owner_name"] or (user.username if user else "")
        item["status"] = _("在线") if (now - device.update_time).total_seconds() <= 120 else _("离线")
        rhash_value = item.get("rhash") or ""
        item["has_rhash"] = _("是") if len(rhash_value) > 1 else _("否")
        items[device.rid] = _normalize_device_item(item)

    # Address-book-only peers remain actionable even before a device heartbeat
    # creates the corresponding inventory record.
    for rid, item in address_book_peers.items():
        rhash_value = item.get("rhash") or ""
        item["has_rhash"] = _("是") if len(rhash_value) > 1 else _("否")
        item["rust_user"] = user.username if user else ""
        item["status"] = _("未知状态")
        items[rid] = _normalize_device_item(item)

    return list(items.values())


def get_all_info():
    device_objects = RemoteDevice.objects.select_related(
        "owner__strategy",
        "device_group__strategy",
        "strategy",
    )
    peers = RemotePeer.objects.filter(
        profile__guid__startswith="personal-",
    ).select_related("profile__owner")
    now = timezone.now()
    devices = {}
    for device in device_objects:
        item = model_to_dict2(device)
        item["owner_name"] = device.owner.username if device.owner else ""
        item["device_group_name"] = device.device_group.name if device.device_group_id else ""
        effective_strategy = device.effective_strategy()
        item["strategy_name"] = effective_strategy.name if effective_strategy else ""
        item["status"] = _("在线") if (now - device.update_time).total_seconds() <= 120 else _("离线")
        devices[device.rid] = item
    for peer in peers:
        user = peer.profile.owner
        device = devices.get(peer.rid, None)
        if device and user:
            devices[peer.rid]["rust_user"] = user.username
            devices[peer.rid]["alias"] = peer.alias

    for rid in devices.keys():
        if not devices[rid].get("rust_user", ""):
            devices[rid]["rust_user"] = _("未登录")
        if "alias" not in devices[rid]:
            devices[rid]["alias"] = ""
        _normalize_device_item(devices[rid])
    return [v for k, v in devices.items()]


def _get_current_user(request):
    user = getattr(request, "user", None)
    if not user or not getattr(user, "is_authenticated", False):
        return None
    return user


def _find_user(value, *, active_only=False):
    value = str(value or "").strip()
    if not value or len(value) > 150:
        return None
    query = Q(username__iexact=value)
    if value.isascii() and value.isdigit():
        query |= Q(pk=int(value))
    users = UserProfile.objects.filter(query)
    if active_only:
        users = users.filter(is_active=True)
    return users.order_by("pk").first()


def _find_group(value):
    value = str(value or "").strip()
    if not value or len(value) > 150:
        return None
    query = Q(name=value)
    if value.isascii() and value.isdigit():
        query |= Q(pk=int(value))
    return Group.objects.filter(query).order_by("pk").first()


@login_required(login_url="/api/user_action?action=login")
def work(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect("/api/user_action?action=login")
    try:
        _log_event(request, "front_work_view", username=u.username, show_type=request.GET.get("show_type", ""))
        show_type = request.GET.get("show_type", "")
        show_all = True if show_type == "admin" and u.is_admin else False
        paginator = (
            Paginator(get_all_info(), 15)
            if show_type == "admin" and u.is_admin
            else Paginator(get_single_info(u.id), 15)
        )
        page_number = request.GET.get("page")
        page_obj = paginator.get_page(page_number)
        nav_active = "work_admin" if show_all else "work"
        return render(
            request,
            "show_work.html",
            {"u": u, "show_all": show_all, "page_obj": page_obj, "nav_active": nav_active},
        )
    except Exception:  # noqa: BLE001 - page-level boundary renders a stable 500 response
        logger.exception("work view failed")
        return render(
            request,
            "msg.html",
            {
                "title": _("系统错误"),
                "msg": _("工作台加载失败，请检查数据库迁移与日志输出。"),
                "u": u,
                "nav_active": "work",
            },
            status=500,
        )


def _summarize_devices(items):
    total = len(items)
    online = 0
    offline = 0
    unknown = 0
    for item in items:
        status = item.get("status", "")
        if status == _("在线"):
            online += 1
        elif status == _("离线"):
            offline += 1
        else:
            unknown += 1
    return {
        "total": total,
        "online": online,
        "offline": offline,
        "unknown": unknown,
    }


def _is_personal_guid(guid):
    return str(guid).startswith("personal-")


def _personal_guid(user):
    return f"personal-{user.id}"


def _personal_profile_name():
    lang = str(getattr(settings, "LANGUAGE_CODE", "")).lower()
    return "我的地址簿" if lang.startswith("zh") else "My address book"


def _is_reserved_ab_profile_name(name):
    return name in {"My address book", "我的地址簿"}


def _ensure_personal_profile(user):
    guid = _personal_guid(user)
    with transaction.atomic():
        profile, _created = AddressBookProfile.objects.get_or_create(
            guid=guid,
            defaults={
                "name": _personal_profile_name(),
                "owner": user,
                "rule": 3,
            },
        )
        if str(profile.owner_id) != str(user.id):
            raise IntegrityError("Personal address-book GUID ownership conflict")
        updates = []
        if not profile.name:
            profile.name = _personal_profile_name()
            updates.append("name")
        if profile.rule != 3:
            profile.rule = 3
            updates.append("rule")
        if updates:
            updates.append("updated_at")
            profile.save(update_fields=updates)
    return profile


def _get_rule_access(profile, user):
    rule = 0
    share = AddressBookShare.objects.filter(Q(profile=profile) & Q(user=user)).first()
    if share:
        rule = max(rule, share.rule)
    rules = AddressBookRule.objects.filter(Q(profile=profile))
    if rules.exists():
        rule = max(rule, rules.filter(Q(is_everyone=True)).values_list("rule", flat=True).first() or 0)
        if user.groups.exists():
            group_rules = rules.filter(Q(group__in=user.groups.all())).values_list("rule", flat=True)
            for r in group_rules:
                rule = max(rule, r)
        user_rule = rules.filter(Q(user=user)).values_list("rule", flat=True).first()
        if user_rule:
            rule = max(rule, user_rule)
    return rule


def _get_profile_access_web(user, guid):
    if guid == _personal_guid(user):
        profile = _ensure_personal_profile(user)
        return profile, user, 3
    profile = AddressBookProfile.objects.filter(Q(guid=guid)).select_related("owner").first()
    if not profile:
        return None, None, 0
    if user.is_admin or str(profile.owner_id) == str(user.id):
        return profile, profile.owner, 3
    rule = _get_rule_access(profile, user)
    if not rule:
        return profile, None, 0
    return profile, profile.owner, rule


def _can_write_rule(rule):
    return rule in (2, 3)


def _ab_accessible_profiles(user, filter_q=None):
    profiles_qs = AddressBookProfile.objects.select_related("owner")
    if not user.is_admin:
        shared_guids = set(AddressBookShare.objects.filter(Q(user=user)).values_list("profile__guid", flat=True))
        rule_qs = AddressBookRule.objects.filter(Q(is_everyone=True) | Q(user=user))
        if user.groups.exists():
            rule_qs = rule_qs | AddressBookRule.objects.filter(Q(group__in=user.groups.all()))
        rule_guids = set(rule_qs.values_list("profile__guid", flat=True))
        accessible_guids = shared_guids | rule_guids
        profiles_qs = profiles_qs.filter(Q(owner=user) | Q(guid__in=accessible_guids))
    if filter_q:
        profiles_qs = profiles_qs.filter(
            Q(name__icontains=filter_q) | Q(guid__icontains=filter_q) | Q(owner__username__icontains=filter_q)
        )
    return profiles_qs


def _parse_rule(value):
    try:
        rule = int(value)
    except (TypeError, ValueError):
        return 1
    return rule if rule in (1, 2, 3) else 1


def _rule_label(rule):
    mapping = {
        1: _("只读"),
        2: _("读写"),
        3: _("完全控制"),
    }
    return mapping.get(rule, str(rule))


def _normalize_tags(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        items = value
    else:
        items = str(value).split(",")
    cleaned = []
    for item in items:
        tag = str(item).strip()
        if tag and tag not in cleaned:
            cleaned.append(tag)
    return cleaned


def _peer_tag_list(peer):
    tags = getattr(peer, "ordered_tags", None)
    if tags is None:
        tags = getattr(peer, "_prefetched_objects_cache", {}).get("tags")
    if tags is None:
        tags = list(peer.tags.order_by("tag_name"))
    else:
        tags = sorted(tags, key=lambda tag: tag.tag_name)
    return [tag.tag_name for tag in tags]


def _peer_tag_text(peer):
    return ",".join(_peer_tag_list(peer))


def _valid_tag_name(value):
    value = str(value or "").strip()
    if (
        not value
        or len(value) > 64
        or len(value.encode()) > 256
        or "," in value
        or any(ord(character) < 32 for character in value)
    ):
        return None
    return value


def _valid_tags(value):
    tags = _normalize_tags(value)
    if len(tags) > 32:
        return None
    return tags if all(_valid_tag_name(tag) == tag for tag in tags) else None


def _valid_form_text(value, *, max_chars, max_bytes, strip=True):
    if not isinstance(value, str):
        return None
    value = value.strip() if strip else value
    if (
        len(value) > max_chars
        or len(value.encode()) > max_bytes
        or any(ord(character) < 32 and character not in "\n\r\t" for character in value)
    ):
        return None
    return value


def _valid_peer_id(value):
    value = _valid_form_text(
        str(value or "").strip(),
        max_chars=255,
        max_bytes=1024,
    )
    if not value or any(character.isspace() for character in value):
        return None
    return value


def _peer_form_payload(post):
    rid = _valid_peer_id(post.get("rid", ""))
    alias = _valid_form_text(
        post.get("alias", ""),
        max_chars=100,
        max_bytes=400,
    )
    note = _valid_form_text(
        post.get("note", ""),
        max_chars=4096,
        max_bytes=4096,
    )
    password = _valid_form_text(
        post.get("password", ""),
        max_chars=256,
        max_bytes=1024,
        strip=False,
    )
    tags = _valid_tags(post.get("tags", ""))
    if rid is None or alias is None or note is None or password is None or tags is None:
        return None
    return {
        "rid": rid,
        "alias": alias,
        "note": note,
        "password": password,
        "tags": tags,
    }


def _upsert_tag(profile, name, color):
    with transaction.atomic():
        AddressBookProfile.objects.select_for_update().get(pk=profile.pk)
        tag = RemoteTag.objects.filter(
            profile=profile,
            tag_name=name,
        ).first()
        if tag:
            tag.tag_color = color
            tag.save(update_fields=["tag_color"])
            return True
        if (
            RemoteTag.objects.filter(
                profile=profile,
            ).count()
            >= MAX_AB_TAGS
        ):
            return False
        RemoteTag.objects.create(
            profile=profile,
            tag_name=name,
            tag_color=color,
        )
        return True


def _resolve_profile_tags(profile, tag_names):
    tag_names = list(dict.fromkeys(tag_names))
    existing = {
        tag.tag_name: tag
        for tag in RemoteTag.objects.filter(
            profile=profile,
            tag_name__in=tag_names,
        )
    }
    missing = [name for name in tag_names if name not in existing]
    if RemoteTag.objects.filter(profile=profile).count() + len(missing) > MAX_AB_TAGS:
        return None
    RemoteTag.objects.bulk_create(
        [
            RemoteTag(
                profile=profile,
                tag_name=name,
                tag_color="",
            )
            for name in missing
        ],
        ignore_conflicts=True,
    )
    return list(
        RemoteTag.objects.filter(
            profile=profile,
            tag_name__in=tag_names,
        )
    )


def _rename_tag(profile, old, new):
    with transaction.atomic():
        AddressBookProfile.objects.select_for_update().get(pk=profile.pk)
        old_tag = (
            RemoteTag.objects.select_for_update()
            .filter(
                profile=profile,
                tag_name=old,
            )
            .first()
        )
        if not old_tag:
            return False
        target = RemoteTag.objects.filter(
            profile=profile,
            tag_name=new,
        ).first()
        if target and target.pk != old_tag.pk:
            target.peers.add(*old_tag.peers.all())
            old_tag.delete()
        else:
            old_tag.tag_name = new
            old_tag.save(update_fields=["tag_name"])
    return True


def _delete_tag(profile, name):
    with transaction.atomic():
        AddressBookProfile.objects.select_for_update().get(pk=profile.pk)
        deleted = RemoteTag.objects.filter(
            profile=profile,
            tag_name=name,
        ).delete()[0]
    return deleted > 0


def _rule_target_info(rule_obj):
    if rule_obj.is_everyone:
        return "everyone", "Everyone"
    if rule_obj.group_id:
        return "group", rule_obj.group.name if rule_obj.group else ""
    if rule_obj.user_id:
        return "user", rule_obj.user.username if rule_obj.user else ""
    return "user", ""


def _rule_target_label(target_type):
    mapping = {
        "user": _("用户"),
        "group": _("用户组"),
        "everyone": _("所有人"),
    }
    return mapping.get(target_type, target_type)


def _audit_share(profile, actor, action, share, details=None):
    target_name = share.user.username if share.user else ""
    payload = {"guid": str(share.guid)}
    if details:
        payload.update(details)
    _audit_ab_rule(profile, actor, action, "user", target_name, share.rule, payload)


def _audit_rule(profile, actor, action, rule_obj, details=None):
    target_type, target_name = _rule_target_info(rule_obj)
    payload = {"guid": str(rule_obj.guid)}
    if details:
        payload.update(details)
    _audit_ab_rule(profile, actor, action, target_type, target_name, rule_obj.rule, payload)


def _apply_rule_change(request, user, action, rule_guid, rule_value=None, details=None):
    share = AddressBookShare.objects.filter(Q(guid=rule_guid)).select_related("profile", "user").first()
    if share:
        profile = share.profile
        if not profile:
            return False, _("规则不存在。")
        if not user.is_admin and str(profile.owner_id) != str(user.id):
            return False, _("无权限操作该地址簿。")
        if action == "delete_rule":
            _audit_share(profile, user, "share_delete", share, details)
            _log_event(
                request,
                "front_ab_share_delete",
                username=user.username,
                guid=profile.guid,
                target=share.user.username if share.user else "",
            )
            share.delete()
            return True, _("用户共享已删除。")
        old_rule = share.rule
        share.rule = rule_value
        share.save()
        _audit_share(profile, user, "share_update", share, {"before": old_rule, **(details or {})})
        _log_event(
            request,
            "front_ab_share_update",
            username=user.username,
            guid=profile.guid,
            target=share.user.username if share.user else "",
        )
        return True, _("用户共享已更新。")

    rule_obj = AddressBookRule.objects.filter(Q(guid=rule_guid)).select_related("profile", "user", "group").first()
    if not rule_obj:
        return False, _("规则不存在。")
    profile = rule_obj.profile
    if not profile:
        return False, _("规则不存在。")
    if not user.is_admin and str(profile.owner_id) != str(user.id):
        return False, _("无权限操作该地址簿。")
    if action == "delete_rule":
        _audit_rule(profile, user, "rule_delete", rule_obj, details)
        _log_event(request, "front_ab_rule_delete", username=user.username, guid=profile.guid)
        rule_obj.delete()
        return True, _("规则已删除。")
    old_rule = rule_obj.rule
    rule_obj.rule = rule_value
    rule_obj.save()
    _audit_rule(profile, user, "rule_update", rule_obj, {"before": old_rule, **(details or {})})
    _log_event(request, "front_ab_rule_update", username=user.username, guid=profile.guid)
    return True, _("规则已更新。")


def _collect_global_rules(filter_q=None, allowed_guids=None):
    rules = []
    shares = AddressBookShare.objects.select_related("profile", "user", "profile__owner").exclude(
        profile__guid__startswith="personal-"
    )
    for share in shares:
        profile = share.profile
        if not profile:
            continue
        if allowed_guids is not None and profile.guid not in allowed_guids:
            continue
        rules.append(
            {
                "guid": share.guid,
                "source": "share",
                "profile_name": profile.name,
                "profile_guid": profile.guid,
                "owner": profile.owner.username if profile.owner else "-",
                "target_type_key": "user",
                "target_type": _rule_target_label("user"),
                "target_name": share.user.username if share.user else "-",
                "rule": share.rule,
                "rule_label": _rule_label(share.rule),
            }
        )
    rule_rows = AddressBookRule.objects.select_related("profile", "user", "group", "profile__owner").exclude(
        profile__guid__startswith="personal-"
    )
    for rule in rule_rows:
        profile = rule.profile
        if not profile:
            continue
        if allowed_guids is not None and profile.guid not in allowed_guids:
            continue
        target_type, target_name = _rule_target_info(rule)
        rules.append(
            {
                "guid": rule.guid,
                "source": "rule",
                "profile_name": profile.name,
                "profile_guid": profile.guid,
                "owner": profile.owner.username if profile.owner else "-",
                "target_type_key": target_type,
                "target_type": _rule_target_label(target_type),
                "target_name": target_name if target_name else "-",
                "rule": rule.rule,
                "rule_label": _rule_label(rule.rule),
            }
        )
    if filter_q:
        q_lower = filter_q.lower()
        rules = [
            r
            for r in rules
            if q_lower in str(r.get("profile_name", "")).lower()
            or q_lower in str(r.get("profile_guid", "")).lower()
            or q_lower in str(r.get("owner", "")).lower()
            or q_lower in str(r.get("target_name", "")).lower()
        ]
    rules.sort(key=lambda x: (x.get("profile_name", ""), x.get("target_type", ""), x.get("target_name", "")))
    return rules


def _summarize_rules(rules):
    summary = {
        "total": len(rules),
        "user": 0,
        "group": 0,
        "everyone": 0,
        "read": 0,
        "write": 0,
        "full": 0,
    }
    for rule in rules:
        target_type = rule.get("target_type_key")
        if target_type in summary:
            summary[target_type] += 1
        rule_value = rule.get("rule", 0)
        if rule_value == 1:
            summary["read"] += 1
        elif rule_value == 2:
            summary["write"] += 1
        elif rule_value == 3:
            summary["full"] += 1
    return summary


def _audit_ab_rule(profile, actor, action, target_type, target_name, rule, details=None):
    if not profile:
        return
    payload = details if isinstance(details, (dict, list)) else {}
    AddressBookRuleAudit.objects.create(
        profile=profile,
        actor=actor if actor and getattr(actor, "id", None) else None,
        action=action,
        target_type=target_type,
        target_name=target_name or "",
        rule=int(rule or 1),
        details=payload,
    )


@login_required(login_url="/api/user_action?action=login")
def home(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect("/api/user_action?action=login")
    try:
        items = get_all_info() if u.is_admin else get_single_info(u.id)
        summary = _summarize_devices(items)
        recent = sorted(items, key=lambda x: x.get("update_time", ""), reverse=True)[:6]
        _log_event(request, "front_home_view", username=u.username, total=summary["total"])
        return render(
            request,
            "home.html",
            {
                "u": u,
                "summary": summary,
                "recent": recent,
                "nav_active": "home",
            },
        )
    except Exception:  # noqa: BLE001 - page-level boundary renders a stable 500 response
        logger.exception("home view failed")
        return render(
            request,
            "msg.html",
            {
                "title": _("系统错误"),
                "msg": _("首页加载失败，请检查数据库迁移与日志输出。"),
                "u": u,
                "nav_active": "home",
            },
            status=500,
        )


@login_required(login_url="/api/user_action?action=login")
def down_peers(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect("/api/user_action?action=login")

    if not u.is_admin:
        logger.debug("down_peers denied, is_admin=%s", u.is_admin)
        _log_event(request, "front_export_denied", level="warning", username=u.username)
        return HttpResponseRedirect("/api/work")

    _log_event(request, "front_export_xlsx", username=u.username)
    all_info = get_all_info()
    all_fields = [x.name for x in RemoteDevice._meta.get_fields()]
    all_fields.append("rust_user")
    rows = [[one.get(name, "-") for name in all_fields] for one in all_info]
    return xlsx_response("DeviceInfo.xlsx", _("设备信息表"), all_fields, rows)


MAX_SHARE_PEERS = 20
MAX_ACTIVE_SHARE_LINKS = 20


def _share_token_hash(raw_token):
    return hashlib.sha256(raw_token.encode()).hexdigest()


def _share_message(request, title, message, status=200):
    return render(
        request,
        "msg.html",
        {
            "title": _(title),
            "msg": _(message),
            "u": request.user,
            "nav_active": "share",
        },
        status=status,
    )


@login_required(login_url="/api/user_action?action=login")
def share(request, share_token=None):
    is_admin = getattr(request.user, "is_admin", False)
    now = timezone.now()

    if share_token is not None:
        if (
            not secrets.compare_digest(
                share_token,
                "".join(ch for ch in share_token if ch.isalnum() or ch in "-_"),
            )
            or not 32 <= len(share_token) <= 128
        ):
            return _share_message(request, "错误", "分享链接不存在或已失效。", status=404)
        token_hash = _share_token_hash(share_token)
        if request.method == "GET":
            link = (
                ShareLink.objects.select_related("creator")
                .filter(
                    shash=token_hash,
                    is_used=False,
                    is_expired=False,
                    expires_at__gt=now,
                )
                .first()
            )
            if not link:
                return _share_message(request, "错误", "分享链接不存在或已失效。", status=404)
            if request.user.id == link.creator_id:
                return _share_message(request, "错误", "不能领取自己创建的分享链接。", status=403)
            peer_count = link.peers.count()
            return render(
                request,
                "share_accept.html",
                {
                    "peer_count": peer_count,
                    "expires_at": link.expires_at,
                    "share_token": share_token,
                    "u": request.user,
                    "nav_active": "share",
                },
            )
        with transaction.atomic():
            link = (
                ShareLink.objects.select_for_update(of=("self",))
                .select_related("creator")
                .filter(shash=token_hash)
                .first()
            )
            if not link or link.is_used or link.is_expired or link.expires_at <= timezone.now():
                if link and not link.is_used:
                    link.is_expired = True
                    link.save(update_fields=["is_expired"])
                return _share_message(request, "错误", "分享链接不存在或已失效。", status=404)
            if request.user.id == link.creator_id:
                return _share_message(request, "错误", "不能领取自己创建的分享链接。", status=403)
            peer_count = link.peers.count()
            if not 1 <= peer_count <= MAX_SHARE_PEERS:
                link.is_expired = True
                link.save(update_fields=["is_expired"])
                return _share_message(request, "错误", "分享链接内容无效。", status=400)
            source_peers = list(
                link.peers.filter(
                    profile__owner_id=link.creator_id,
                )
                .prefetch_related(
                    Prefetch(
                        "tags",
                        queryset=RemoteTag.objects.order_by("tag_name"),
                        to_attr="ordered_tags",
                    )
                )
                .order_by("pk")
            )
            if len(source_peers) != peer_count:
                link.is_expired = True
                link.save(update_fields=["is_expired"])
                return _share_message(request, "错误", "分享链接内容无效。", status=400)
            personal_profile = _ensure_personal_profile(request.user)
            AddressBookProfile.objects.select_for_update().get(
                pk=personal_profile.pk,
            )
            existing_ids = set(
                RemotePeer.objects.filter(
                    profile=personal_profile,
                    rid__in=[peer.rid for peer in source_peers],
                ).values_list("rid", flat=True)
            )
            sources_to_import = [peer for peer in source_peers if peer.rid not in existing_ids]
            recipient_peer_count = RemotePeer.objects.filter(
                profile=personal_profile,
            ).count()
            if recipient_peer_count + len(sources_to_import) > MAX_AB_PEERS:
                return _share_message(
                    request,
                    "错误",
                    "个人地址簿设备数量已达到上限。",
                    status=409,
                )
            source_tag_names = list(
                dict.fromkeys(tag_name for peer in sources_to_import for tag_name in _peer_tag_list(peer))
            )
            recipient_tags = _resolve_profile_tags(
                personal_profile,
                source_tag_names,
            )
            if recipient_tags is None:
                return _share_message(
                    request,
                    "错误",
                    "个人地址簿标签数量已达到上限。",
                    status=409,
                )
            tags_by_name = {tag.tag_name: tag for tag in recipient_tags}
            imports = []
            for source in sources_to_import:
                peer = RemotePeer.objects.create(
                    profile=personal_profile,
                    rid=source.rid,
                    username=source.username,
                    hostname=source.hostname,
                    alias=source.alias,
                    platform=source.platform,
                    rhash=source.rhash,
                    note=source.note,
                    password="",
                    device_group_name=source.device_group_name,
                    login_name=source.login_name,
                    same_server=source.same_server,
                )
                peer.tags.set([tags_by_name[name] for name in _peer_tag_list(source)])
                imports.append(peer)
            link.is_used = True
            link.used_at = timezone.now()
            link.used_by = request.user
            link.save(update_fields=["is_used", "used_at", "used_by"])
        _log_event(
            request,
            "front_share_accept",
            username=request.user.username,
            token_id=link.shash[:16],
            imported=len(imports),
        )
        return _share_message(
            request,
            "成功",
            f"已获取 {len(imports)} 台设备；已存在的设备不会被覆盖。",
        )

    if is_admin:
        peers_qs = RemotePeer.objects.select_related(
            "profile__owner",
        ).order_by("profile__owner__username", "rid", "pk")
        sharelinks_qs = (
            ShareLink.objects.select_related("creator")
            .filter(
                is_used=False,
                is_expired=False,
                expires_at__gt=now,
            )
            .annotate(peer_count_value=Count("peers"))
        )
    else:
        peers_qs = (
            RemotePeer.objects.filter(
                profile__owner=request.user,
            )
            .select_related("profile__owner")
            .order_by("rid", "pk")
        )
        sharelinks_qs = (
            ShareLink.objects.select_related("creator")
            .filter(
                creator=request.user,
                is_used=False,
                is_expired=False,
                expires_at__gt=now,
            )
            .annotate(peer_count_value=Count("peers"))
        )

    peers = []
    for p in peers_qs:
        owner = p.profile.owner.username if is_admin else None
        if is_admin:
            peers.append({"id": str(p.pk), "name": f"{p.rid}|{p.alias}|{owner}"})
        else:
            peers.append({"id": str(p.pk), "name": f"{p.rid}|{p.alias}"})

    sharelinks = []
    for s in sharelinks_qs:
        owner = s.creator.username if is_admin else None
        row = {
            "token_prefix": s.token_prefix,
            "is_used": s.is_used,
            "is_expired": s.is_expired,
            "create_time": s.create_time,
            "expires_at": s.expires_at,
            "peer_count": s.peer_count_value,
        }
        if is_admin:
            row["owner"] = owner
        sharelinks.append(row)

    if request.method == "GET":
        _log_event(request, "front_share_view", username=request.user.username)
        return render(
            request,
            "share.html",
            {"peers": peers, "sharelinks": sharelinks, "u": request.user, "nav_active": "share", "is_admin": is_admin},
        )
    else:
        data = request.POST.get("data", "[]")
        try:
            data = json.loads(data)
        except (TypeError, json.JSONDecodeError):
            _log_event(
                request,
                "front_share_create_failed",
                level="warning",
                username=request.user.username,
                reason="invalid_json",
            )
            return JsonResponse({"code": 0, "msg": _("数据解析失败。")})
        if not data:
            _log_event(
                request,
                "front_share_create_failed",
                level="warning",
                username=request.user.username,
                reason="empty_data",
            )
            return JsonResponse({"code": 0, "msg": _("数据为空。")})
        if not isinstance(data, list) or not 1 <= len(data) <= MAX_SHARE_PEERS:
            return JsonResponse({"code": 0, "msg": _("一次最多分享 20 台设备。")}, status=400)
        selected_keys = {str(item.get("value", "")).strip() for item in data if isinstance(item, dict)}
        if len(selected_keys) != len(data) or any(not key.isdigit() for key in selected_keys):
            _log_event(
                request,
                "front_share_create_failed",
                level="warning",
                username=request.user.username,
                reason="empty_ids",
            )
            return JsonResponse({"code": 0, "msg": _("设备选择无效。")}, status=400)

        share_uid = request.user.id
        selected_peers = RemotePeer.objects.filter(pk__in=selected_keys)
        if is_admin:
            owner_ids = list(
                selected_peers.values_list(
                    "profile__owner_id",
                    flat=True,
                ).distinct()
            )
            if not owner_ids:
                _log_event(
                    request,
                    "front_share_create_failed",
                    level="warning",
                    username=request.user.username,
                    reason="owner_missing",
                )
                return JsonResponse({"code": 0, "msg": _("未找到所选设备的归属用户。")})
            if len(owner_ids) > 1:
                _log_event(
                    request,
                    "front_share_create_failed",
                    level="warning",
                    username=request.user.username,
                    reason="mixed_owner",
                )
                return JsonResponse({"code": 0, "msg": _("请选择同一用户的设备进行分享。")})
            share_uid = owner_ids[0]
        else:
            selected_peers = selected_peers.filter(profile__owner=request.user)
            if selected_peers.count() != len(selected_keys):
                _log_event(
                    request,
                    "front_share_create_failed",
                    level="warning",
                    username=request.user.username,
                    reason="invalid_owner",
                )
                return JsonResponse({"code": 0, "msg": _("仅支持分享自己名下的设备。")}, status=403)

        selected_peer_keys = list(selected_peers.order_by("pk").values_list("pk", flat=True))
        if len(selected_peer_keys) != len(selected_keys):
            return JsonResponse({"code": 0, "msg": _("设备选择无效。")}, status=400)
        with transaction.atomic():
            source_user = (
                UserProfile.objects.select_for_update()
                .filter(
                    pk=share_uid,
                    is_active=True,
                )
                .first()
            )
            if not source_user:
                return JsonResponse(
                    {"code": 0, "msg": _("设备归属用户不存在或已禁用。")},
                    status=409,
                )
            if (
                ShareLink.objects.filter(
                    creator=source_user,
                    is_used=False,
                    is_expired=False,
                    expires_at__gt=timezone.now(),
                ).count()
                >= MAX_ACTIVE_SHARE_LINKS
            ):
                return JsonResponse(
                    {"code": 0, "msg": _("有效分享链接数量已达到上限。")},
                    status=429,
                )
            raw_token = secrets.token_urlsafe(32)
            sharelink = ShareLink.objects.create(
                creator=source_user,
                shash=_share_token_hash(raw_token),
                token_prefix=raw_token[:8],
            )
            sharelink.peers.set(selected_peer_keys)
        _log_event(request, "front_share_create", username=request.user.username, count=len(selected_peer_keys))

        return JsonResponse({"code": 1, "token": raw_token, "expires_at": sharelink.expires_at.isoformat()})


@login_required(login_url="/api/user_action?action=login")
def ab_manage(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect("/api/user_action?action=login")

    filter_q = str(request.GET.get("q", "")).strip()

    if request.method == "POST":
        filter_q = str(request.POST.get("q", filter_q)).strip()
        action = request.POST.get("action", "")
        if action in ("update_rule", "delete_rule"):
            rule_value = _parse_rule(request.POST.get("rule", 1))
            rule_guid = request.POST.get("rule_guid", "")
            if not rule_guid:
                messages.error(request, _("规则不存在。"))
                return HttpResponseRedirect("/api/ab_manage")
            ok, msg = _apply_rule_change(request, u, action, rule_guid, rule_value)
            if ok:
                messages.success(request, msg)
            else:
                messages.error(request, msg)
            return HttpResponseRedirect("/api/ab_manage")

        profile_guid = request.POST.get("profile_guid", "")
        rule_value = _parse_rule(request.POST.get("rule", 1))
        profile = AddressBookProfile.objects.filter(Q(guid=profile_guid)).select_related("owner").first()

        if not profile or _is_personal_guid(profile.guid):
            messages.error(request, _("地址簿不存在或不可配置。"))
            return HttpResponseRedirect("/api/ab_manage")

        if not u.is_admin and str(profile.owner_id) != str(u.id):
            messages.error(request, _("无权限操作该地址簿。"))
            return HttpResponseRedirect("/api/ab_manage")

        if action == "add_user_share":
            user_key = str(request.POST.get("user", "")).strip()
            if not user_key:
                messages.error(request, _("用户不存在。"))
                return HttpResponseRedirect("/api/ab_manage")
            target = _find_user(user_key, active_only=True)
            if not target:
                messages.error(request, _("用户不存在。"))
                return HttpResponseRedirect("/api/ab_manage")
            share = AddressBookShare.objects.filter(Q(profile=profile) & Q(user=target)).first()
            created = False
            if not share:
                share = AddressBookShare(profile=profile, user=target, rule=rule_value)
                created = True
            else:
                share.rule = rule_value
            share.save()
            action_name = "share_add" if created else "share_update"
            _audit_share(profile, u, action_name, share, {"created": created})
            _log_event(request, "front_ab_share_add", username=u.username, guid=profile_guid, target=target.username)
            messages.success(request, _("用户共享已更新。"))
            return HttpResponseRedirect("/api/ab_manage")

        if action == "add_group_rule":
            group_key = str(request.POST.get("group", "")).strip()
            if not group_key:
                messages.error(request, _("用户组不存在。"))
                return HttpResponseRedirect("/api/ab_manage")
            group = _find_group(group_key)
            if not group:
                messages.error(request, _("用户组不存在。"))
                return HttpResponseRedirect("/api/ab_manage")
            rule_obj = AddressBookRule.objects.filter(Q(profile=profile) & Q(group=group)).first()
            created = False
            if not rule_obj:
                rule_obj = AddressBookRule(profile=profile, group=group, rule=rule_value)
                created = True
            else:
                rule_obj.rule = rule_value
            rule_obj.is_everyone = False
            rule_obj.save()
            action_name = "rule_add" if created else "rule_update"
            _audit_rule(profile, u, action_name, rule_obj, {"created": created})
            _log_event(request, "front_ab_rule_group_add", username=u.username, guid=profile_guid, group=group.name)
            messages.success(request, _("组规则已更新。"))
            return HttpResponseRedirect("/api/ab_manage")

        if action == "add_everyone_rule":
            rule_obj = AddressBookRule.objects.filter(Q(profile=profile) & Q(is_everyone=True)).first()
            created = False
            if not rule_obj:
                rule_obj = AddressBookRule(profile=profile, rule=rule_value, is_everyone=True)
                created = True
            else:
                rule_obj.rule = rule_value
            rule_obj.save()
            action_name = "rule_add" if created else "rule_update"
            _audit_rule(profile, u, action_name, rule_obj, {"created": created})
            _log_event(request, "front_ab_rule_everyone_add", username=u.username, guid=profile_guid)
            messages.success(request, _("Everyone 规则已更新。"))
            return HttpResponseRedirect("/api/ab_manage")

        messages.error(request, _("操作失败。"))
        return HttpResponseRedirect("/api/ab_manage")

    profiles_qs = AddressBookProfile.objects.exclude(guid__startswith="personal-").select_related("owner")
    if not u.is_admin:
        profiles_qs = profiles_qs.filter(owner=u)
    if filter_q:
        profiles_qs = profiles_qs.filter(
            Q(name__icontains=filter_q) | Q(guid__icontains=filter_q) | Q(owner__username__icontains=filter_q)
        )

    profiles = []
    for profile in profiles_qs.order_by("name"):
        shares = AddressBookShare.objects.filter(profile=profile).select_related("user")
        user_rules = AddressBookRule.objects.filter(profile=profile, user__isnull=False).select_related("user")
        group_rules = AddressBookRule.objects.filter(profile=profile, group__isnull=False).select_related("group")
        everyone_rule = AddressBookRule.objects.filter(profile=profile, is_everyone=True).first()

        user_entries = [
            {
                "guid": s.guid,
                "name": s.user.username if s.user else "-",
                "rule": s.rule,
                "rule_label": _rule_label(s.rule),
            }
            for s in shares
        ]
        for r in user_rules:
            user_entries.append(
                {
                    "guid": r.guid,
                    "name": r.user.username if r.user else "-",
                    "rule": r.rule,
                    "rule_label": _rule_label(r.rule),
                }
            )
        user_entries.sort(key=lambda x: x["name"])

        group_entries = [
            {
                "guid": r.guid,
                "name": r.group.name if r.group else "-",
                "rule": r.rule,
                "rule_label": _rule_label(r.rule),
            }
            for r in group_rules
        ]
        group_entries.sort(key=lambda x: x["name"])

        profiles.append(
            {
                "profile": profile,
                "user_entries": user_entries,
                "group_entries": group_entries,
                "everyone_rule": {
                    "guid": everyone_rule.guid,
                    "rule": everyone_rule.rule,
                    "rule_label": _rule_label(everyone_rule.rule),
                }
                if everyone_rule
                else None,
                "can_manage": u.is_admin or str(profile.owner_id) == str(u.id),
            }
        )

    rule_choices = [
        (1, _("只读")),
        (2, _("读写")),
        (3, _("完全控制")),
    ]

    global_rules = []
    rule_stats = None
    if u.is_admin:
        global_rules = _collect_global_rules(filter_q)
        rule_stats = _summarize_rules(global_rules)

    return render(
        request,
        "ab_manage.html",
        {
            "u": u,
            "profiles": profiles,
            "global_rules": global_rules,
            "rule_stats": rule_stats,
            "filter_q": filter_q,
            "groups": Group.objects.all().order_by("name"),
            "rule_choices": rule_choices,
            "nav_active": "ab_manage",
        },
    )


@login_required(login_url="/api/user_action?action=login")
def ab_books(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect("/api/user_action?action=login")

    filter_q = str(request.GET.get("q", "")).strip()[:200]

    if request.method == "POST":
        action = request.POST.get("action", "")
        if action == "create_book":
            name = _valid_form_text(
                request.POST.get("name", ""),
                max_chars=60,
                max_bytes=240,
            )
            note = _valid_form_text(
                request.POST.get("note", ""),
                max_chars=4096,
                max_bytes=4096,
                strip=False,
            )
            owner_key = str(request.POST.get("owner", "")).strip()
            if not name or note is None:
                messages.error(request, _("地址簿名称或备注格式无效。"))
                return HttpResponseRedirect("/api/ab_books")
            if _is_reserved_ab_profile_name(name):
                messages.error(request, _("地址簿名称为保留名称。"))
                return HttpResponseRedirect("/api/ab_books")
            owner = u
            if u.is_admin and owner_key:
                owner = _find_user(owner_key, active_only=True)
                if not owner:
                    messages.error(request, _("目标用户不存在。"))
                    return HttpResponseRedirect("/api/ab_books")
            try:
                profile = AddressBookProfile.objects.create(
                    guid=uuid.uuid4().hex,
                    name=name,
                    owner=owner,
                    rule=3,
                    note=note,
                )
            except IntegrityError:
                messages.error(request, _("地址簿名称已存在。"))
                return HttpResponseRedirect("/api/ab_books")
            _log_event(request, "front_ab_book_create", username=u.username, guid=profile.guid, owner=owner.username)
            messages.success(request, _("地址簿已创建。"))
            return HttpResponseRedirect("/api/ab_books")

        if action == "update_book":
            guid = request.POST.get("guid", "")
            profile = AddressBookProfile.objects.filter(Q(guid=guid)).select_related("owner").first()
            if not profile:
                messages.error(request, _("地址簿不存在。"))
                return HttpResponseRedirect("/api/ab_books")
            if _is_personal_guid(profile.guid):
                messages.error(request, _("个人地址簿不可修改。"))
                return HttpResponseRedirect("/api/ab_books")
            if not u.is_admin and str(profile.owner_id) != str(u.id):
                messages.error(request, _("无权限操作该地址簿。"))
                return HttpResponseRedirect("/api/ab_books")
            name = _valid_form_text(
                request.POST.get("name", ""),
                max_chars=60,
                max_bytes=240,
            )
            note = _valid_form_text(
                request.POST.get("note", ""),
                max_chars=4096,
                max_bytes=4096,
                strip=False,
            )
            if not name or note is None:
                messages.error(request, _("地址簿名称或备注格式无效。"))
                return HttpResponseRedirect("/api/ab_books")
            if name != profile.name:
                if _is_reserved_ab_profile_name(name):
                    messages.error(request, _("地址簿名称为保留名称。"))
                    return HttpResponseRedirect("/api/ab_books")
                if (
                    AddressBookProfile.objects.filter(Q(owner=profile.owner) & Q(name=name))
                    .exclude(pk=profile.pk)
                    .exists()
                ):
                    messages.error(request, _("地址簿名称已存在。"))
                    return HttpResponseRedirect("/api/ab_books")
                profile.name = name
            profile.note = note
            try:
                profile.save()
            except IntegrityError:
                messages.error(request, _("地址簿名称已存在。"))
                return HttpResponseRedirect("/api/ab_books")
            _log_event(request, "front_ab_book_update", username=u.username, guid=profile.guid)
            messages.success(request, _("地址簿已更新。"))
            return HttpResponseRedirect("/api/ab_books")

        if action == "delete_book":
            guid = request.POST.get("guid", "")
            profile = AddressBookProfile.objects.filter(Q(guid=guid)).select_related("owner").first()
            if not profile:
                messages.error(request, _("地址簿不存在。"))
                return HttpResponseRedirect("/api/ab_books")
            if _is_personal_guid(profile.guid):
                messages.error(request, _("个人地址簿不可删除。"))
                return HttpResponseRedirect("/api/ab_books")
            if not u.is_admin and str(profile.owner_id) != str(u.id):
                messages.error(request, _("无权限操作该地址簿。"))
                return HttpResponseRedirect("/api/ab_books")
            profile.delete()
            _log_event(request, "front_ab_book_delete", username=u.username, guid=guid)
            messages.success(request, _("地址簿已删除。"))
            return HttpResponseRedirect("/api/ab_books")

        if action == "transfer_book":
            if not u.is_admin:
                messages.error(request, _("无权限操作该地址簿。"))
                return HttpResponseRedirect("/api/ab_books")
            guid = request.POST.get("guid", "")
            target_key = str(request.POST.get("owner", "")).strip()
            profile = AddressBookProfile.objects.filter(Q(guid=guid)).select_related("owner").first()
            if not profile:
                messages.error(request, _("地址簿不存在。"))
                return HttpResponseRedirect("/api/ab_books")
            if _is_personal_guid(profile.guid):
                messages.error(request, _("个人地址簿不可修改。"))
                return HttpResponseRedirect("/api/ab_books")
            if not target_key:
                messages.error(request, _("目标用户不存在。"))
                return HttpResponseRedirect("/api/ab_books")
            new_owner = _find_user(target_key, active_only=True)
            if not new_owner:
                messages.error(request, _("目标用户不存在。"))
                return HttpResponseRedirect("/api/ab_books")
            if str(profile.owner_id) != str(new_owner.id):
                if (
                    AddressBookProfile.objects.filter(
                        owner=new_owner,
                        name=profile.name,
                    )
                    .exclude(pk=profile.pk)
                    .exists()
                ):
                    messages.error(request, _("目标用户已有同名地址簿。"))
                    return HttpResponseRedirect("/api/ab_books")
                try:
                    with transaction.atomic():
                        profile = AddressBookProfile.objects.select_for_update().get(pk=profile.pk)
                        profile.owner = new_owner
                        profile.save(update_fields=["owner", "updated_at"])
                        AddressBookShare.objects.filter(
                            profile=profile,
                            user=new_owner,
                        ).delete()
                except IntegrityError:
                    messages.error(request, _("目标用户已有同名地址簿。"))
                    return HttpResponseRedirect("/api/ab_books")
            _log_event(
                request, "front_ab_book_transfer", username=u.username, guid=profile.guid, owner=new_owner.username
            )
            messages.success(request, _("地址簿已更新。"))
            return HttpResponseRedirect("/api/ab_books")

    profiles_qs = _ab_accessible_profiles(u, filter_q)

    profiles = []
    for profile in profiles_qs.order_by("name"):
        is_personal = _is_personal_guid(profile.guid)
        peers_count = profile.peers.count()
        tags_count = profile.tags.count()
        access_rule = 3 if (u.is_admin or str(profile.owner_id) == str(u.id)) else _get_rule_access(profile, u)
        can_edit = u.is_admin or str(profile.owner_id) == str(u.id) or _can_write_rule(access_rule)
        profiles.append(
            {
                "profile": profile,
                "is_personal": is_personal,
                "peers_count": peers_count,
                "tags_count": tags_count,
                "access_rule": access_rule,
                "access_label": _rule_label(access_rule) if access_rule else _("无权限"),
                "can_manage": u.is_admin or str(profile.owner_id) == str(u.id),
                "can_edit": can_edit,
            }
        )

    _log_event(request, "front_ab_books_view", username=u.username, total=len(profiles))
    return render(
        request,
        "ab_books.html",
        {
            "u": u,
            "profiles": profiles,
            "filter_q": filter_q,
            "nav_active": "ab_books",
        },
    )


@login_required(login_url="/api/user_action?action=login")
def ab_books_export(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect("/api/user_action?action=login")
    export_format = str(request.GET.get("format", "csv")).lower()
    filter_q = str(request.GET.get("q", "")).strip()
    profiles_qs = _ab_accessible_profiles(u, filter_q).order_by("name")
    profiles = list(profiles_qs)
    filename_stamp = _filename_stamp()

    headers = [_("地址簿名称"), _("地址簿 GUID"), _("所属用户"), _("备注（可选）"), _("设备"), _("标签")]

    if export_format in ("xls", "xlsx"):
        rows = []
        for profile in profiles:
            peers_count = profile.peers.count()
            tags_count = profile.tags.count()
            rows.append(
                [
                    profile.name,
                    profile.guid,
                    profile.owner.username if profile.owner else "-",
                    profile.note or "",
                    peers_count,
                    tags_count,
                ]
            )
        response = xlsx_response(f"ab_books_{filename_stamp}.xlsx", _("地址簿列表"), headers, rows)
        _log_event(request, "front_ab_books_export", username=u.username, count=len(profiles))
        return response

    output = StringIO()
    writer = safe_csv_writer(output)
    writer.writerow(headers)
    for profile in profiles:
        peers_count = profile.peers.count()
        tags_count = profile.tags.count()
        writer.writerow(
            [
                profile.name,
                profile.guid,
                profile.owner.username if profile.owner else "-",
                profile.note or "",
                peers_count,
                tags_count,
            ]
        )
    response = HttpResponse(output.getvalue(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f"attachment; filename=ab_books_{filename_stamp}.csv"
    _log_event(request, "front_ab_books_export", username=u.username, count=len(profiles))
    return response


@login_required(login_url="/api/user_action?action=login")
def ab_book(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect("/api/user_action?action=login")

    guid = request.GET.get("guid", "") or request.POST.get("guid", "")
    if not guid:
        messages.error(request, _("地址簿不存在。"))
        return HttpResponseRedirect("/api/ab_books")

    profile, owner, rule = _get_profile_access_web(u, guid)
    if not profile:
        messages.error(request, _("地址簿不存在。"))
        return HttpResponseRedirect("/api/ab_books")
    if not owner and not u.is_admin:
        messages.error(request, _("无权限操作该地址簿。"))
        return HttpResponseRedirect("/api/ab_books")

    can_edit = u.is_admin or str(profile.owner_id) == str(u.id) or _can_write_rule(rule)
    is_personal = _is_personal_guid(profile.guid)

    if request.method == "POST":
        action = request.POST.get("action", "")
        if not can_edit:
            messages.error(request, _("当前权限不足以修改地址簿内容。"))
            return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")

        if action in ("bulk_tag_add", "bulk_tag_remove", "bulk_tag_replace", "bulk_note_update", "bulk_peer_delete"):
            peer_ids = request.POST.getlist("peer_ids")
            tags_input = request.POST.get("tags", "")
            tags = _valid_tags(tags_input)
            if (
                not peer_ids
                or len(peer_ids) > 500
                or any(_valid_peer_id(peer_id) != peer_id for peer_id in peer_ids)
                or tags is None
            ):
                messages.error(request, _("请选择至少一台设备。"))
                return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
            peers_qs = RemotePeer.objects.filter(
                profile=profile,
                rid__in=peer_ids,
            )
            updated = 0
            if action in ("bulk_tag_add", "bulk_tag_remove", "bulk_tag_replace"):
                with transaction.atomic():
                    AddressBookProfile.objects.select_for_update().get(pk=profile.pk)
                    peers = list(peers_qs.select_for_update().prefetch_related("tags"))
                    tags_by_peer = {}
                    required_tags = set()
                    for peer in peers:
                        existing = _peer_tag_list(peer)
                        if action == "bulk_tag_add":
                            new_tags = list(dict.fromkeys([*existing, *tags]))
                        elif action == "bulk_tag_remove":
                            new_tags = [tag for tag in existing if tag not in tags]
                        else:
                            new_tags = tags[:]
                        if len(new_tags) > MAX_AB_TAGS_PER_PEER:
                            messages.error(request, _("每台设备最多支持 32 个标签。"))
                            return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
                        tags_by_peer[peer.pk] = new_tags
                        required_tags.update(new_tags)
                    resolved_tags = _resolve_profile_tags(
                        profile,
                        required_tags,
                    )
                    if resolved_tags is None:
                        messages.error(request, _("地址簿标签数量已达到上限。"))
                        return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
                    tags_by_name = {tag.tag_name: tag for tag in resolved_tags}
                    for peer in peers:
                        peer.tags.set([tags_by_name[name] for name in tags_by_peer[peer.pk]])
                    updated = len(peers)
                _log_event(
                    request, "front_ab_bulk_tag", username=u.username, guid=profile.guid, action=action, count=updated
                )
                messages.success(request, _("已批量更新 %(count)s 台设备标签。") % {"count": updated})
                return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")

            if action == "bulk_note_update":
                note_value = _valid_form_text(
                    request.POST.get("note", ""),
                    max_chars=4096,
                    max_bytes=4096,
                )
                if note_value is None:
                    messages.error(request, _("备注内容过长或格式无效。"))
                    return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
                updated = peers_qs.update(note=note_value)
                _log_event(request, "front_ab_bulk_note", username=u.username, guid=profile.guid, count=updated)
                messages.success(request, _("已批量更新 %(count)s 台设备备注。") % {"count": updated})
                return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")

            if action == "bulk_peer_delete":
                deleted = peers_qs.count()
                peers_qs.delete()
                _log_event(request, "front_ab_bulk_delete", username=u.username, guid=profile.guid, count=deleted)
                messages.success(request, _("已批量删除 %(count)s 台设备。") % {"count": deleted})
                return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")

        if action == "add_tag":
            name = _valid_tag_name(request.POST.get("name", ""))
            color = normalize_tag_color(request.POST.get("color", ""))
            if name is None or color is None:
                messages.error(request, _("标签名称或颜色格式无效。"))
                return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
            if not _upsert_tag(profile, name, color):
                messages.error(request, _("地址簿标签数量已达到上限。"))
                return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
            _log_event(request, "front_ab_tag_add", username=u.username, guid=profile.guid, tag=name)
            messages.success(request, _("标签已更新。"))
            return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")

        if action == "rename_tag":
            old = _valid_tag_name(request.POST.get("old", ""))
            new = _valid_tag_name(request.POST.get("new", ""))
            if old is None or new is None:
                messages.error(request, _("标签名称无效。"))
                return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
            if not _rename_tag(profile, old, new):
                messages.error(request, _("标签不存在。"))
                return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
            _log_event(request, "front_ab_tag_rename", username=u.username, guid=profile.guid, old=old, new=new)
            messages.success(request, _("标签已重命名。"))
            return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")

        if action == "update_tag":
            name = _valid_tag_name(request.POST.get("name", ""))
            color = normalize_tag_color(request.POST.get("color", ""))
            if name is None or color is None:
                messages.error(request, _("标签名称或颜色格式无效。"))
                return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
            if not _upsert_tag(profile, name, color):
                messages.error(request, _("地址簿标签数量已达到上限。"))
                return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
            _log_event(request, "front_ab_tag_update", username=u.username, guid=profile.guid, tag=name)
            messages.success(request, _("标签颜色已更新。"))
            return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")

        if action == "delete_tag":
            name = _valid_tag_name(request.POST.get("name", ""))
            if name is None:
                messages.error(request, _("标签名称无效。"))
                return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
            _delete_tag(profile, name)
            _log_event(request, "front_ab_tag_delete", username=u.username, guid=profile.guid, tag=name)
            messages.success(request, _("标签已删除。"))
            return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")

        if action == "add_peer":
            peer_data = _peer_form_payload(request.POST)
            if peer_data is None:
                messages.error(request, _("设备信息格式无效或超过长度限制。"))
                return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
            rid = peer_data["rid"]
            with transaction.atomic():
                AddressBookProfile.objects.select_for_update().get(pk=profile.pk)
                peer = RemotePeer.objects.filter(
                    profile=profile,
                    rid=rid,
                ).first()
                if (
                    not peer
                    and RemotePeer.objects.filter(
                        profile=profile,
                    ).count()
                    >= 10_000
                ):
                    messages.error(request, _("地址簿设备数量已达到上限。"))
                    return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
                resolved_tags = _resolve_profile_tags(
                    profile,
                    peer_data["tags"],
                )
                if resolved_tags is None:
                    messages.error(request, _("地址簿标签数量已达到上限。"))
                    return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
                if peer:
                    peer.alias = peer_data["alias"] or peer.alias
                    peer.note = peer_data["note"]
                    if not is_personal and peer_data["password"]:
                        peer.password = peer_data["password"]
                    peer.save()
                    event = "front_ab_peer_update"
                    success_message = _("设备已更新。")
                else:
                    peer = RemotePeer.objects.create(
                        profile=profile,
                        rid=rid,
                        username="",
                        hostname="",
                        alias=peer_data["alias"] or rid,
                        platform="",
                        rhash="",
                        note=peer_data["note"],
                        password=("" if is_personal else peer_data["password"]),
                        device_group_name="",
                        login_name="",
                        same_server=False,
                    )
                    event = "front_ab_peer_add"
                    success_message = _("设备已新增。")
                peer.tags.set(resolved_tags)
            _log_event(request, event, username=u.username, guid=profile.guid, rid=rid)
            messages.success(request, success_message)
            return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")

        if action == "update_peer":
            peer_data = _peer_form_payload(request.POST)
            if peer_data is None:
                messages.error(request, _("设备信息格式无效或超过长度限制。"))
                return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
            rid = peer_data["rid"]
            with transaction.atomic():
                AddressBookProfile.objects.select_for_update().get(pk=profile.pk)
                peer = (
                    RemotePeer.objects.select_for_update()
                    .filter(
                        profile=profile,
                        rid=rid,
                    )
                    .first()
                )
                if not peer:
                    messages.error(request, _("设备不存在。"))
                    return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
                resolved_tags = _resolve_profile_tags(
                    profile,
                    peer_data["tags"],
                )
                if resolved_tags is None:
                    messages.error(request, _("地址簿标签数量已达到上限。"))
                    return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
                peer.alias = peer_data["alias"] or peer.alias
                peer.note = peer_data["note"]
                if not is_personal and peer_data["password"]:
                    peer.password = peer_data["password"]
                peer.save()
                peer.tags.set(resolved_tags)
            _log_event(request, "front_ab_peer_update", username=u.username, guid=profile.guid, rid=rid)
            messages.success(request, _("设备已更新。"))
            return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")

        if action == "delete_peer":
            rid = _valid_peer_id(request.POST.get("rid", ""))
            if rid is None:
                messages.error(request, _("设备 ID 格式无效。"))
                return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")
            RemotePeer.objects.filter(profile=profile, rid=rid).delete()
            _log_event(request, "front_ab_peer_delete", username=u.username, guid=profile.guid, rid=rid)
            messages.success(request, _("设备已删除。"))
            return HttpResponseRedirect(f"/api/ab_book?guid={profile.guid}")

    peers = list(
        RemotePeer.objects.filter(profile=profile).prefetch_related(
            Prefetch(
                "tags",
                queryset=RemoteTag.objects.order_by("tag_name"),
                to_attr="ordered_tags",
            )
        )
    )
    for peer in peers:
        peer.tag_names = _peer_tag_text(peer)
    peers.sort(key=lambda x: x.rid)

    return render(
        request,
        "ab_book.html",
        {
            "u": u,
            "profile": profile,
            "owner": owner,
            "peers": peers,
            "can_edit": can_edit,
            "is_personal": is_personal,
            "rule_label": _rule_label(rule) if rule else _("无权限"),
            "nav_active": "ab_books",
        },
    )


@login_required(login_url="/api/user_action?action=login")
def ab_book_export(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect("/api/user_action?action=login")
    guid = request.GET.get("guid", "")
    kind = str(request.GET.get("kind", "peers")).lower()
    export_format = str(request.GET.get("format", "csv")).lower()
    profile, owner, _rule = _get_profile_access_web(u, guid)
    if not profile:
        return HttpResponseRedirect("/api/ab_books")
    if not owner and not u.is_admin:
        return HttpResponseRedirect("/api/ab_books")

    filename_stamp = _filename_stamp()
    if kind == "tags":
        rows = list(RemoteTag.objects.filter(profile=profile))
        headers = [_("标签名称"), _("颜色")]
        if export_format in ("xls", "xlsx"):
            response = xlsx_response(
                f"ab_tags_{filename_stamp}.xlsx",
                _("标签列表"),
                headers,
                [[tag.tag_name, tag.tag_color] for tag in rows],
            )
            _log_event(request, "front_ab_book_export", username=u.username, guid=profile.guid, kind="tags")
            return response
        output = StringIO()
        writer = safe_csv_writer(output)
        writer.writerow(headers)
        for tag in rows:
            writer.writerow([tag.tag_name, tag.tag_color])
        response = HttpResponse(output.getvalue(), content_type="text/csv; charset=utf-8")
        response["Content-Disposition"] = f"attachment; filename=ab_tags_{filename_stamp}.csv"
        _log_event(request, "front_ab_book_export", username=u.username, guid=profile.guid, kind="tags")
        return response

    rows = list(
        RemotePeer.objects.filter(profile=profile).prefetch_related(
            Prefetch(
                "tags",
                queryset=RemoteTag.objects.order_by("tag_name"),
                to_attr="ordered_tags",
            )
        )
    )
    # Portable exports intentionally omit connection credentials. They remain
    # available only through authenticated, access-scoped runtime APIs.
    headers = [_("设备ID"), _("别名"), _("备注"), _("标签")]
    if export_format in ("xls", "xlsx"):
        response = xlsx_response(
            f"ab_peers_{filename_stamp}.xlsx",
            _("设备列表"),
            headers,
            [
                [
                    peer.rid,
                    peer.alias,
                    peer.note or "",
                    _peer_tag_text(peer),
                ]
                for peer in rows
            ],
        )
        _log_event(request, "front_ab_book_export", username=u.username, guid=profile.guid, kind="peers")
        return response

    output = StringIO()
    writer = safe_csv_writer(output)
    writer.writerow(headers)
    for peer in rows:
        writer.writerow(
            [
                peer.rid,
                peer.alias,
                peer.note or "",
                _peer_tag_text(peer),
            ]
        )
    response = HttpResponse(output.getvalue(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f"attachment; filename=ab_peers_{filename_stamp}.csv"
    _log_event(request, "front_ab_book_export", username=u.username, guid=profile.guid, kind="peers")
    return response


@login_required(login_url="/api/user_action?action=login")
def tag_manage(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect("/api/user_action?action=login")

    filter_q = str(request.GET.get("q", "")).strip()
    profiles_qs = _ab_accessible_profiles(u, None).select_related("owner")
    profiles = list(profiles_qs)
    profile_map = {p.guid: p for p in profiles}
    create_profiles = []
    for profile in profiles:
        access_rule = 3 if (u.is_admin or str(profile.owner_id) == str(u.id)) else _get_rule_access(profile, u)
        if _can_write_rule(access_rule):
            create_profiles.append(profile)

    if request.method == "POST":
        action = request.POST.get("action", "")
        profile_guid = str(request.POST.get("profile_guid", "")).strip()
        target_profile = profile_map.get(profile_guid)
        if not target_profile:
            messages.error(request, _("地址簿不存在。"))
            return HttpResponseRedirect("/api/tag_manage")
        access_rule = (
            3 if (u.is_admin or str(target_profile.owner_id) == str(u.id)) else _get_rule_access(target_profile, u)
        )
        if not _can_write_rule(access_rule):
            messages.error(request, _("无权限操作该地址簿。"))
            return HttpResponseRedirect("/api/tag_manage")

        if action == "add_tag":
            name = _valid_tag_name(request.POST.get("name", ""))
            color = normalize_tag_color(request.POST.get("color", ""))
            if name is None or color is None:
                messages.error(request, _("标签名称或颜色格式无效。"))
                return HttpResponseRedirect("/api/tag_manage")
            if not _upsert_tag(target_profile, name, color):
                messages.error(request, _("地址簿标签数量已达到上限。"))
                return HttpResponseRedirect("/api/tag_manage")
            _log_event(request, "front_tag_add", username=u.username, guid=profile_guid, tag=name)
            messages.success(request, _("标签已更新。"))
            return HttpResponseRedirect("/api/tag_manage")

        if action == "update_tag":
            name = _valid_tag_name(request.POST.get("name", ""))
            color = normalize_tag_color(request.POST.get("color", ""))
            if name is None or color is None:
                messages.error(request, _("标签名称或颜色格式无效。"))
                return HttpResponseRedirect("/api/tag_manage")
            if not _upsert_tag(target_profile, name, color):
                messages.error(request, _("地址簿标签数量已达到上限。"))
                return HttpResponseRedirect("/api/tag_manage")
            _log_event(request, "front_tag_update", username=u.username, guid=profile_guid, tag=name)
            messages.success(request, _("标签颜色已更新。"))
            return HttpResponseRedirect("/api/tag_manage")

        if action == "rename_tag":
            old = _valid_tag_name(request.POST.get("old", ""))
            new = _valid_tag_name(request.POST.get("new", ""))
            if old is None or new is None:
                messages.error(request, _("标签名称无效。"))
                return HttpResponseRedirect("/api/tag_manage")
            if old == new:
                messages.success(request, _("标签已重命名。"))
                return HttpResponseRedirect("/api/tag_manage")
            if not _rename_tag(target_profile, old, new):
                messages.error(request, _("标签不存在。"))
                return HttpResponseRedirect("/api/tag_manage")
            _log_event(request, "front_tag_rename", username=u.username, guid=profile_guid, old=old, new=new)
            messages.success(request, _("标签已重命名。"))
            return HttpResponseRedirect("/api/tag_manage")

        if action == "delete_tag":
            name = _valid_tag_name(request.POST.get("name", ""))
            if name is None:
                messages.error(request, _("标签名称无效。"))
                return HttpResponseRedirect("/api/tag_manage")
            _delete_tag(target_profile, name)
            _log_event(request, "front_tag_delete", username=u.username, guid=profile_guid, tag=name)
            messages.success(request, _("标签已删除。"))
            return HttpResponseRedirect("/api/tag_manage")

    tag_rows = RemoteTag.objects.filter(
        profile__guid__in=list(profile_map.keys()),
    ).select_related("profile__owner")
    if filter_q:
        tag_rows = tag_rows.filter(Q(tag_name__icontains=filter_q) | Q(profile__guid__icontains=filter_q))
    tags = []
    for tag in tag_rows.order_by("tag_name"):
        profile = tag.profile
        if not profile:
            continue
        access_rule = 3 if (u.is_admin or str(profile.owner_id) == str(u.id)) else _get_rule_access(profile, u)
        tags.append(
            {
                "name": tag.tag_name,
                "color": tag.tag_color,
                "css_color": tag_color_css(tag.tag_color),
                "profile_guid": profile.guid,
                "profile_name": profile.name,
                "owner": profile.owner.username if profile.owner else "-",
                "can_edit": _can_write_rule(access_rule),
            }
        )

    _log_event(request, "front_tag_manage_view", username=u.username, total=len(tags))
    return render(
        request,
        "tag_manage.html",
        {
            "u": u,
            "profiles": create_profiles,
            "tags": tags,
            "filter_q": filter_q,
            "nav_active": "tag_manage",
        },
    )


@login_required(login_url="/api/user_action?action=login")
def tag_export(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect("/api/user_action?action=login")
    export_format = str(request.GET.get("format", "csv")).lower()
    filter_q = str(request.GET.get("q", "")).strip()
    profiles = list(_ab_accessible_profiles(u, None).select_related("owner"))
    profile_map = {p.guid: p for p in profiles}
    tags_qs = RemoteTag.objects.filter(
        profile__guid__in=list(profile_map.keys()),
    ).select_related("profile__owner")
    if filter_q:
        tags_qs = tags_qs.filter(Q(tag_name__icontains=filter_q) | Q(profile__guid__icontains=filter_q))
    rows = list(tags_qs.order_by("tag_name"))
    filename_stamp = _filename_stamp()
    headers = [_("标签名称"), _("颜色"), _("地址簿"), _("地址簿 GUID"), _("所属用户")]

    if export_format in ("xls", "xlsx"):
        xlsx_rows = []
        for tag in rows:
            profile = tag.profile
            xlsx_rows.append(
                [
                    tag.tag_name,
                    tag.tag_color,
                    profile.name if profile else "",
                    profile.guid if profile else "",
                    profile.owner.username if profile and profile.owner else "-",
                ]
            )
        response = xlsx_response(f"ab_tags_{filename_stamp}.xlsx", _("标签列表"), headers, xlsx_rows)
        _log_event(request, "front_tag_export", username=u.username, count=len(rows))
        return response

    output = StringIO()
    writer = safe_csv_writer(output)
    writer.writerow(headers)
    for tag in rows:
        profile = tag.profile
        writer.writerow(
            [
                tag.tag_name,
                tag.tag_color,
                profile.name if profile else "",
                profile.guid if profile else "",
                profile.owner.username if profile and profile.owner else "-",
            ]
        )
    response = HttpResponse(output.getvalue(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f"attachment; filename=ab_tags_{filename_stamp}.csv"
    _log_event(request, "front_tag_export", username=u.username, count=len(rows))
    return response


@login_required(login_url="/api/user_action?action=login")
def ab_dashboard(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect("/api/user_action?action=login")

    profiles_qs = _ab_accessible_profiles(u, None).select_related("owner")
    profiles = list(profiles_qs)
    allowed_guids = {p.guid for p in profiles}

    total_books = len(profiles)
    total_peers = 0
    total_tags = 0
    profile_stats = []
    for profile in profiles:
        peers_count = profile.peers.count()
        tags_count = profile.tags.count()
        total_peers += peers_count
        total_tags += tags_count
        profile_stats.append(
            {
                "name": profile.name,
                "guid": profile.guid,
                "owner": profile.owner.username if profile.owner else "-",
                "peers": peers_count,
                "tags": tags_count,
            }
        )
    profile_stats.sort(key=lambda x: x["peers"], reverse=True)
    top_profiles = profile_stats[:6]
    max_peers = max([p["peers"] for p in top_profiles], default=1)
    for p in top_profiles:
        p["peers_pct"] = int((p["peers"] / max_peers) * 100) if max_peers else 0

    shares_qs = AddressBookShare.objects.exclude(profile__guid__startswith="personal-")
    rules_qs = AddressBookRule.objects.exclude(profile__guid__startswith="personal-")
    if not u.is_admin:
        shares_qs = shares_qs.filter(Q(profile__guid__in=allowed_guids))
        rules_qs = rules_qs.filter(Q(profile__guid__in=allowed_guids))
    total_shares = shares_qs.count()
    total_rules = rules_qs.count()

    rule_stats = _summarize_rules(_collect_global_rules(None, allowed_guids if not u.is_admin else None))

    _log_event(request, "front_ab_dashboard_view", username=u.username, total=total_books)
    return render(
        request,
        "ab_dashboard.html",
        {
            "u": u,
            "total_books": total_books,
            "total_peers": total_peers,
            "total_tags": total_tags,
            "total_shares": total_shares,
            "total_rules": total_rules,
            "top_profiles": top_profiles,
            "rule_stats": rule_stats,
            "nav_active": "ab_dashboard",
        },
    )


@login_required(login_url="/api/user_action?action=login")
def ab_rules(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect("/api/user_action?action=login")
    if not u.is_admin:
        _log_event(request, "front_ab_rules_denied", level="warning", username=u.username)
        return HttpResponseRedirect("/api/home")

    filter_q = str(request.GET.get("q", "")).strip()

    if request.method == "POST":
        action = request.POST.get("action", "")
        redirect_params = {}
        if filter_q:
            redirect_params["q"] = filter_q
        redirect_url = "/api/ab_rules"
        if redirect_params:
            redirect_url = f"{redirect_url}?{urlencode(redirect_params)}"

        if action in ("update_rule", "delete_rule"):
            rule_value = _parse_rule(request.POST.get("rule", 1))
            rule_guid = request.POST.get("rule_guid", "")
            if not rule_guid:
                messages.error(request, _("规则不存在。"))
                return HttpResponseRedirect(redirect_url)
            ok, msg = _apply_rule_change(request, u, action, rule_guid, rule_value)
            if ok:
                messages.success(request, msg)
            else:
                messages.error(request, msg)
            return HttpResponseRedirect(redirect_url)

        if action in ("bulk_update", "bulk_delete"):
            selected = request.POST.getlist("selected")
            if not selected:
                messages.error(request, _("请选择至少一条规则。"))
                return HttpResponseRedirect(redirect_url)
            rule_value = _parse_rule(request.POST.get("rule", 1))
            success = 0
            failed = 0
            for guid in selected:
                if action == "bulk_delete":
                    ok, _msg = _apply_rule_change(request, u, "delete_rule", guid, rule_value, {"bulk": True})
                else:
                    ok, _msg = _apply_rule_change(request, u, "update_rule", guid, rule_value, {"bulk": True})
                if ok:
                    success += 1
                else:
                    failed += 1
            if action == "bulk_delete":
                messages.success(request, _("已批量删除 %(count)s 条规则。") % {"count": success})
            else:
                messages.success(request, _("已批量更新 %(count)s 条规则。") % {"count": success})
            if failed:
                messages.warning(request, _("有 %(count)s 条规则未能处理。") % {"count": failed})
            return HttpResponseRedirect(redirect_url)

    try:
        rules = _collect_global_rules(filter_q)
        rule_stats = _summarize_rules(rules)
        paginator = Paginator(rules, 20)
        page_number = request.GET.get("page")
        page_obj = paginator.get_page(page_number)
    except Exception as exc:  # noqa: BLE001 - page-level boundary redirects with a stable error
        logger.exception("ab_rules view failed: %s", exc)
        messages.error(request, _("规则总览加载失败，请检查数据库迁移与日志输出。"))
        return HttpResponseRedirect("/api/ab_manage")

    _log_event(request, "front_ab_rules_view", username=u.username, total=page_obj.paginator.count)
    return render(
        request,
        "ab_rules.html",
        {
            "u": u,
            "page_obj": page_obj,
            "rule_stats": rule_stats,
            "filter_q": filter_q,
            "rule_choices": [
                (1, _("只读")),
                (2, _("读写")),
                (3, _("完全控制")),
            ],
            "nav_active": "ab_rules",
        },
    )


@login_required(login_url="/api/user_action?action=login")
def ab_rules_export(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect("/api/user_action?action=login")
    if not u.is_admin:
        _log_event(request, "front_ab_rules_export_denied", level="warning", username=u.username)
        return HttpResponseRedirect("/api/home")

    export_format = str(request.GET.get("format", "csv")).lower()
    filter_q = str(request.GET.get("q", "")).strip()
    rules = _collect_global_rules(filter_q)
    filename_stamp = _filename_stamp()

    if export_format in ("xls", "xlsx"):
        headers = [_("地址簿"), _("地址簿 GUID"), _("所属用户"), _("类型"), _("目标"), _("权限")]
        return xlsx_response(
            f"ab_rules_{filename_stamp}.xlsx",
            _("地址簿规则"),
            headers,
            [
                [
                    entry.get("profile_name", ""),
                    entry.get("profile_guid", ""),
                    entry.get("owner", ""),
                    entry.get("target_type", ""),
                    entry.get("target_name", ""),
                    entry.get("rule_label", ""),
                ]
                for entry in rules
            ],
        )

    output = StringIO()
    writer = safe_csv_writer(output)
    writer.writerow([_("地址簿"), _("地址簿 GUID"), _("所属用户"), _("类型"), _("目标"), _("权限")])
    for entry in rules:
        writer.writerow(
            [
                entry.get("profile_name", ""),
                entry.get("profile_guid", ""),
                entry.get("owner", ""),
                entry.get("target_type", ""),
                entry.get("target_name", ""),
                entry.get("rule_label", ""),
            ]
        )
    response = HttpResponse(output.getvalue(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f"attachment; filename=ab_rules_{filename_stamp}.csv"
    return response


@login_required(login_url="/api/user_action?action=login")
def ab_shares_export(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect("/api/user_action?action=login")
    export_format = str(request.GET.get("format", "csv")).lower()
    filter_q = str(request.GET.get("q", "")).strip()

    shares = AddressBookShare.objects.select_related("profile", "user", "profile__owner").exclude(
        profile__guid__startswith="personal-"
    )
    if not u.is_admin:
        shares = shares.filter(Q(profile__owner=u))
    if filter_q:
        shares = shares.filter(
            Q(profile__name__icontains=filter_q)
            | Q(profile__guid__icontains=filter_q)
            | Q(profile__owner__username__icontains=filter_q)
            | Q(user__username__icontains=filter_q)
        )
    rows = list(shares.order_by("profile__name"))
    filename_stamp = _filename_stamp()

    headers = [_("地址簿"), _("地址簿 GUID"), _("所属用户"), _("共享给用户"), _("权限"), _("创建时间")]
    if export_format in ("xls", "xlsx"):
        xlsx_rows = []
        for share in rows:
            profile = share.profile
            xlsx_rows.append(
                [
                    profile.name if profile else "",
                    profile.guid if profile else "",
                    profile.owner.username if profile and profile.owner else "-",
                    share.user.username if share.user else "-",
                    _rule_label(share.rule),
                    share.created_at.strftime("%Y-%m-%d %H:%M") if share.created_at else "",
                ]
            )
        response = xlsx_response(f"ab_shares_{filename_stamp}.xlsx", _("地址簿共享列表"), headers, xlsx_rows)
        _log_event(request, "front_ab_shares_export", username=u.username, count=len(rows))
        return response

    output = StringIO()
    writer = safe_csv_writer(output)
    writer.writerow(headers)
    for share in rows:
        profile = share.profile
        writer.writerow(
            [
                profile.name if profile else "",
                profile.guid if profile else "",
                profile.owner.username if profile and profile.owner else "-",
                share.user.username if share.user else "-",
                _rule_label(share.rule),
                share.created_at.strftime("%Y-%m-%d %H:%M") if share.created_at else "",
            ]
        )
    response = HttpResponse(output.getvalue(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f"attachment; filename=ab_shares_{filename_stamp}.csv"
    _log_event(request, "front_ab_shares_export", username=u.username, count=len(rows))
    return response


@login_required(login_url="/api/user_action?action=login")
def ab_audit(request):
    u = _get_current_user(request)
    if not u:
        return HttpResponseRedirect("/api/user_action?action=login")
    if not u.is_admin:
        _log_event(request, "front_ab_audit_denied", level="warning", username=u.username)
        return HttpResponseRedirect("/api/home")

    filter_q = str(request.GET.get("q", "")).strip()
    audits = AddressBookRuleAudit.objects.select_related("profile", "actor").order_by("-created_at")
    if filter_q:
        audits = audits.filter(
            Q(profile__name__icontains=filter_q)
            | Q(profile__guid__icontains=filter_q)
            | Q(actor__username__icontains=filter_q)
            | Q(target_name__icontains=filter_q)
            | Q(action__icontains=filter_q)
        )
    paginator = Paginator(audits, 20)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    _log_event(request, "front_ab_audit_view", username=u.username, total=page_obj.paginator.count)

    action_labels = {
        "share_add": _("用户共享新增"),
        "share_update": _("用户共享更新"),
        "share_delete": _("用户共享删除"),
        "rule_add": _("规则新增"),
        "rule_update": _("规则更新"),
        "rule_delete": _("规则删除"),
    }

    entries = []
    for audit in page_obj:
        entries.append(
            {
                "created_at": audit.created_at,
                "profile_name": audit.profile.name if audit.profile else "-",
                "profile_guid": audit.profile.guid if audit.profile else "-",
                "actor": audit.actor.username if audit.actor else "-",
                "action": action_labels.get(audit.action, audit.action),
                "target_type": _rule_target_label(audit.target_type),
                "target_name": audit.target_name or "-",
                "rule_label": _rule_label(audit.rule),
                "details": (json.dumps(audit.details, ensure_ascii=False) if audit.details else ""),
            }
        )

    return render(
        request,
        "ab_audit.html",
        {
            "u": u,
            "page_obj": page_obj,
            "entries": entries,
            "filter_q": filter_q,
            "nav_active": "ab_audit",
        },
    )


def _peer_alias_map(peer_ids):
    aliases = {}
    for peer in RemotePeer.objects.filter(rid__in=peer_ids).order_by("pk"):
        aliases.setdefault(peer.rid, peer.alias or _("UNKNOWN"))
    return aliases


@login_required(login_url="/api/user_action?action=login")
def conn_log(request):
    if not request.user.is_admin:
        _log_event(request, "front_conn_log_denied", level="warning", username=request.user.username)
        return HttpResponseRedirect("/api/home")
    paginator = Paginator(
        ConnLog.objects.select_related("reporter").order_by("-conn_start", "-id"),
        20,
    )
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    logs = list(page_obj.object_list)
    aliases = _peer_alias_map({peer_id for log in logs for peer_id in (log.rid, log.from_id) if peer_id})
    entries = []
    for log in logs:
        item = model_to_dict(log)
        item["alias"] = aliases.get(log.rid, _("UNKNOWN"))
        item["from_alias"] = aliases.get(log.from_id, _("UNKNOWN"))
        if log.conn_start and log.conn_end:
            duration = max(0, round((log.conn_end - log.conn_start).total_seconds()))
            minutes, seconds = divmod(duration, 60)
            hours, minutes = divmod(minutes, 60)
            item["duration"] = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        else:
            item["duration"] = "-"
        entries.append(item)
    page_obj.object_list = entries
    _log_event(request, "front_conn_log_view", username=request.user.username, page=page_number)
    return render(
        request,
        "show_conn_log.html",
        {"page_obj": page_obj, "u": request.user, "nav_active": "conn_log"},
    )


@login_required(login_url="/api/user_action?action=login")
def file_log(request):
    if not request.user.is_admin:
        _log_event(request, "front_file_log_denied", level="warning", username=request.user.username)
        return HttpResponseRedirect("/api/home")
    paginator = Paginator(
        FileLog.objects.select_related("reporter").order_by("-logged_at", "-id"),
        20,
    )
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    logs = list(page_obj.object_list)
    aliases = _peer_alias_map({peer_id for log in logs for peer_id in (log.remote_id, log.user_id) if peer_id})
    entries = []
    for log in logs:
        item = model_to_dict(log)
        item["remote_alias"] = aliases.get(log.remote_id, _("UNKNOWN"))
        item["user_alias"] = aliases.get(log.user_id, _("UNKNOWN"))
        item["filesize_display"] = format_bytes(log.filesize)
        entries.append(item)
    page_obj.object_list = entries
    _log_event(request, "front_file_log_view", username=request.user.username, page=page_number)
    return render(
        request,
        "show_file_log.html",
        {"page_obj": page_obj, "u": request.user, "nav_active": "file_log"},
    )
