from django.urls import re_path as url
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from api import views_api, views_front
from api.response_security import credential_response


def stateless_api(view, *methods):
    """Declare the method contract for APIs that never authenticate by cookie."""
    return csrf_exempt(require_http_methods(methods)(view))


def browser_view(view, *methods):
    """Declare the method contract while retaining session and CSRF protection."""
    return require_http_methods(methods)(view)


def credential_stateless_api(view, *methods):
    return credential_response(stateless_api(view, *methods))


def credential_browser_view(view, *methods):
    return credential_response(browser_view(view, *methods))


urlpatterns = [
    url(r"^login-options$", stateless_api(views_api.login_options, "GET")),
    url(r"^oidc/auth$", credential_stateless_api(views_api.oidc_auth, "POST")),
    url(r"^oidc/auth-query$", credential_stateless_api(views_api.oidc_auth_query, "POST")),
    url(r"^oidc/callback$", credential_stateless_api(views_api.oidc_callback, "GET")),
    url(r"^login$", credential_stateless_api(views_api.login, "POST")),
    url(r"^logout$", credential_stateless_api(views_api.logout, "POST")),
    url(r"^currentUser$", credential_stateless_api(views_api.currentUser, "POST")),
    url(r"^sysinfo_ver$", stateless_api(views_api.sysinfo_ver, "POST")),
    url(r"^sysinfo$", stateless_api(views_api.sysinfo, "POST")),
    url(r"^heartbeat$", credential_stateless_api(views_api.heartbeat, "POST")),
    url(r"^record$", stateless_api(views_api.record, "POST")),
    url(r"^devices/cli$", stateless_api(views_api.devices_cli, "POST")),
    url(r"^devices/proof-challenge$", stateless_api(views_api.devices_proof_challenge, "POST")),
    url(r"^devices/deploy$", stateless_api(views_api.devices_deploy, "POST")),
    url(r"^devices/verify-deployment$", stateless_api(views_api.devices_verify_deployment, "POST")),
    url(
        r"^audit/(?P<typ>conn/active|conn|file|alarm)$",
        stateless_api(views_api.audit_with_type, "GET", "POST"),
    ),
    url(r"^audit$", stateless_api(views_api.audit_root, "PUT")),
    url(r"^ab/settings$", stateless_api(views_api.ab_settings, "POST")),
    url(r"^ab/personal$", stateless_api(views_api.ab_personal, "POST")),
    url(r"^ab/shared/profiles$", credential_stateless_api(views_api.ab_shared_profiles, "POST")),
    url(r"^ab/shared/credential$", credential_stateless_api(views_api.ab_shared_credential, "POST")),
    url(r"^ab/shared/add$", stateless_api(views_api.ab_shared_add, "POST")),
    url(r"^ab/shared/update/profile$", stateless_api(views_api.ab_shared_update_profile, "PUT")),
    url(r"^ab/shared$", stateless_api(views_api.ab_shared_delete, "DELETE")),
    url(r"^ab/peers$", credential_stateless_api(views_api.ab_peers, "POST")),
    url(r"^ab/tags/(?P<guid>[^/]+)$", stateless_api(views_api.ab_tags, "POST")),
    url(r"^ab/peer/add/(?P<guid>[^/]+)$", stateless_api(views_api.ab_peer_add, "POST")),
    url(r"^ab/peer/update/(?P<guid>[^/]+)$", stateless_api(views_api.ab_peer_update, "PUT")),
    url(r"^ab/peer/(?P<guid>[^/]+)$", stateless_api(views_api.ab_peer_delete, "DELETE")),
    url(r"^ab/tag/add/(?P<guid>[^/]+)$", stateless_api(views_api.ab_tag_add, "POST")),
    url(r"^ab/tag/rename/(?P<guid>[^/]+)$", stateless_api(views_api.ab_tag_rename, "PUT")),
    url(r"^ab/tag/update/(?P<guid>[^/]+)$", stateless_api(views_api.ab_tag_update, "PUT")),
    url(r"^ab/tag/(?P<guid>[^/]+)$", stateless_api(views_api.ab_tag_delete, "DELETE")),
    url(r"^ab/rules$", stateless_api(views_api.ab_rules, "GET", "DELETE")),
    url(r"^ab/rule$", stateless_api(views_api.ab_rule, "POST", "PATCH")),
    url(r"^device-group/accessible$", stateless_api(views_api.device_group_accessible, "GET")),
    url(r"^device-groups$", stateless_api(views_api.device_groups, "GET", "POST")),
    url(
        r"^device-groups/(?P<guid>[^/]+)/devices$",
        stateless_api(views_api.device_group_remove_devices, "DELETE"),
    ),
    url(
        r"^device-groups/(?P<guid>[^/]+)$",
        stateless_api(views_api.device_group_detail, "POST", "PATCH", "DELETE"),
    ),
    url(r"^devices$", stateless_api(views_api.devices, "GET")),
    url(
        r"^devices/(?P<guid>[^/]+)/disable$",
        stateless_api(lambda request, guid: views_api.device_status(request, guid, "disable"), "POST"),
    ),
    url(
        r"^devices/(?P<guid>[^/]+)/enable$",
        stateless_api(lambda request, guid: views_api.device_status(request, guid, "enable"), "POST"),
    ),
    url(
        r"^devices/(?P<guid>[^/]+)/approve-recovery$",
        stateless_api(views_api.device_approve_recovery, "POST"),
    ),
    url(r"^devices/(?P<guid>[^/]+)/assign$", stateless_api(views_api.device_assign, "POST")),
    url(r"^devices/(?P<guid>[^/]+)$", stateless_api(views_api.device_delete, "DELETE")),
    url(r"^users$", stateless_api(views_api.users, "GET", "POST")),
    url(r"^users/force-logout$", stateless_api(views_api.users_force_logout, "POST")),
    url(
        r"^users/(?P<guid>[^/]+)/disable$",
        stateless_api(lambda request, guid: views_api.user_status(request, guid, "disable"), "POST"),
    ),
    url(
        r"^users/(?P<guid>[^/]+)/enable$",
        stateless_api(lambda request, guid: views_api.user_status(request, guid, "enable"), "POST"),
    ),
    url(r"^users/(?P<guid>[^/]+)$", stateless_api(views_api.user_delete, "DELETE")),
    url(r"^strategies$", stateless_api(views_api.strategies, "GET", "POST")),
    url(r"^strategies/assign$", stateless_api(views_api.strategy_assign, "POST")),
    url(r"^strategies/(?P<guid>[^/]+)/status$", stateless_api(views_api.strategy_status, "PUT")),
    url(
        r"^strategies/(?P<guid>[^/]+)$",
        stateless_api(views_api.strategy_detail, "GET", "PATCH", "DELETE"),
    ),
    url(r"^peers$", stateless_api(views_api.peers, "GET")),
    url(r"^user_action$", browser_view(views_front.user_action, "GET", "POST")),
    url(r"^home$", browser_view(views_front.home, "GET")),
    url(r"^work$", browser_view(views_front.work, "GET")),
    url(r"^ab_dashboard$", browser_view(views_front.ab_dashboard, "GET")),
    url(r"^ab_books$", browser_view(views_front.ab_books, "GET", "POST")),
    url(r"^ab_book$", browser_view(views_front.ab_book, "GET", "POST")),
    url(r"^ab_books_export$", browser_view(views_front.ab_books_export, "GET")),
    url(r"^ab_book_export$", browser_view(views_front.ab_book_export, "GET")),
    url(r"^tag_manage$", browser_view(views_front.tag_manage, "GET", "POST")),
    url(r"^tag_export$", browser_view(views_front.tag_export, "GET")),
    url(r"^ab_manage$", browser_view(views_front.ab_manage, "GET", "POST")),
    url(r"^ab_rules_export$", browser_view(views_front.ab_rules_export, "GET")),
    url(r"^ab_shares_export$", browser_view(views_front.ab_shares_export, "GET")),
    url(r"^ab_rules$", browser_view(views_front.ab_rules, "GET", "POST")),
    url(r"^ab_audit$", browser_view(views_front.ab_audit, "GET")),
    url(r"^down_peers$", browser_view(views_front.down_peers, "GET")),
    url(r"^share$", credential_browser_view(views_front.share, "GET", "POST")),
    url(
        r"^share/(?P<share_token>[A-Za-z0-9_-]{32,128})$",
        credential_browser_view(views_front.share, "GET", "POST"),
    ),
    url(r"^conn_log$", browser_view(views_front.conn_log, "GET")),
    url(r"^file_log$", browser_view(views_front.file_log, "GET")),
]
