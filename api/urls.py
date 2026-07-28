from django.urls import re_path as url

from api import views_api, views_front
from django.views.decorators.csrf import csrf_exempt

urlpatterns = [
    url(r"^login-options$", csrf_exempt(views_api.login_options)),
    url(r"^oidc/auth$", csrf_exempt(views_api.oidc_auth)),
    url(r"^oidc/auth-query$", csrf_exempt(views_api.oidc_auth_query)),
    url(r"^oidc/callback$", csrf_exempt(views_api.oidc_callback)),
    url(r"^login$", csrf_exempt(views_api.login)),
    url(r"^logout$", csrf_exempt(views_api.logout)),
    url(r"^currentUser$", csrf_exempt(views_api.currentUser)),
    url(r"^sysinfo_ver$", csrf_exempt(views_api.sysinfo_ver)),
    url(r"^sysinfo$", csrf_exempt(views_api.sysinfo)),
    url(r"^heartbeat$", csrf_exempt(views_api.heartbeat)),
    url(r"^record$", csrf_exempt(views_api.record)),
    url(r"^devices/cli$", csrf_exempt(views_api.devices_cli)),
    url(r"^devices/deploy$", csrf_exempt(views_api.devices_deploy)),
    url(r"^devices/verify-deployment$", csrf_exempt(views_api.devices_verify_deployment)),
    url(r"^audit/(?P<typ>conn/active|conn|file|alarm)$", csrf_exempt(views_api.audit_with_type)),
    url(r"^audit$", csrf_exempt(views_api.audit_root)),
    url(r"^ab/settings$", csrf_exempt(views_api.ab_settings)),
    url(r"^ab/personal$", csrf_exempt(views_api.ab_personal)),
    url(r"^ab/shared/profiles$", csrf_exempt(views_api.ab_shared_profiles)),
    url(r"^ab/shared/add$", csrf_exempt(views_api.ab_shared_add)),
    url(r"^ab/shared/update/profile$", csrf_exempt(views_api.ab_shared_update_profile)),
    url(r"^ab/shared$", csrf_exempt(views_api.ab_shared_delete)),
    url(r"^ab/peers$", csrf_exempt(views_api.ab_peers)),
    url(r"^ab/tags/(?P<guid>[^/]+)$", csrf_exempt(views_api.ab_tags)),
    url(r"^ab/peer/add/(?P<guid>[^/]+)$", csrf_exempt(views_api.ab_peer_add)),
    url(r"^ab/peer/update/(?P<guid>[^/]+)$", csrf_exempt(views_api.ab_peer_update)),
    url(r"^ab/peer/(?P<guid>[^/]+)$", csrf_exempt(views_api.ab_peer_delete)),
    url(r"^ab/tag/add/(?P<guid>[^/]+)$", csrf_exempt(views_api.ab_tag_add)),
    url(r"^ab/tag/rename/(?P<guid>[^/]+)$", csrf_exempt(views_api.ab_tag_rename)),
    url(r"^ab/tag/update/(?P<guid>[^/]+)$", csrf_exempt(views_api.ab_tag_update)),
    url(r"^ab/tag/(?P<guid>[^/]+)$", csrf_exempt(views_api.ab_tag_delete)),
    url(r"^ab/rules$", csrf_exempt(views_api.ab_rules)),
    url(r"^ab/rule$", csrf_exempt(views_api.ab_rule)),
    url(r"^device-group/accessible$", csrf_exempt(views_api.device_group_accessible)),
    url(r"^device-groups$", csrf_exempt(views_api.device_groups)),
    url(r"^device-groups/(?P<guid>[^/]+)/devices$", csrf_exempt(views_api.device_group_remove_devices)),
    url(r"^device-groups/(?P<guid>[^/]+)$", csrf_exempt(views_api.device_group_detail)),
    url(r"^devices$", csrf_exempt(views_api.devices)),
    url(
        r"^devices/(?P<guid>[^/]+)/disable$",
        csrf_exempt(lambda request, guid: views_api.device_status(request, guid, "disable")),
    ),
    url(
        r"^devices/(?P<guid>[^/]+)/enable$",
        csrf_exempt(lambda request, guid: views_api.device_status(request, guid, "enable")),
    ),
    url(r"^devices/(?P<guid>[^/]+)/assign$", csrf_exempt(views_api.device_assign)),
    url(r"^devices/(?P<guid>[^/]+)$", csrf_exempt(views_api.device_delete)),
    url(r"^users$", csrf_exempt(views_api.users)),
    url(r"^users/force-logout$", csrf_exempt(views_api.users_force_logout)),
    url(
        r"^users/(?P<guid>[^/]+)/disable$",
        csrf_exempt(lambda request, guid: views_api.user_status(request, guid, "disable")),
    ),
    url(
        r"^users/(?P<guid>[^/]+)/enable$",
        csrf_exempt(lambda request, guid: views_api.user_status(request, guid, "enable")),
    ),
    url(r"^users/(?P<guid>[^/]+)$", csrf_exempt(views_api.user_delete)),
    url(r"^strategies$", csrf_exempt(views_api.strategies)),
    url(r"^strategies/assign$", csrf_exempt(views_api.strategy_assign)),
    url(r"^strategies/(?P<guid>[^/]+)/status$", csrf_exempt(views_api.strategy_status)),
    url(r"^strategies/(?P<guid>[^/]+)$", csrf_exempt(views_api.strategy_detail)),
    url(r"^peers$", csrf_exempt(views_api.peers)),
    # url(r'^register',views.register),
    url(r"^user_action$", views_front.user_action),  # 前端
    url(r"^home$", views_front.home),  # 前端
    url(r"^work$", views_front.work),  # 前端
    url(r"^ab_dashboard$", views_front.ab_dashboard),  # 前端
    url(r"^ab_books$", views_front.ab_books),  # 前端
    url(r"^ab_book$", views_front.ab_book),  # 前端
    url(r"^ab_books_export$", views_front.ab_books_export),  # 前端
    url(r"^ab_book_export$", views_front.ab_book_export),  # 前端
    url(r"^tag_manage$", views_front.tag_manage),  # 前端
    url(r"^tag_export$", views_front.tag_export),  # 前端
    url(r"^ab_manage$", views_front.ab_manage),  # 前端
    url(r"^ab_rules_export$", views_front.ab_rules_export),  # 前端
    url(r"^ab_shares_export$", views_front.ab_shares_export),  # 前端
    url(r"^ab_rules$", views_front.ab_rules),  # 前端
    url(r"^ab_audit$", views_front.ab_audit),  # 前端
    url(r"^down_peers$", views_front.down_peers),  # 前端
    url(r"^share$", views_front.share),  # 前端
    url(r"^share/(?P<share_token>[A-Za-z0-9_-]{32,128})$", views_front.share),
    url(r"^conn_log$", views_front.conn_log),
    url(r"^file_log$", views_front.file_log),
]
