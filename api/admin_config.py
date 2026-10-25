from django.contrib.admin.apps import AdminConfig


class CamelliaAdminConfig(AdminConfig):
    default_site = "api.admin_site.CamelliaAdminSite"
