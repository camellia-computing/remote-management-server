from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class ApiConfig(AppConfig):
    name = "api"
    verbose_name = _("Camellia 管理")

    def ready(self):
        from api.signals import connect_api_signals

        connect_api_signals()
