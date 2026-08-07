from django.contrib import admin
from django.urls import include, path, re_path
from django.views.decorators.http import require_GET

from api import views_api
from api.response_security import sensitive_response
from api.views import index

urlpatterns = [
    path("i18n/", include("django.conf.urls.i18n")),
    path("admin/", admin.site.urls),
    re_path(r"^$", sensitive_response(require_GET(index))),
    path("health/live", require_GET(views_api.health_live)),
    path("health/ready", require_GET(views_api.health_ready)),
    re_path(r"^api/", include("api.urls")),
    re_path(r"^webui2/", include("webui2.urls")),
]
