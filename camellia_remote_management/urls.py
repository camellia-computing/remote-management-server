"""camellia_remote_management URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import include, path, re_path
from django.views.decorators.csrf import csrf_exempt

from api import views_api
from api.views import index

urlpatterns = [
    path("i18n/", include("django.conf.urls.i18n")),
    path("admin/", admin.site.urls),
    re_path(r"^$", index),
    path("health/live", views_api.health_live),
    path("health/ready", views_api.health_ready),
    re_path(r"^api/", include("api.urls")),
    re_path(r"^lic/web/api/plugin-sign$", csrf_exempt(views_api.plugin_sign)),
    re_path(r"^webui2/", include("webui2.urls")),
]
