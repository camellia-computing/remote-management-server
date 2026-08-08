from django.urls import re_path as url
from django.views.decorators.http import require_GET

from api.response_security import sensitive_response
from webui2 import views

urlpatterns = [
    url(r"^status$", sensitive_response(require_GET(views.status))),
    url(r"^$", sensitive_response(require_GET(views.index))),
]
