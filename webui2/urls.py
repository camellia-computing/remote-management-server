from django.urls import re_path as url
from django.views.decorators.http import require_GET

from webui2 import views

urlpatterns = [
    url(r"^status$", require_GET(views.status)),
    url(r"^$", require_GET(views.index)),
]
