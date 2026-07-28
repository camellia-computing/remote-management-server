from webui2 import views
from django.urls import re_path as url

urlpatterns = [
    url(r"^status$", views.status),
    url(r"^$", views.index),
]
