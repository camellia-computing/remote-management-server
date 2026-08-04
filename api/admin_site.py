import logging

from django.contrib.admin import AdminSite
from django.contrib.admin.forms import AdminAuthenticationForm
from django.contrib.auth.decorators import login_not_required
from django.core.exceptions import ValidationError
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache

from api.login_admission import complete_login_success, reserve_login_attempt
from api.request_utils import client_ip
from camellia_remote_management.access_logging import normalized_route, safe_request_id

logger = logging.getLogger(__name__)
_ADMISSION_ATTRIBUTE = "_camellia_admin_login_admission"
_LOCKED_ATTRIBUTE = "_camellia_admin_login_locked"


class AdmissionAdminAuthenticationForm(AdminAuthenticationForm):
    error_messages = {
        **AdminAuthenticationForm.error_messages,
        "locked": _("尝试次数过多，请稍后再试。"),
    }

    def clean(self):
        username = self.cleaned_data.get("username")
        password = self.cleaned_data.get("password")
        if username is not None and password:
            admission = reserve_login_attempt(client_ip(self.request), username)
            if admission is None:
                setattr(self.request, _LOCKED_ATTRIBUTE, True)
                raise ValidationError(self.error_messages["locked"], code="locked")
            setattr(self.request, _ADMISSION_ATTRIBUTE, admission)
        return super().clean()


class CamelliaAdminSite(AdminSite):
    login_form = AdmissionAdminAuthenticationForm

    @method_decorator(never_cache)
    @login_not_required
    def login(self, request, extra_context=None):
        response = super().login(request, extra_context=extra_context)
        if request.method != "POST":
            return response

        route = normalized_route(getattr(request, "resolver_match", None))
        request_id = safe_request_id(request.META)
        if getattr(request, _LOCKED_ATTRIBUTE, False):
            response.status_code = 429
            logger.warning("event=admin_login_locked route=%s request_id=%s", route, request_id)
            return response

        admission = getattr(request, _ADMISSION_ATTRIBUTE, None)
        if admission is None:
            return response
        if 300 <= response.status_code < 400:
            complete_login_success(admission)
            logger.info("event=admin_login_success route=%s request_id=%s", route, request_id)
        else:
            logger.warning("event=admin_login_failed route=%s request_id=%s", route, request_id)
        return response
