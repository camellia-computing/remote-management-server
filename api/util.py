# -*- coding: utf-8 -*-
"""
Created on Thu Nov 19 15:51:21 2020

@author: lenovo
"""

import platform
import logging
from django.conf import settings as _settings

logger = logging.getLogger(__name__)


def settings(request):
    """
    TEMPLATE_CONTEXT_PROCESSORS
    """
    context = {"settings": _settings}
    try:
        user = getattr(request, "user", None)
        if user and getattr(user, "is_authenticated", False):
            context["u"] = user
            context["username"] = user.username
            context["is_admin"] = getattr(user, "is_admin", False)
            context["is_active"] = getattr(user, "is_active", True)
        context["domain"] = _settings.ID_SERVER
        context["is_windows"] = True if platform.system() == "Windows" else False
        context.setdefault("subtitle", "")
        logger.debug("set system status variable")
    except Exception as e:
        logger.error("settings:%s", e)
    return context
