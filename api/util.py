import platform

from django.conf import settings as _settings


def settings(request):
    """Expose the bounded application context shared by server-rendered pages."""
    user = getattr(request, "user", None)
    context = {
        "settings": _settings,
        "domain": _settings.ID_SERVER,
        "is_windows": platform.system() == "Windows",
        "subtitle": "",
    }
    if user and getattr(user, "is_authenticated", False):
        context.update(
            {
                "u": user,
                "username": user.username,
                "is_admin": getattr(user, "is_admin", False),
                "is_active": getattr(user, "is_active", True),
            }
        )
    return context
