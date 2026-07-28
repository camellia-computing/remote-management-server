from django import template
from django.forms.utils import flatatt
from django.utils.safestring import mark_safe
from django.utils.translation import gettext as _

register = template.Library()


@register.filter
def translate(text):
    return _(text)


@register.filter
def safe_attrs(attrs):
    if not attrs:
        return ""
    return mark_safe(flatatt(attrs))
