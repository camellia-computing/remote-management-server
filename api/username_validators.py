"""Versioned validator/field for the frozen username identity authority."""

from django import forms
from django.core.exceptions import ValidationError
from django.utils.deconstruct import deconstructible
from django.utils.translation import gettext_lazy as _

from api.username_unicode16 import MAX_LENGTH, normalize_username, require_unicode_version, valid_character


@deconstructible
class Unicode16UsernameValidator:
    message = _("Enter a valid username. This value may contain only letters, numbers, and @/./+/-/_ characters.")
    code = "invalid"

    def __call__(self, value):
        require_unicode_version()
        if (
            not isinstance(value, str)
            or not value
            or len(value) > MAX_LENGTH
            or not all(valid_character(character) for character in value)
        ):
            raise ValidationError(self.message, code=self.code)

    def __eq__(self, other):
        return self.__class__ is other.__class__


class Unicode16UsernameField(forms.CharField):
    def to_python(self, value):
        if value is None or value == "":
            return ""
        try:
            return normalize_username(value)
        except ValueError:
            raise ValidationError(Unicode16UsernameValidator.message, code="invalid") from None
