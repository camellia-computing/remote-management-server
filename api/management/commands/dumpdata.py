"""Fail closed before Django logical export can load credential plaintext."""

from django.apps import apps
from django.core.management.base import CommandError
from django.core.management.commands.dumpdata import Command as DjangoDumpdataCommand
from django.core.management.commands.dumpdata import parse_apps_and_model_labels
from django.db import router

from api.encrypted_fields import EncryptedTextField

MAX_REPORTED_MODELS = 16


def _selected_models(app_labels, excludes, primary_keys, using):
    excluded_models, excluded_apps = parse_apps_and_model_labels(excludes)
    if not app_labels:
        if primary_keys:
            raise CommandError("You can only use --pks option with one model")
        app_list = {
            app_config: None
            for app_config in apps.get_app_configs()
            if app_config.models_module is not None and app_config not in excluded_apps
        }
    else:
        if len(app_labels) > 1 and primary_keys:
            raise CommandError("You can only use --pks option with one model")
        app_list = {}
        for label in app_labels:
            try:
                app_label, model_label = label.split(".")
            except ValueError:
                if primary_keys:
                    raise CommandError("You can only use --pks option with one model") from None
                try:
                    app_config = apps.get_app_config(label)
                except LookupError as exc:
                    raise CommandError(str(exc)) from exc
                if app_config.models_module is not None and app_config not in excluded_apps:
                    app_list[app_config] = None
                continue
            try:
                app_config = apps.get_app_config(app_label)
            except LookupError as exc:
                raise CommandError(str(exc)) from exc
            if app_config.models_module is None or app_config in excluded_apps:
                continue
            try:
                model = app_config.get_model(model_label)
            except LookupError as exc:
                raise CommandError(f"Unknown model: {app_label}.{model_label}") from exc
            selected = app_list.setdefault(app_config, [])
            if selected is not None and model not in selected:
                selected.append(model)

    for app_config, model_list in app_list.items():
        selected = app_config.get_models() if model_list is None else model_list
        for model in selected:
            if model not in excluded_models and not model._meta.proxy and router.allow_migrate_model(using, model):
                yield model


def _encrypted_models(models):
    return sorted(
        model._meta.label
        for model in models
        if any(isinstance(field, EncryptedTextField) for field in model._meta.concrete_fields)
    )


class Command(DjangoDumpdataCommand):
    help = DjangoDumpdataCommand.help + " Models containing encrypted credentials are refused."

    def handle(self, *app_labels, **options):
        blocked = _encrypted_models(
            _selected_models(
                app_labels,
                options["exclude"],
                options["primary_keys"],
                options["database"],
            )
        )
        if blocked:
            reported = blocked[:MAX_REPORTED_MODELS]
            omitted = len(blocked) - len(reported)
            suffix = f" (+{omitted} more)" if omitted else ""
            raise CommandError(
                "safe-logical-export-v1 refuses models containing encrypted credentials; "
                f"count={len(blocked)} models={','.join(reported)}{suffix}. "
                "Use the authenticated physical backup set."
            )
        return super().handle(*app_labels, **options)
