"""Frozen import surface used by published Django migration history."""

import ast
import importlib
import json
import re
from collections import defaultdict
from pathlib import Path

MANIFEST_PATH = Path(__file__).with_name("migration_compatibility_manifest.json")
_MIGRATION_FILE = re.compile(r"[0-9]{4}_[a-z0-9_]+\.py\Z")
_SYMBOL_PATH = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z")


class MigrationCompatibilityError(RuntimeError):
    """The historical migration import contract is malformed or drifted."""


def _attribute_path(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def discover_migration_runtime_symbols(migrations_path=None):
    """Discover explicit ``api.*`` imports and qualified references in history."""

    migrations_path = Path(migrations_path or Path(__file__).with_name("migrations"))
    consumers = defaultdict(set)
    for migration in sorted(migrations_path.glob("*.py")):
        if not _MIGRATION_FILE.fullmatch(migration.name):
            continue
        try:
            tree = ast.parse(migration.read_text(encoding="utf-8"), filename=str(migration))
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise MigrationCompatibilityError(f"cannot parse migration {migration.name}") from exc

        direct_modules = set()
        qualified_bindings = {}
        imported_symbols = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if not alias.name.startswith("api."):
                        continue
                    if alias.asname:
                        qualified_bindings[alias.asname] = alias.name
                    else:
                        direct_modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("api."):
                for alias in node.names:
                    if alias.name != "*":
                        imported_symbols.add(f"{node.module}.{alias.name}")

        paths = set(imported_symbols)
        for node in ast.walk(tree):
            path = _attribute_path(node)
            if not path:
                continue
            if any(path.startswith(f"{module}.") for module in direct_modules):
                paths.add(path)
            for local, module in qualified_bindings.items():
                if path == local or path.startswith(f"{local}."):
                    paths.add(module + path[len(local) :])
        for path in paths:
            if _SYMBOL_PATH.fullmatch(path):
                consumers[path].add(migration.name)
    return {path: tuple(sorted(names)) for path, names in sorted(consumers.items())}


def _load_json():
    try:
        value = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MigrationCompatibilityError("migration compatibility manifest cannot be loaded") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise MigrationCompatibilityError("migration compatibility manifest version is unsupported")
    symbols = value.get("symbols")
    if not isinstance(symbols, list) or not symbols:
        raise MigrationCompatibilityError("migration compatibility manifest symbols are invalid")
    normalized = []
    previous_path = ""
    for item in symbols:
        if not isinstance(item, dict):
            raise MigrationCompatibilityError("migration compatibility manifest contains an invalid symbol")
        path = item.get("path")
        kind = item.get("kind")
        consumers = item.get("consumers")
        deconstruct_path = item.get("deconstruct_path")
        valid_deconstruct = deconstruct_path is None or (
            isinstance(deconstruct_path, str) and _SYMBOL_PATH.fullmatch(deconstruct_path)
        )
        if (
            not isinstance(path, str)
            or not _SYMBOL_PATH.fullmatch(path)
            or path <= previous_path
            or not isinstance(kind, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", kind)
            or not isinstance(consumers, list)
            or not consumers
            or any(not isinstance(name, str) or not _MIGRATION_FILE.fullmatch(name) for name in consumers)
            or consumers != sorted(set(consumers))
            or not valid_deconstruct
        ):
            raise MigrationCompatibilityError(f"migration compatibility symbol {path!r} is invalid")
        normalized.append(
            {
                "path": path,
                "kind": kind,
                "consumers": tuple(consumers),
                "deconstruct_path": deconstruct_path,
            }
        )
        previous_path = path
    return tuple(normalized)


def load_migration_compatibility_manifest():
    return _load_json()


def _resolve(path):
    module_path, separator, attribute_path = path.rpartition(".")
    if not separator:
        raise MigrationCompatibilityError(f"migration compatibility path is not qualified: {path}")
    try:
        value = importlib.import_module(module_path)
    except (ImportError, AttributeError) as exc:
        raise MigrationCompatibilityError(f"migration compatibility module cannot be imported: {path}") from exc
    for attribute in attribute_path.split("."):
        if not hasattr(value, attribute):
            raise MigrationCompatibilityError(f"migration compatibility symbol is missing: {path}")
        value = getattr(value, attribute)
    return value


def check_migration_compatibility(migrations_path=None):
    """Validate manifest, source references, importability, and frozen paths."""

    manifest = load_migration_compatibility_manifest()
    expected = {item["path"]: item["consumers"] for item in manifest}
    observed = discover_migration_runtime_symbols(migrations_path)
    if observed != expected:
        missing = sorted(set(expected) - set(observed))
        extra = sorted(set(observed) - set(expected))
        changed = sorted(path for path in set(expected) & set(observed) if expected[path] != observed[path])
        raise MigrationCompatibilityError(
            "migration compatibility source drift: "
            f"missing={','.join(missing) or '-'} "
            f"extra={','.join(extra) or '-'} "
            f"changed={','.join(changed) or '-'}"
        )
    for item in manifest:
        value = _resolve(item["path"])
        if item["kind"] == "callable" and not callable(value):
            raise MigrationCompatibilityError(f"migration compatibility callable is invalid: {item['path']}")
        deconstruct_path = item["deconstruct_path"]
        if deconstruct_path and item["kind"] in {"field", "manager", "expression", "validator"}:
            if item["kind"] == "field":
                observed_path = value(max_length=1).deconstruct()[1]
            elif item["kind"] == "manager":
                observed_path = value().deconstruct()[1]
            elif item["kind"] == "validator":
                observed_path = value().deconstruct()[0]
            else:
                observed_path = value("compatibility_probe").deconstruct()[0]
            if observed_path != deconstruct_path:
                raise MigrationCompatibilityError(
                    f"migration compatibility deconstruct path changed: {item['path']} -> {observed_path}"
                )
    return manifest
