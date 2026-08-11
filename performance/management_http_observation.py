#!/usr/bin/env python3
"""Emit one bounded observation for the authenticated device-list hot path."""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import pathlib
import sys
import time

SCENARIO = "management-http-devices-v1"
REQUESTS = 20
SEED_DEVICES = 100


def _configure(output: pathlib.Path) -> pathlib.Path:
    if not output.is_absolute():
        raise RuntimeError("performance observation path must be absolute")
    forbidden = (
        "CAMELLIA_REMOTE_DATABASE_URL",
        "CAMELLIA_REMOTE_DATABASE_HOST",
        "CAMELLIA_REMOTE_DATABASE_NAME",
        "CAMELLIA_REMOTE_DATABASE_USER",
        "CAMELLIA_REMOTE_DATABASE_PASSWORD",
    )
    configured = [name for name in forbidden if os.environ.get(name)]
    if configured:
        raise RuntimeError("management performance smoke refuses PostgreSQL settings: " + ",".join(configured))
    database = output.with_name("management-performance.sqlite3")
    if database.exists() or database.is_symlink():
        raise RuntimeError("performance database path already exists")
    os.environ["DJANGO_SETTINGS_MODULE"] = "camellia_remote_management.settings"
    os.environ["CAMELLIA_REMOTE_DEBUG"] = "true"
    os.environ["CAMELLIA_REMOTE_SECRET_KEY"] = hashlib.sha256(
        b"camellia-management-performance-settings-v1"
    ).hexdigest()
    os.environ["CAMELLIA_REMOTE_ALLOWED_HOSTS"] = "testserver"
    os.environ["CAMELLIA_REMOTE_CSRF_TRUSTED_ORIGINS"] = "http://testserver"
    os.environ["CAMELLIA_REMOTE_RATE_LIMIT_ENABLED"] = "false"
    os.environ["CAMELLIA_REMOTE_SQLITE_DB_PATH"] = str(database)
    return database


def _seed() -> tuple[str, int]:
    from django.utils import timezone

    from api.models import RemoteDevice, RemoteToken, UserProfile

    user_password = hashlib.sha256(b"camellia-management-performance-user-v1").hexdigest()
    user = UserProfile.objects.create_superuser(
        username="performance-admin",
        password=user_password,
    )
    devices = []
    for index in range(SEED_DEVICES):
        encoded_uuid = base64.b64encode(f"performance-uuid-{index:04d}".encode()).decode()
        devices.append(
            RemoteDevice(
                rid=f"perf{index:04d}",
                cpu="synthetic-cpu",
                hostname=f"perf-host-{index:04d}",
                memory="synthetic-memory",
                os="synthetic-os",
                owner=user,
                username=f"operator-{index:04d}",
                uuid=encoded_uuid,
                version="performance-v1",
            )
        )
    RemoteDevice.objects.bulk_create(devices)
    token_device = RemoteDevice.objects.get(rid="perf0000")
    raw_token = base64.urlsafe_b64encode(hashlib.sha256(b"camellia-management-performance-token-v1").digest()).decode()
    RemoteToken.objects.create(
        access_token=hashlib.sha256(raw_token.encode()).hexdigest(),
        credential_hash=user.get_session_auth_hash(),
        device=token_device,
        expires_at=timezone.now() + datetime.timedelta(hours=1),
        subject_user=user,
    )
    return raw_token, user.pk


def _observe(raw_token: str) -> dict[str, float]:
    from django.db import connection
    from django.test import Client
    from django.test.utils import CaptureQueriesContext

    client = Client(raise_request_exception=False)
    headers = {"HTTP_AUTHORIZATION": f"Bearer {raw_token}"}
    query = {"device_name": "perf-host-004%", "pageSize": "20"}

    for _ in range(3):
        response = client.get("/api/devices", query, **headers)
        if response.status_code != 200 or len(response.json().get("data", ())) != 10:
            raise RuntimeError("device-list warmup changed semantics")

    last_size = 0
    started = time.perf_counter_ns()
    with CaptureQueriesContext(connection) as captured:
        for _ in range(REQUESTS):
            response = client.get("/api/devices", query, **headers)
            if response.status_code != 200:
                raise RuntimeError(f"device-list request failed with {response.status_code}")
            payload = response.json()
            if len(payload.get("data", ())) != 10:
                raise RuntimeError("device-list response changed semantics")
            last_size = len(response.content)
    elapsed_ns = time.perf_counter_ns() - started
    return {
        "query_count_per_request": len(captured) / REQUESTS,
        "response_bytes": float(last_size),
        "response_ms_mean": elapsed_ns / REQUESTS / 1_000_000,
    }


def _write(output: pathlib.Path, metrics: dict[str, float]) -> None:
    for name, value in metrics.items():
        if not isinstance(value, (int, float)) or not 0 < value < 1e18:
            raise RuntimeError(f"invalid performance metric: {name}")
    document = {
        "metrics": {
            "query_count_per_request": {
                "direction": "lower",
                "unit": "count",
                "value": metrics["query_count_per_request"],
            },
            "response_bytes": {
                "direction": "lower",
                "unit": "bytes",
                "value": metrics["response_bytes"],
            },
            "response_ms_mean": {
                "direction": "lower",
                "unit": "ms",
                "value": metrics["response_ms_mean"],
            },
        },
        "scenario": SCENARIO,
        "schema": "camellia-performance-observation-v1",
    }
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(document, stream, allow_nan=False, separators=(",", ":"), sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main() -> int:
    raw_output = os.environ.get("CAMELLIA_PERFORMANCE_OBSERVATION_FILE", "")
    if not raw_output:
        raise RuntimeError("CAMELLIA_PERFORMANCE_OBSERVATION_FILE is required")
    output = pathlib.Path(raw_output)
    database = _configure(output)
    repository = pathlib.Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repository))
    os.chdir(repository)

    import django
    from django.core.management import call_command
    from django.db import connections

    django.setup()
    call_command("migrate", interactive=False, verbosity=0)
    raw_token, _user_id = _seed()
    metrics = _observe(raw_token)
    _write(output, metrics)
    connections.close_all()
    database.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
