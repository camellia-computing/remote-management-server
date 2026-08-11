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
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

SCENARIO = "management-http-devices-v1"
REQUESTS = 20
SEED_DEVICES = 100


@dataclass(frozen=True)
class DatabaseHandle:
    sqlite_path: pathlib.Path | None = None
    postgres_admin_url: str | None = None
    postgres_database: str | None = None


def _prepare_postgres(output: pathlib.Path, raw_url: str) -> DatabaseHandle:
    parsed = urlsplit(raw_url)
    if (
        parsed.scheme not in {"postgres", "postgresql"}
        or parsed.hostname != "127.0.0.1"
        or parsed.port is None
        or not 55600 <= parsed.port <= 55699
        or parsed.username is None
        or parsed.password is None
        or parsed.path != "/postgres"
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError(
            "CAMELLIA_PERFORMANCE_DATABASE_URL must target PostgreSQL on 127.0.0.1:55600..55699/postgres"
        )
    database = "camellia_perf_" + hashlib.sha256(str(output).encode("utf-8")).hexdigest()[:16]
    admin_url = urlunsplit((parsed.scheme, parsed.netloc, "/postgres", "", ""))
    database_url = urlunsplit((parsed.scheme, parsed.netloc, f"/{database}", "", ""))
    import psycopg
    from psycopg import sql

    with psycopg.connect(admin_url, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
    os.environ["CAMELLIA_REMOTE_DATABASE_URL"] = database_url
    os.environ["CAMELLIA_REMOTE_DATABASE_SSLMODE"] = "disable"
    return DatabaseHandle(postgres_admin_url=admin_url, postgres_database=database)


def _configure(output: pathlib.Path) -> DatabaseHandle:
    if not output.is_absolute():
        raise RuntimeError("performance observation path must be absolute")
    configured = sorted(name for name in os.environ if name.startswith("CAMELLIA_REMOTE_DATABASE_"))
    if configured:
        raise RuntimeError(
            "management performance observation refuses production database settings: " + ",".join(configured)
        )
    os.environ["DJANGO_SETTINGS_MODULE"] = "camellia_remote_management.settings"
    os.environ["CAMELLIA_REMOTE_DEBUG"] = "true"
    os.environ["CAMELLIA_REMOTE_SECRET_KEY"] = hashlib.sha256(
        b"camellia-management-performance-settings-v1"
    ).hexdigest()
    os.environ["CAMELLIA_REMOTE_ALLOWED_HOSTS"] = "testserver"
    os.environ["CAMELLIA_REMOTE_CSRF_TRUSTED_ORIGINS"] = "http://testserver"
    os.environ["CAMELLIA_REMOTE_RATE_LIMIT_ENABLED"] = "false"
    performance_url = os.environ.get("CAMELLIA_PERFORMANCE_DATABASE_URL", "").strip()
    if performance_url:
        return _prepare_postgres(output, performance_url)
    database = output.with_name("management-performance.sqlite3")
    if database.exists() or database.is_symlink():
        raise RuntimeError("performance database path already exists")
    os.environ["CAMELLIA_REMOTE_SQLITE_DB_PATH"] = str(database)
    return DatabaseHandle(sqlite_path=database)


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


def _observe(raw_token: str, work_seconds: int | None) -> dict[str, float]:
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
    deadline = started + work_seconds * 1_000_000_000 if work_seconds is not None else None
    request_count = 0
    with CaptureQueriesContext(connection) as captured:
        while request_count < REQUESTS or (deadline is not None and time.perf_counter_ns() < deadline):
            response = client.get("/api/devices", query, **headers)
            if response.status_code != 200:
                raise RuntimeError(f"device-list request failed with {response.status_code}")
            payload = response.json()
            if len(payload.get("data", ())) != 10:
                raise RuntimeError("device-list response changed semantics")
            last_size = len(response.content)
            request_count += 1
    elapsed_ns = time.perf_counter_ns() - started
    return {
        "query_count_per_request": len(captured) / request_count,
        "response_bytes": float(last_size),
        "response_ms_mean": elapsed_ns / request_count / 1_000_000,
    }


def _work_seconds() -> int | None:
    raw = os.environ.get("CAMELLIA_PERFORMANCE_WORK_SECONDS")
    if raw is None:
        return None
    if not raw.isascii() or not raw.isdigit() or len(raw) > 2 or str(int(raw)) != raw or not 1 <= int(raw) <= 60:
        raise RuntimeError("CAMELLIA_PERFORMANCE_WORK_SECONDS must be a canonical integer in 1..60")
    return int(raw)


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
    work_seconds = _work_seconds()
    database = _configure(output)
    repository = pathlib.Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repository))
    os.chdir(repository)

    import django
    from django.core.management import call_command
    from django.db import connections

    django_ready = False
    try:
        django.setup()
        django_ready = True
        call_command("migrate", interactive=False, verbosity=0)
        raw_token, _user_id = _seed()
        metrics = _observe(raw_token, work_seconds)
        _write(output, metrics)
    finally:
        if django_ready:
            connections.close_all()
        if database.sqlite_path is not None:
            database.sqlite_path.unlink(missing_ok=True)
        if database.postgres_admin_url and database.postgres_database:
            import psycopg
            from psycopg import sql

            with psycopg.connect(database.postgres_admin_url, autocommit=True) as connection:
                connection.execute(
                    sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database.postgres_database))
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
