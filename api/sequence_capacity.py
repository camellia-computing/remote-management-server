from dataclasses import dataclass
from datetime import timedelta
from decimal import ROUND_FLOOR, Decimal

from django.db import DEFAULT_DB_ALIAS, connections, transaction

SEQUENCE_MAX_VALUE = (1 << 63) - 1
_STATUS_RANK = {"ok": 0, "warning": 1, "critical": 2}


@dataclass(frozen=True, slots=True)
class SequenceSample:
    sequence_name: str
    table_name: str
    column_name: str
    last_value: int
    max_value: int


def collect_sequence_samples(*, using=DEFAULT_DB_ALIAS):
    connection = connections[using]
    if connection.vendor == "postgresql":
        return _postgresql_sequence_samples(connection)
    if connection.vendor == "sqlite":
        return _sqlite_sequence_samples(connection)
    raise RuntimeError(f"unsupported sequence-capacity backend: {connection.vendor}")


def _postgresql_sequence_samples(connection):
    with connection.cursor() as cursor:
        cursor.execute(
            r"""
            SELECT
                format('%I.%I', sequence_namespace.nspname, sequence_class.relname),
                table_class.relname,
                attribute.attname,
                COALESCE(pg_sequence_last_value(sequence_class.oid), 0),
                sequence_parameters.seqmax
            FROM pg_class AS sequence_class
            JOIN pg_namespace AS sequence_namespace
              ON sequence_namespace.oid = sequence_class.relnamespace
            JOIN pg_sequence AS sequence_parameters
              ON sequence_parameters.seqrelid = sequence_class.oid
            JOIN pg_depend AS dependency
              ON dependency.objid = sequence_class.oid
             AND dependency.deptype IN ('a', 'i')
            JOIN pg_class AS table_class
              ON table_class.oid = dependency.refobjid
            JOIN pg_namespace AS table_namespace
              ON table_namespace.oid = table_class.relnamespace
            JOIN pg_attribute AS attribute
              ON attribute.attrelid = table_class.oid
             AND attribute.attnum = dependency.refobjsubid
            WHERE sequence_class.relkind = 'S'
              AND table_namespace.nspname = current_schema()
              AND left(table_class.relname, 4) = 'api_'
            ORDER BY sequence_namespace.nspname, sequence_class.relname
            """
        )
        rows = cursor.fetchall()
    return tuple(SequenceSample(*row) for row in rows)


def _sqlite_sequence_samples(connection):
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT sqlite_master.name, COALESCE(sqlite_sequence.seq, 0)
            FROM sqlite_master
            LEFT JOIN sqlite_sequence ON sqlite_sequence.name = sqlite_master.name
            WHERE sqlite_master.type = 'table'
              AND substr(sqlite_master.name, 1, 4) = 'api_'
              AND upper(sqlite_master.sql) LIKE '%AUTOINCREMENT%'
            ORDER BY sqlite_master.name
            """
        )
        tables = cursor.fetchall()
        rows = []
        for table_name, last_value in tables:
            quoted_table = connection.ops.quote_name(table_name)
            cursor.execute(f"PRAGMA table_info({quoted_table})")  # noqa: S608 - identifier is introspected and quoted
            primary_key = next((column[1] for column in cursor.fetchall() if column[5]), None)
            if primary_key is None:
                continue
            rows.append(
                SequenceSample(
                    sequence_name=f"main.{table_name}",
                    table_name=table_name,
                    column_name=primary_key,
                    last_value=int(last_value),
                    max_value=SEQUENCE_MAX_VALUE,
                )
            )
    return tuple(rows)


def record_sequence_capacity(
    samples,
    *,
    sampled_at,
    warning_percent,
    critical_percent,
    using=DEFAULT_DB_ALIAS,
):
    from api.models import SequenceCapacityState

    samples = tuple(samples)
    if not samples:
        raise RuntimeError("no application-owned database sequences were found")
    names = [sample.sequence_name for sample in samples]
    if len(names) != len(set(names)):
        raise RuntimeError("duplicate application-owned database sequence")

    reports = []
    states = []
    with transaction.atomic(using=using):
        locked_states = tuple(SequenceCapacityState.objects.using(using).select_for_update())
        previous = {state.sequence_name: state for state in locked_states if state.sequence_name in names}
        SequenceCapacityState.objects.using(using).exclude(sequence_name__in=names).delete()
        for sample in samples:
            report = _sequence_report(
                sample,
                previous.get(sample.sequence_name),
                sampled_at=sampled_at,
                warning_percent=warning_percent,
                critical_percent=critical_percent,
            )
            reports.append(report)
            states.append(
                SequenceCapacityState(
                    sequence_name=sample.sequence_name,
                    last_value=sample.last_value,
                    sampled_at=sampled_at,
                )
            )
        SequenceCapacityState.objects.using(using).bulk_create(
            states,
            update_conflicts=True,
            update_fields=("last_value", "sampled_at"),
            unique_fields=("sequence_name",),
        )

    overall = max((report["status"] for report in reports), key=_STATUS_RANK.__getitem__)
    return {"status": overall, "sequences": reports}


def _sequence_report(sample, previous, *, sampled_at, warning_percent, critical_percent):
    if not 0 <= sample.last_value <= sample.max_value <= SEQUENCE_MAX_VALUE:
        raise RuntimeError(f"invalid database sequence bounds: {sample.sequence_name}")
    consumed_ppm = (sample.last_value * 1_000_000) // sample.max_value
    remaining = sample.max_value - sample.last_value
    status = "ok"
    reason = "within_capacity"
    if sample.last_value * 100 >= sample.max_value * critical_percent:
        status = "critical"
        reason = "critical_threshold"
    elif sample.last_value * 100 >= sample.max_value * warning_percent:
        status = "warning"
        reason = "warning_threshold"

    growth_per_day = None
    eta_days = None
    if previous is not None:
        elapsed = sampled_at - previous.sampled_at
        delta = sample.last_value - previous.last_value
        if delta < 0:
            status = "critical"
            reason = "sequence_regressed"
        elif delta > 0 and elapsed > timedelta(0):
            elapsed_seconds = Decimal(str(elapsed.total_seconds()))
            growth = Decimal(delta * 86_400) / elapsed_seconds
            growth_per_day = format(growth.quantize(Decimal("0.001")), "f")
            eta = Decimal(remaining) / growth
            eta_days = int(eta.to_integral_value(rounding=ROUND_FLOOR))

    return {
        "sequence": sample.sequence_name,
        "table": sample.table_name,
        "column": sample.column_name,
        "last_value": sample.last_value,
        "max_value": sample.max_value,
        "remaining": remaining,
        "consumed_ppm": consumed_ppm,
        "growth_per_day": growth_per_day,
        "eta_days": eta_days,
        "status": status,
        "reason": reason,
    }
