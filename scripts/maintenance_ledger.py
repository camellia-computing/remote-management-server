#!/usr/bin/env python3
"""Durable, secret-free run ledger and freshness query for maintenance jobs."""

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import sys

EVENT_FORMAT = "camellia-remote-maintenance-event-v1"
SUMMARY_FORMAT = "camellia-remote-maintenance-summary-v1"
FRESHNESS_FORMAT = "camellia-remote-maintenance-freshness-v1"
TIMESTAMP_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
ID_RE = re.compile(r"^[0-9a-f]{32}$")
REASON_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,63}$")
KINDS = frozenset(("backup", "cleanup"))
STATUSES = frozenset(("scheduled", "started", "heartbeat", "completed", "failed", "skipped", "unknown"))
TERMINAL_STATUSES = frozenset(("completed", "failed", "skipped", "unknown"))
MAX_EVENT_BYTES = 4096
MAX_INTEGER = (1 << 63) - 1
EVENT_FIELDS = frozenset(
    {
        "artifact_generation",
        "deadline_seconds",
        "digest",
        "duration_seconds",
        "format",
        "input_bytes",
        "input_count",
        "kind",
        "observed_at",
        "operation_id",
        "output_bytes",
        "output_count",
        "previous_digest",
        "reason",
        "sequence",
        "started_at",
        "status",
    }
)
SUMMARY_FIELDS = frozenset(
    {
        "artifact_generation",
        "consecutive_failures",
        "consecutive_skips",
        "consecutive_unknown",
        "deadline_seconds",
        "duration_seconds",
        "event_digest",
        "event_sequence",
        "format",
        "heartbeat_at",
        "input_bytes",
        "input_count",
        "kind",
        "last_failure_at",
        "last_skip_at",
        "last_success_at",
        "last_success_operation_id",
        "last_unknown_at",
        "observed_at",
        "operation_id",
        "output_bytes",
        "output_count",
        "reason",
        "started_at",
        "status",
    }
)


class LedgerError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _json_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LedgerError("maintenance JSON contains duplicate fields")
        result[key] = value
    return result


def now_timestamp():
    return dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")


def parse_timestamp(value, field):
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        raise LedgerError(f"{field} is invalid")
    try:
        parsed = dt.datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.UTC)
    except ValueError as exc:
        raise LedgerError(f"{field} is invalid") from exc
    if parsed.strftime("%Y%m%dT%H%M%SZ") != value:
        raise LedgerError(f"{field} is invalid")
    return parsed


def validate_state_dir(path):
    if not os.path.isabs(path):
        raise LedgerError("maintenance state directory must be absolute")
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        try:
            os.makedirs(path, mode=0o700, exist_ok=False)
            current = os.lstat(path)
        except OSError as exc:
            raise LedgerError("maintenance state directory cannot be created") from exc
    except OSError as exc:
        raise LedgerError("maintenance state directory cannot be inspected") from exc
    if not stat.S_ISDIR(current.st_mode) or stat.S_ISLNK(current.st_mode):
        raise LedgerError("maintenance state directory is unsafe")
    if current.st_mode & 0o077 or current.st_uid != os.getuid():
        raise LedgerError("maintenance state directory has unsafe owner or permissions")
    return path


def safe_file(path, *, create=False):
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if create:
        flags |= os.O_CREAT
    try:
        fd = os.open(path, flags, 0o600)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise LedgerError("maintenance ledger path cannot be opened safely") from exc
    try:
        current = os.fstat(fd)
        if not stat.S_ISREG(current.st_mode) or current.st_mode & 0o077 or current.st_uid != os.getuid():
            raise LedgerError("maintenance ledger path has unsafe type, owner, or permissions")
    except Exception:
        os.close(fd)
        raise
    return fd


def read_json(path, description):
    fd = safe_file(path)
    if fd is None:
        return None
    try:
        with os.fdopen(fd, "rb") as stream:
            encoded = stream.read(MAX_EVENT_BYTES + 1)
    except OSError as exc:
        raise LedgerError(f"{description} cannot be read") from exc
    if not encoded or len(encoded) > MAX_EVENT_BYTES:
        raise LedgerError(f"{description} size is invalid")
    try:
        value = json.loads(encoded.decode("utf-8"), object_pairs_hook=_json_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LedgerError(f"{description} JSON is invalid") from exc
    if canonical(value) != encoded:
        raise LedgerError(f"{description} is not canonical")
    return value


def _write_all(fd, encoded):
    offset = 0
    while offset < len(encoded):
        written = os.write(fd, encoded[offset:])
        if written <= 0:
            raise OSError("short maintenance ledger write")
        offset += written


def atomic_write(path, encoded):
    parent = os.path.dirname(path)
    temporary = os.path.join(parent, f".{os.path.basename(path)}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        existing_fd = safe_file(path)
        if existing_fd is not None:
            os.close(existing_fd)
        fd = os.open(temporary, flags, 0o600)
        try:
            _write_all(fd, encoded)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise LedgerError("maintenance summary cannot be committed") from exc


def _validate_nonnegative(value, field, *, optional=True):
    if value is None and optional:
        return
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_INTEGER:
        raise LedgerError(f"{field} is invalid")


def validate_summary(value, kind):
    if not isinstance(value, dict) or set(value) != SUMMARY_FIELDS:
        raise LedgerError("maintenance summary fields are invalid")
    if value["format"] != SUMMARY_FORMAT or value["kind"] != kind:
        raise LedgerError("maintenance summary format or kind is invalid")
    if not isinstance(value["operation_id"], str) or not ID_RE.fullmatch(value["operation_id"]):
        raise LedgerError("maintenance summary operation ID is invalid")
    if value["status"] not in STATUSES or not REASON_RE.fullmatch(value.get("reason", "")):
        raise LedgerError("maintenance summary status or reason is invalid")
    for field in (
        "observed_at",
        "started_at",
        "heartbeat_at",
        "last_failure_at",
        "last_skip_at",
        "last_success_at",
        "last_unknown_at",
    ):
        if value[field] is not None:
            parse_timestamp(value[field], field)
    if value["started_at"] is None:
        raise LedgerError("maintenance summary start timestamp is invalid")
    for field in (
        "artifact_generation",
        "deadline_seconds",
        "duration_seconds",
        "event_sequence",
        "input_bytes",
        "input_count",
        "output_bytes",
        "output_count",
        "consecutive_failures",
        "consecutive_skips",
        "consecutive_unknown",
    ):
        _validate_nonnegative(value[field], field, optional=field not in {"deadline_seconds", "event_sequence"})
    if value["event_sequence"] < 1 or not re.fullmatch(r"[0-9a-f]{64}", value["event_digest"]):
        raise LedgerError("maintenance summary event pointer is invalid")
    if value["last_success_at"] is None:
        if value["last_success_operation_id"] is not None:
            raise LedgerError("maintenance summary success pointer is inconsistent")
    elif not isinstance(value["last_success_operation_id"], str) or not ID_RE.fullmatch(
        value["last_success_operation_id"]
    ):
        raise LedgerError("maintenance summary success operation ID is invalid")
    return value


def _validate_event(value):
    if not isinstance(value, dict) or set(value) != EVENT_FIELDS or value["format"] != EVENT_FORMAT:
        raise LedgerError("maintenance ledger tail fields are invalid")
    if value["kind"] not in KINDS or value["status"] not in STATUSES:
        raise LedgerError("maintenance ledger tail kind or status is invalid")
    if not isinstance(value["operation_id"], str) or not ID_RE.fullmatch(value["operation_id"]):
        raise LedgerError("maintenance ledger tail operation ID is invalid")
    if not REASON_RE.fullmatch(value["reason"]):
        raise LedgerError("maintenance ledger tail reason is invalid")
    parse_timestamp(value["observed_at"], "observed_at")
    parse_timestamp(value["started_at"], "started_at")
    for field in (
        "artifact_generation",
        "deadline_seconds",
        "duration_seconds",
        "input_bytes",
        "input_count",
        "output_bytes",
        "output_count",
        "sequence",
    ):
        _validate_nonnegative(value[field], field)
    digest = value["digest"]
    unsigned = dict(value)
    del unsigned["digest"]
    if not isinstance(digest, str) or hashlib.sha256(canonical(unsigned)).hexdigest() != digest:
        raise LedgerError("maintenance ledger tail digest is invalid")
    if value["sequence"] < 1 or (
        value["previous_digest"] is not None
        and (
            not isinstance(value["previous_digest"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["previous_digest"])
        )
    ):
        raise LedgerError("maintenance ledger tail sequence is invalid")
    return value


def read_ledger_tail(fd):
    size = os.fstat(fd).st_size
    if size == 0:
        return None
    if size > 0:
        os.lseek(fd, -1, os.SEEK_END)
        if os.read(fd, 1) != b"\n":
            raise LedgerError("maintenance ledger has an incomplete tail")
    read_size = min(size, MAX_EVENT_BYTES + 2)
    os.lseek(fd, size - read_size, os.SEEK_SET)
    suffix = os.read(fd, read_size)
    lines = suffix.rstrip(b"\n").split(b"\n")
    encoded = lines[-1]
    if not encoded or len(encoded) > MAX_EVENT_BYTES:
        raise LedgerError("maintenance ledger tail size is invalid")
    try:
        value = json.loads(encoded.decode("utf-8"), object_pairs_hook=_json_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LedgerError("maintenance ledger tail JSON is invalid") from exc
    if canonical(value) != encoded:
        raise LedgerError("maintenance ledger tail is not canonical")
    return _validate_event(value)


def _validate_transition(previous, args, observed_at):
    if previous is None:
        if args.status not in {"scheduled", "failed", "unknown"}:
            raise LedgerError("maintenance operation must begin as scheduled")
        return
    if parse_timestamp(observed_at, "observed_at") < parse_timestamp(previous["observed_at"], "previous observed_at"):
        raise LedgerError("maintenance clock moved backwards")
    if previous["operation_id"] != args.operation_id:
        if previous["status"] not in TERMINAL_STATUSES:
            raise LedgerError("previous maintenance operation has no terminal state")
        if args.status not in {"scheduled", "failed", "unknown"}:
            raise LedgerError("new maintenance operation must begin as scheduled")
        return
    if previous["started_at"] != args.started_at or previous["deadline_seconds"] != args.deadline_seconds:
        raise LedgerError("maintenance operation identity fields changed")
    if previous["status"] in TERMINAL_STATUSES:
        if previous["status"] == args.status:
            return
        raise LedgerError("maintenance terminal state cannot change")
    allowed = {
        "scheduled": {"started", "failed", "skipped", "unknown"},
        "started": {"heartbeat", "completed", "failed", "skipped", "unknown"},
        "heartbeat": {"heartbeat", "completed", "failed", "skipped", "unknown"},
    }
    if args.status not in allowed[previous["status"]]:
        raise LedgerError("maintenance state transition is invalid")


def _build_summary(previous, event):
    status = event["status"]
    completed = status == "completed"
    failed = status == "failed"
    skipped = status == "skipped"
    unknown = status == "unknown"
    previous = previous or {}
    same_operation = previous.get("operation_id") == event["operation_id"]
    heartbeat_at = event["observed_at"] if status in {"started", "heartbeat"} else None
    if same_operation and heartbeat_at is None and status not in TERMINAL_STATUSES:
        heartbeat_at = previous.get("heartbeat_at")
    return {
        "artifact_generation": event["artifact_generation"],
        "consecutive_failures": (
            previous.get("consecutive_failures", 0) + 1
            if failed
            else (0 if status in TERMINAL_STATUSES else previous.get("consecutive_failures", 0))
        ),
        "consecutive_skips": (
            previous.get("consecutive_skips", 0) + 1
            if skipped
            else (0 if status in TERMINAL_STATUSES else previous.get("consecutive_skips", 0))
        ),
        "consecutive_unknown": (
            previous.get("consecutive_unknown", 0) + 1
            if unknown
            else (0 if status in TERMINAL_STATUSES else previous.get("consecutive_unknown", 0))
        ),
        "deadline_seconds": event["deadline_seconds"],
        "duration_seconds": event["duration_seconds"],
        "event_digest": event["digest"],
        "event_sequence": event["sequence"],
        "format": SUMMARY_FORMAT,
        "heartbeat_at": heartbeat_at,
        "input_bytes": event["input_bytes"],
        "input_count": event["input_count"],
        "kind": event["kind"],
        "last_failure_at": event["observed_at"] if failed else previous.get("last_failure_at"),
        "last_skip_at": event["observed_at"] if skipped else previous.get("last_skip_at"),
        "last_success_at": event["observed_at"] if completed else previous.get("last_success_at"),
        "last_success_operation_id": event["operation_id"] if completed else previous.get("last_success_operation_id"),
        "last_unknown_at": event["observed_at"] if unknown else previous.get("last_unknown_at"),
        "observed_at": event["observed_at"],
        "operation_id": event["operation_id"],
        "output_bytes": event["output_bytes"],
        "output_count": event["output_count"],
        "reason": event["reason"],
        "started_at": event["started_at"],
        "status": status,
    }


def record(args):
    state_dir = validate_state_dir(args.state_dir)
    if not ID_RE.fullmatch(args.operation_id):
        raise LedgerError("operation ID is invalid")
    if args.kind not in KINDS or args.status not in STATUSES or not REASON_RE.fullmatch(args.reason):
        raise LedgerError("maintenance kind, status, or reason is invalid")
    for name in (
        "deadline_seconds",
        "duration_seconds",
        "input_count",
        "output_count",
        "input_bytes",
        "output_bytes",
        "artifact_generation",
    ):
        _validate_nonnegative(getattr(args, name), name, optional=name != "deadline_seconds")
    if not 0 <= args.deadline_seconds <= 3600:
        raise LedgerError("deadline is out of range")
    if args.status == "heartbeat" and args.duration_seconds is None:
        raise LedgerError("heartbeat duration is required")
    if args.status == "completed":
        if args.duration_seconds is None:
            raise LedgerError("completed duration is required")
        if args.kind == "backup" and ((args.artifact_generation or 0) < 1 or (args.output_bytes or 0) < 1):
            raise LedgerError("completed backup metrics are incomplete")
        if args.kind == "cleanup" and (args.input_count is None or args.output_count is None):
            raise LedgerError("completed cleanup metrics are incomplete")
    observed_at = now_timestamp()
    args.started_at = args.started_at or observed_at
    parse_timestamp(args.started_at, "started_at")
    if parse_timestamp(args.started_at, "started_at") > parse_timestamp(observed_at, "observed_at"):
        raise LedgerError("maintenance operation starts in the future")

    ledger_path = os.path.join(state_dir, "maintenance-events.jsonl")
    summary_path = os.path.join(state_dir, f"latest-{args.kind}.json")
    lock_path = os.path.join(state_dir, ".maintenance-ledger.lock")
    lock_fd = safe_file(lock_path, create=True)
    ledger_fd = None
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        ledger_fd = safe_file(ledger_path, create=True)
        tail = read_ledger_tail(ledger_fd)
        previous_value = read_json(summary_path, "maintenance summary")
        previous = validate_summary(previous_value, args.kind) if previous_value is not None else None
        if previous and previous["operation_id"] == args.operation_id and previous["status"] == args.status:
            print(canonical(previous).decode("utf-8"))
            return
        _validate_transition(previous, args, observed_at)
        event = {
            "artifact_generation": args.artifact_generation,
            "deadline_seconds": args.deadline_seconds,
            "duration_seconds": args.duration_seconds,
            "format": EVENT_FORMAT,
            "input_bytes": args.input_bytes,
            "input_count": args.input_count,
            "kind": args.kind,
            "observed_at": observed_at,
            "operation_id": args.operation_id,
            "output_bytes": args.output_bytes,
            "output_count": args.output_count,
            "previous_digest": tail["digest"] if tail else None,
            "reason": args.reason,
            "sequence": (tail["sequence"] + 1 if tail else 1),
            "started_at": args.started_at,
            "status": args.status,
        }
        event["digest"] = hashlib.sha256(canonical(event)).hexdigest()
        encoded_event = canonical(event) + b"\n"
        if len(encoded_event) > MAX_EVENT_BYTES:
            raise LedgerError("maintenance event is too large")
        os.lseek(ledger_fd, 0, os.SEEK_END)
        _write_all(ledger_fd, encoded_event)
        os.fsync(ledger_fd)
        summary = _build_summary(previous, event)
        atomic_write(summary_path, canonical(summary))
        print(canonical(summary).decode("utf-8"))
    finally:
        if ledger_fd is not None:
            os.close(ledger_fd)
        os.close(lock_fd)


def check_freshness(args):
    state_dir = validate_state_dir(args.state_dir)
    if args.kind not in KINDS:
        raise LedgerError("maintenance kind is invalid")
    if not 60 <= args.maximum_age_seconds <= 604800:
        raise LedgerError("freshness budget is out of range")
    if not 0 <= args.clock_skew_seconds <= 3600:
        raise LedgerError("clock skew budget is out of range")
    now_value = args.now or now_timestamp()
    now = parse_timestamp(now_value, "now")
    value = read_json(os.path.join(state_dir, f"latest-{args.kind}.json"), "maintenance summary")
    if value is None:
        payload = {
            "age_seconds": None,
            "budget_seconds": args.maximum_age_seconds,
            "format": FRESHNESS_FORMAT,
            "kind": args.kind,
            "last_success_at": None,
            "observed_at": None,
            "operation_id": None,
            "state": "never-run",
            "status": None,
        }
        print(canonical(payload).decode("utf-8"))
        return 20
    summary = validate_summary(value, args.kind)
    observed = parse_timestamp(summary["observed_at"], "observed_at")
    if observed > now + dt.timedelta(seconds=args.clock_skew_seconds):
        state = "clock-anomaly"
        age = None
        result = 50
    else:
        last_success = (
            parse_timestamp(summary["last_success_at"], "last_success_at")
            if summary["last_success_at"] is not None
            else None
        )
        if last_success is not None and last_success > now + dt.timedelta(seconds=args.clock_skew_seconds):
            state = "clock-anomaly"
            age = None
            result = 50
        elif summary["status"] in {"scheduled", "started", "heartbeat"}:
            progress_at = parse_timestamp(summary["heartbeat_at"] or summary["started_at"], "progress_at")
            progress_age = max(0, int((now - progress_at).total_seconds()))
            age = int((now - last_success).total_seconds()) if last_success is not None else None
            if progress_age > summary["deadline_seconds"] + args.clock_skew_seconds:
                state = "overdue"
                result = 40
            elif age is not None and age > args.maximum_age_seconds:
                state = "stale-running"
                result = 40
            else:
                state = "running"
                result = 0
        elif summary["status"] != "completed":
            state = summary["status"]
            age = int((now - last_success).total_seconds()) if last_success is not None else None
            result = 30
        elif last_success is None:
            state = "invalid"
            age = None
            result = 50
        else:
            age = int((now - last_success).total_seconds())
            state = "healthy" if age <= args.maximum_age_seconds else "stale"
            result = 0 if state == "healthy" else 40
    payload = {
        "age_seconds": age,
        "budget_seconds": args.maximum_age_seconds,
        "format": FRESHNESS_FORMAT,
        "kind": args.kind,
        "last_success_at": summary["last_success_at"],
        "observed_at": summary["observed_at"],
        "operation_id": summary["operation_id"],
        "state": state,
        "status": summary["status"],
    }
    print(canonical(payload).decode("utf-8"))
    return result


def notify_failure(args):
    state_dir = validate_state_dir(args.state_dir)
    if args.kind not in KINDS or not ID_RE.fullmatch(args.notification_id):
        raise LedgerError("maintenance failure notification identity is invalid")
    value = read_json(os.path.join(state_dir, f"latest-{args.kind}.json"), "maintenance summary")
    previous = validate_summary(value, args.kind) if value is not None else None
    if previous is not None and previous["operation_id"] == args.notification_id:
        if previous["status"] in TERMINAL_STATUSES:
            print(canonical(previous).decode("utf-8"))
            return
        started_at = previous["started_at"]
        deadline_seconds = previous["deadline_seconds"]
    else:
        started_at = now_timestamp()
        deadline_seconds = 0
    record_args = argparse.Namespace(
        artifact_generation=None,
        deadline_seconds=deadline_seconds,
        duration_seconds=0,
        input_bytes=None,
        input_count=None,
        kind=args.kind,
        operation_id=args.notification_id,
        output_bytes=None,
        output_count=None,
        reason="unit-failure",
        started_at=started_at,
        state_dir=state_dir,
        status="failed",
    )
    record(record_args)


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    record_parser = subparsers.add_parser("record")
    record_parser.add_argument("--state-dir", required=True)
    record_parser.add_argument("--operation-id", required=True)
    record_parser.add_argument("--kind", required=True, choices=sorted(KINDS))
    record_parser.add_argument("--status", required=True, choices=sorted(STATUSES))
    record_parser.add_argument("--reason", default="none")
    record_parser.add_argument("--started-at")
    record_parser.add_argument("--deadline-seconds", type=int, default=0)
    record_parser.add_argument("--duration-seconds", type=int)
    record_parser.add_argument("--input-count", type=int)
    record_parser.add_argument("--output-count", type=int)
    record_parser.add_argument("--input-bytes", type=int)
    record_parser.add_argument("--output-bytes", type=int)
    record_parser.add_argument("--artifact-generation", type=int)
    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--state-dir", required=True)
    check_parser.add_argument("--kind", required=True, choices=sorted(KINDS))
    check_parser.add_argument("--maximum-age-seconds", required=True, type=int)
    check_parser.add_argument("--clock-skew-seconds", default=300, type=int)
    check_parser.add_argument("--now")
    notify_parser = subparsers.add_parser("notify-failure")
    notify_parser.add_argument("--state-dir", required=True)
    notify_parser.add_argument("--kind", required=True, choices=sorted(KINDS))
    notify_parser.add_argument("--notification-id", required=True)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "record":
            record(args)
            return 0
        if args.command == "notify-failure":
            notify_failure(args)
            return 0
        return check_freshness(args)
    except (LedgerError, OSError) as exc:
        print(f"maintenance ledger error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
