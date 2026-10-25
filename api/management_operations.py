import hashlib
import json
import re
from dataclasses import dataclass

from django.db import IntegrityError, transaction

from api.identifiers import InvalidIdentifier, parse_uuid
from api.models_work import ManagementBatchOperation
from api.operation_intents import (
    canonical_document,
    new_private_binding,
    private_binding_matches,
    public_intent_digest,
    validate_private_binding,
)

MANAGEMENT_OPERATION_RECEIPT_VERSION = 2
OPERATION_KEY_PREFIX = "v2:"
MAX_OPERATION_NAME_BYTES = 64
MAX_PRIVATE_RECEIPT_BYTES = 4 * 1024 * 1024
_BATCH_MUTATION_LOCK_NAMESPACE = (0x43414D45, 0x4C4C4941)  # ASCII "CAMELLIA"
_MACHINE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class ManagementOperationConflict(RuntimeError):
    """An operation identifier is already bound to another request."""


class ManagementOperationRetired(ManagementOperationConflict):
    """An old unsafe receipt was retired, but its operation ID remains reserved."""


@dataclass(frozen=True)
class ManagementMutation:
    status_code: int
    body: dict
    applied: dict
    result_state: object


@dataclass(frozen=True)
class ManagementOperationResult:
    status_code: int
    body: dict


def operation_id_from_request(request):
    value = request.META.get("HTTP_IDEMPOTENCY_KEY")
    return parse_operation_key(value)


def operation_key(operation_id):
    return OPERATION_KEY_PREFIX + str(parse_operation_id(str(operation_id)))


def parse_operation_key(value):
    if not isinstance(value, str) or not value.startswith(OPERATION_KEY_PREFIX):
        raise InvalidIdentifier("A receipt-v2 Idempotency-Key is required")
    return parse_operation_id(value[len(OPERATION_KEY_PREFIX) :])


def parse_operation_id(value):
    try:
        parsed = parse_uuid(value)
    except InvalidIdentifier as exc:
        raise InvalidIdentifier("A canonical Idempotency-Key UUID is required") from exc
    if parsed.version != 4:
        raise InvalidIdentifier("Idempotency-Key must be a random UUIDv4")
    return parsed


def document_digest(value):
    return hashlib.sha256(canonical_document(value)).hexdigest()


def _private_receipt_document(*, binding, status_code, body):
    raw = canonical_document({"version": 2, "binding": binding, "status_code": status_code, "body": body})
    if len(raw) > MAX_PRIVATE_RECEIPT_BYTES:
        raise RuntimeError("Management operation receipt exceeds its storage budget")
    return raw.decode("utf-8")


def _existing_result(existing, *, actor, operation, request_document=None):
    if existing.actor_id != actor.pk or existing.operation != operation:
        raise ManagementOperationConflict("Operation identifier is already in use")
    if existing.receipt_version == 0:
        raise ManagementOperationRetired("Operation receipt retired; operation must not be repeated")
    if existing.receipt_version != MANAGEMENT_OPERATION_RECEIPT_VERSION:
        raise RuntimeError("Stored operation receipt version is unsupported")
    try:
        sealed = existing.secret_response
        if not isinstance(sealed, str) or not sealed or len(sealed) > MAX_PRIVATE_RECEIPT_BYTES:
            raise ValueError
        private = json.loads(sealed)
        if (
            not isinstance(private, dict)
            or set(private) != {"version", "binding", "status_code", "body"}
            or type(private["version"]) is not int
            or private["version"] != 2
            or type(private["status_code"]) is not int
            or private["status_code"] != existing.status_code
        ):
            raise ValueError
        validate_private_binding(private["binding"])
    except (TypeError, ValueError):
        raise RuntimeError("Stored private operation receipt is invalid") from None
    response = private["body"]
    if (
        not isinstance(response, dict)
        or isinstance(existing.status_code, bool)
        or not 500 > existing.status_code >= 200
        or response.get("operation_id") != str(existing.operation_id)
        or response.get("operation") != existing.operation
        or response.get("operation_generation") != existing.generation
        or type(response.get("management_operation_receipt_version")) is not int
        or response["management_operation_receipt_version"] != MANAGEMENT_OPERATION_RECEIPT_VERSION
        or response.get("request_digest") != existing.request_digest
    ):
        raise RuntimeError("Stored management operation receipt is invalid")
    if request_document is not None:
        if existing.request_digest != public_intent_digest(request_document) or not private_binding_matches(
            private["binding"],
            request_document,
            actor_id=actor.pk,
            operation_id=existing.operation_id,
            operation=operation,
        ):
            raise ManagementOperationConflict("Operation identifier is already in use")
    return ManagementOperationResult(
        status_code=existing.status_code,
        body=response,
    )


def find_management_operation(*, actor, operation_id):
    """Return one immutable receipt to its original actor for recovery."""

    existing = ManagementBatchOperation.objects.filter(
        operation_id=operation_id,
        actor=actor,
    ).first()
    if existing is None:
        return None
    return _existing_result(
        existing,
        actor=actor,
        operation=existing.operation,
    )


def _acquire_batch_mutation_lock():
    """Serialize low-frequency management batches before any target row lock."""

    connection = transaction.get_connection()
    if not connection.in_atomic_block:
        raise RuntimeError("Management batch mutation lock requires a transaction")
    if connection.vendor == "sqlite":
        return
    if connection.vendor != "postgresql":
        raise RuntimeError("Management batch mutation locking requires PostgreSQL")
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT pg_advisory_xact_lock(%s, %s)",
            _BATCH_MUTATION_LOCK_NAMESPACE,
        )


def execute_management_operation(
    *,
    actor,
    operation_id,
    operation,
    request_document,
    requested,
    mutation,
):
    if not isinstance(operation, str) or not operation or len(operation.encode("utf-8")) > MAX_OPERATION_NAME_BYTES:
        raise ValueError("Management operation name is invalid")
    if (
        not isinstance(requested, dict)
        or not requested
        or any(
            not isinstance(key, str) or not key or isinstance(count, bool) or not isinstance(count, int) or count < 0
            for key, count in requested.items()
        )
    ):
        raise ValueError("Management operation counts are invalid")
    request_digest = public_intent_digest(request_document)
    binding = new_private_binding(request_document, actor_id=actor.pk, operation_id=operation_id, operation=operation)

    with transaction.atomic():
        try:
            with transaction.atomic():
                receipt = ManagementBatchOperation.objects.create(
                    operation_id=operation_id,
                    actor=actor,
                    operation=operation,
                    request_digest=request_digest,
                    receipt_version=MANAGEMENT_OPERATION_RECEIPT_VERSION,
                    status_code=200,
                    secret_response=_private_receipt_document(binding=binding, status_code=200, body={}),
                )
        except IntegrityError:
            existing = ManagementBatchOperation.objects.select_for_update().filter(operation_id=operation_id).first()
            if existing is None:
                raise
            return _existing_result(
                existing,
                actor=actor,
                operation=operation,
                request_document=request_document,
            )

        _acquire_batch_mutation_lock()
        outcome = mutation()
        if (
            not isinstance(outcome, ManagementMutation)
            or not isinstance(outcome.body, dict)
            or not 500 > outcome.status_code >= 200
            or set(outcome.applied) != set(requested)
            or any(
                isinstance(count, bool) or not isinstance(count, int) or count < 0 or count > requested[key]
                for key, count in outcome.applied.items()
            )
        ):
            raise RuntimeError("Management operation produced an invalid outcome")
        body = {
            **outcome.body,
            "response_schema_version": 1,
            "management_operation_receipt_version": MANAGEMENT_OPERATION_RECEIPT_VERSION,
            "operation_id": str(operation_id),
            "operation": operation,
            "operation_generation": receipt.generation,
            "request_digest": request_digest,
            "result_digest": public_intent_digest(outcome.result_state),
            "requested": requested,
            "applied": outcome.applied,
        }
        if outcome.status_code < 400:
            body.setdefault("result", "OK")
        else:
            legacy_message = body.pop("error", None)
            body.pop("msg", None)
            code = body.get("code")
            if not isinstance(code, str) or _MACHINE_CODE.fullmatch(code) is None:
                body["code"] = "management_operation_failed"
            message = body.get("message") or legacy_message or "Management operation failed"
            body["message"] = str(message)[:256]
            body["retryable"] = bool(body.get("retryable", outcome.status_code in {408, 425, 429, 500, 502, 503, 504}))
        receipt.status_code = outcome.status_code
        receipt.secret_response = _private_receipt_document(binding=binding, status_code=outcome.status_code, body=body)
        receipt.save(update_fields=("status_code", "secret_response"))
        return ManagementOperationResult(status_code=outcome.status_code, body=body)
