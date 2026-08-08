import hashlib
import json
from dataclasses import dataclass

from django.db import IntegrityError, transaction

from api.identifiers import InvalidIdentifier, parse_uuid
from api.models_work import ManagementBatchOperation

MANAGEMENT_OPERATION_RECEIPT_VERSION = 1
MAX_OPERATION_NAME_BYTES = 64
_BATCH_MUTATION_LOCK_NAMESPACE = (0x43414D45, 0x4C4C4941)  # ASCII "CAMELLIA"


class ManagementOperationConflict(RuntimeError):
    """An operation identifier is already bound to another request."""


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
    try:
        return parse_uuid(value)
    except InvalidIdentifier as exc:
        raise InvalidIdentifier("A canonical Idempotency-Key UUID is required") from exc


def canonical_document(value):
    try:
        return json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Management operation document is not canonical JSON") from exc


def document_digest(value):
    return hashlib.sha256(canonical_document(value)).hexdigest()


def _existing_result(existing, *, actor, operation, request_digest):
    if existing.actor_id != actor.pk or existing.operation != operation or existing.request_digest != request_digest:
        raise ManagementOperationConflict("Operation identifier is already in use")
    if (
        not isinstance(existing.response, dict)
        or isinstance(existing.status_code, bool)
        or not 500 > existing.status_code >= 200
    ):
        raise RuntimeError("Stored management operation receipt is invalid")
    return ManagementOperationResult(
        status_code=existing.status_code,
        body=existing.response,
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
    request_digest = document_digest(request_document)

    with transaction.atomic():
        try:
            with transaction.atomic():
                receipt = ManagementBatchOperation.objects.create(
                    operation_id=operation_id,
                    actor=actor,
                    operation=operation,
                    request_digest=request_digest,
                    status_code=200,
                    response={},
                )
        except IntegrityError:
            existing = ManagementBatchOperation.objects.select_for_update().filter(operation_id=operation_id).first()
            if existing is None:
                raise
            return _existing_result(
                existing,
                actor=actor,
                operation=operation,
                request_digest=request_digest,
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
            "management_operation_receipt_version": MANAGEMENT_OPERATION_RECEIPT_VERSION,
            "operation_id": str(operation_id),
            "operation": operation,
            "operation_generation": receipt.generation,
            "request_digest": request_digest,
            "result_digest": document_digest(outcome.result_state),
            "requested": requested,
            "applied": outcome.applied,
        }
        receipt.status_code = outcome.status_code
        receipt.response = body
        receipt.save(update_fields=("status_code", "response"))
        return ManagementOperationResult(status_code=outcome.status_code, body=body)
