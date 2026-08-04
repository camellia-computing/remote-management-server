import base64
import binascii
import datetime
import hashlib
import hmac
import secrets
from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from api.models import (
    DeviceProofChallenge,
    DeviceRecoveryApproval,
    LoginAdmissionLock,
    RemoteToken,
)

PROOF_VERSION = "camellia-device-proof-v1"
ASSERTION_VERSION = "camellia-deployment-assertion-v1"
MAX_DEPLOYMENT_GENERATION = (1 << 63) - 1
MAX_OUTSTANDING_CHALLENGES_PER_IP = 32
LOGIN_CHALLENGE_SECONDS = 120
OIDC_CHALLENGE_SECONDS = 300
DEPLOY_CHALLENGE_SECONDS = 120
RECOVERY_APPROVAL_SECONDS = 600
ASSERTION_SECONDS = 30


class DeviceProofError(Exception):
    pass


class DeviceRecoveryRequired(DeviceProofError):
    pass


@dataclass(frozen=True)
class ProofResult:
    public_key_hash: str
    identity_changed: bool = False
    recovered: bool = False


def decode_canonical_base64(value, expected_length):
    if not isinstance(value, str) or not value or len(value) > 512:
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(decoded) != expected_length:
        return None
    if base64.b64encode(decoded).decode("ascii") != value:
        return None
    return decoded


def public_key_hash(public_key):
    return hashlib.sha256(public_key).hexdigest()


def _token_hash(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _challenge_seconds(purpose):
    return {
        DeviceProofChallenge.PURPOSE_LOGIN: LOGIN_CHALLENGE_SECONDS,
        DeviceProofChallenge.PURPOSE_OIDC: OIDC_CHALLENGE_SECONDS,
        DeviceProofChallenge.PURPOSE_DEPLOY: DEPLOY_CHALLENGE_SECONDS,
    }[purpose]


def proof_message(code, purpose, rid, device_uuid, generation, key_hash, expires_at):
    return "\n".join(
        (
            PROOF_VERSION,
            purpose,
            code,
            rid,
            device_uuid,
            str(generation),
            key_hash,
            str(int(expires_at.timestamp())),
        )
    )


def issue_proof_challenge(*, purpose, rid, device_uuid, public_key_text, request_ip, device=None, user=None):
    if purpose not in dict(DeviceProofChallenge.PURPOSE_CHOICES):
        raise DeviceProofError("Unsupported proof purpose")
    public_key = decode_canonical_base64(public_key_text, 32)
    if public_key is None:
        raise DeviceProofError("Invalid public key")
    if purpose == DeviceProofChallenge.PURPOSE_DEPLOY and (not user or not device):
        raise DeviceProofError("Deployment challenge requires a device session")

    now = timezone.now()
    expires_at = (now + datetime.timedelta(seconds=_challenge_seconds(purpose))).replace(microsecond=0)
    key_hash = public_key_hash(public_key)
    generation = device.deployment_generation if device else 0
    code = secrets.token_urlsafe(32)
    with transaction.atomic():
        LoginAdmissionLock.objects.bulk_create(
            [LoginAdmissionLock(ip=request_ip)],
            ignore_conflicts=True,
        )
        admission_lock = LoginAdmissionLock.objects.select_for_update().filter(ip=request_ip).first()
        if not admission_lock:
            raise DeviceProofError("Proof challenge admission is unavailable")
        DeviceProofChallenge.objects.filter(expires_at__lte=now).delete()
        outstanding = DeviceProofChallenge.objects.filter(
            request_ip=request_ip,
            expires_at__gt=now,
        ).count()
        if outstanding >= MAX_OUTSTANDING_CHALLENGES_PER_IP:
            raise DeviceProofError("Too many outstanding proof challenges")
        DeviceProofChallenge.objects.create(
            code_hash=_token_hash(code),
            purpose=purpose,
            rid=rid,
            device_uuid=device_uuid,
            public_key_hash=key_hash,
            deployment_generation=generation,
            device=device,
            subject_user=user if purpose == DeviceProofChallenge.PURPOSE_DEPLOY else None,
            request_ip=request_ip,
            expires_at=expires_at,
        )
        admission_lock.updated_at = now
        admission_lock.save(update_fields=("updated_at",))
    return {
        "challenge": code,
        "message": proof_message(code, purpose, rid, device_uuid, generation, key_hash, expires_at),
        "expires_at": int(expires_at.timestamp()),
    }


def _verify_detached(message, public_key, signature):
    try:
        VerifyKey(public_key).verify(message.encode("utf-8"), signature)
    except (BadSignatureError, ValueError, TypeError) as exc:
        raise DeviceProofError("Invalid device proof") from exc


def _locked_challenge(
    proof,
    *,
    purpose,
    device,
    user,
    expected_rid=None,
    expected_device_uuid=None,
):
    if not isinstance(proof, dict):
        raise DeviceProofError("Device proof is required")
    code = proof.get("challenge")
    public_key = decode_canonical_base64(proof.get("public_key"), 32)
    signature = decode_canonical_base64(proof.get("signature"), 64)
    if not isinstance(code, str) or not code or len(code) > 128 or public_key is None or signature is None:
        raise DeviceProofError("Invalid device proof")
    challenge = DeviceProofChallenge.objects.select_for_update().filter(code_hash=_token_hash(code)).first()
    now = timezone.now()
    if not challenge or challenge.expires_at <= now:
        raise DeviceProofError("Device proof expired")
    if challenge.purpose != purpose:
        raise DeviceProofError("Device proof purpose mismatch")
    expected_rid = device.rid if expected_rid is None else expected_rid
    expected_device_uuid = device.uuid if expected_device_uuid is None else expected_device_uuid
    if challenge.rid != expected_rid or challenge.device_uuid != expected_device_uuid:
        raise DeviceProofError("Device proof identity mismatch")
    if challenge.device_id and challenge.device_id != device.pk:
        raise DeviceProofError("Device proof target mismatch")
    if challenge.subject_user_id and challenge.subject_user_id != user.pk:
        raise DeviceProofError("Device proof subject mismatch")
    if challenge.deployment_generation != device.deployment_generation:
        raise DeviceProofError("Device proof generation is stale")
    key_hash = public_key_hash(public_key)
    if not secrets.compare_digest(challenge.public_key_hash, key_hash):
        raise DeviceProofError("Device proof key mismatch")
    message = proof_message(
        code,
        challenge.purpose,
        challenge.rid,
        challenge.device_uuid,
        challenge.deployment_generation,
        challenge.public_key_hash,
        challenge.expires_at,
    )
    _verify_detached(message, public_key, signature)
    return challenge, message, public_key, key_hash


def _consume_recovery(device, key_hash, now):
    approval = (
        DeviceRecoveryApproval.objects.select_for_update()
        .filter(
            device=device,
            public_key_hash=key_hash,
            consumed_at__isnull=True,
            expires_at__gt=now,
        )
        .order_by("-created_at")
        .first()
    )
    if not approval:
        raise DeviceRecoveryRequired("Administrator recovery approval is required")
    approval.consumed_at = now
    approval.save(update_fields=("consumed_at",))
    return approval


def consume_session_proof(*, proof, purpose, device, user):
    """Consume current-key proof, or a one-use approved lost-key recovery."""

    if not device.public_key_hash:
        # Account authentication may create an undeployed controller/device
        # row. Its first authoritative key binding happens in deploy.
        if proof:
            challenge, _message, _public_key, key_hash = _locked_challenge(
                proof,
                purpose=purpose,
                device=device,
                user=user,
            )
            challenge.delete()
            return ProofResult(public_key_hash=key_hash)
        return ProofResult(public_key_hash="")
    challenge, _message, _public_key, key_hash = _locked_challenge(
        proof,
        purpose=purpose,
        device=device,
        user=user,
    )
    if secrets.compare_digest(device.public_key_hash, key_hash):
        challenge.delete()
        return ProofResult(public_key_hash=key_hash)

    if device.deployment_generation >= MAX_DEPLOYMENT_GENERATION:
        raise DeviceProofError("Deployment generation exhausted")
    now = timezone.now()
    _consume_recovery(device, key_hash, now)
    device.public_key_hash = key_hash
    device.deployment_generation += 1
    device.save(update_fields=("public_key_hash", "deployment_generation", "update_time"))
    RemoteToken.objects.filter(device=device).delete()
    challenge.delete()
    return ProofResult(public_key_hash=key_hash, identity_changed=True, recovered=True)


def consume_deployment_proof(*, proof, device, user, new_rid, new_uuid):
    challenge, message, _public_key, key_hash = _locked_challenge(
        proof,
        purpose=DeviceProofChallenge.PURPOSE_DEPLOY,
        device=device,
        user=user,
        expected_rid=new_rid,
        expected_device_uuid=new_uuid,
    )

    old_hash = device.public_key_hash or ""
    identity_changed = device.rid != new_rid or device.uuid != new_uuid or old_hash != key_hash
    recovered = False
    if old_hash and not secrets.compare_digest(old_hash, key_hash):
        if device.deployment_generation >= MAX_DEPLOYMENT_GENERATION:
            raise DeviceProofError("Deployment generation exhausted")
        old_public_key = decode_canonical_base64(proof.get("old_public_key"), 32)
        old_signature = decode_canonical_base64(proof.get("old_signature"), 64)
        old_proof_valid = bool(
            old_public_key is not None
            and old_signature is not None
            and secrets.compare_digest(public_key_hash(old_public_key), old_hash)
        )
        if old_proof_valid:
            _verify_detached(message, old_public_key, old_signature)
        else:
            _consume_recovery(device, key_hash, timezone.now())
            recovered = True

    if identity_changed:
        if device.deployment_generation >= MAX_DEPLOYMENT_GENERATION:
            raise DeviceProofError("Deployment generation exhausted")
        device.deployment_generation += 1
    device.rid = new_rid
    device.uuid = new_uuid
    device.public_key_hash = key_hash
    challenge.delete()
    return ProofResult(
        public_key_hash=key_hash,
        identity_changed=identity_changed,
        recovered=recovered,
    )


def create_recovery_approval(*, device, public_key_text, admin_user):
    public_key = decode_canonical_base64(public_key_text, 32)
    if public_key is None:
        raise DeviceProofError("Invalid public key")
    now = timezone.now()
    expires_at = (now + datetime.timedelta(seconds=RECOVERY_APPROVAL_SECONDS)).replace(microsecond=0)
    key_hash = public_key_hash(public_key)
    with transaction.atomic():
        DeviceRecoveryApproval.objects.select_for_update().filter(
            device=device,
            consumed_at__isnull=True,
        ).update(consumed_at=now)
        approval = DeviceRecoveryApproval.objects.create(
            device=device,
            public_key_hash=key_hash,
            approved_by=admin_user,
            expires_at=expires_at,
        )
    return approval


def deployment_assertion(*, secret, rid, device_uuid, key_hash, generation, request_nonce):
    nonce = decode_canonical_base64(request_nonce, 32)
    if nonce is None:
        raise DeviceProofError("Invalid assertion nonce")
    expires_at = int((timezone.now() + datetime.timedelta(seconds=ASSERTION_SECONDS)).timestamp())
    message = "\n".join(
        (
            ASSERTION_VERSION,
            rid,
            device_uuid,
            key_hash,
            str(generation),
            request_nonce,
            str(expires_at),
        )
    )
    signature = hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).digest()
    return {
        "version": 1,
        "deployment_generation": generation,
        "request_nonce": request_nonce,
        "expires_at": expires_at,
        "assertion": base64.b64encode(signature).decode("ascii"),
    }
