from datetime import UTC, datetime, timedelta
from secrets import token_bytes, token_urlsafe
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from ..models import ApiCredential, RegistrationChallenge, User
from ..models.api_credential import digest_api_token
from ..schemas.registration_challenge_request import RegistrationChallengeRequest
from ..schemas.registration_challenge_response import RegistrationChallengeResponse
from ..schemas.registration_request import RegistrationRequest
from ..schemas.registration_response import RegistrationResponse
from ..schemas.user_response import UserResponse

CHALLENGE_LIFETIME = timedelta(minutes=5)


class InvalidChallenge(Exception):
    pass


class UserIdTaken(Exception):
    pass


class TokenCollision(Exception):
    pass


def issue(db: Session, request: RegistrationChallengeRequest) -> RegistrationChallengeResponse:
    now = datetime.now(UTC)
    response = RegistrationChallengeResponse(
        challenge_id=uuid4(), challenge_b64=token_bytes(32), expires_at=now + CHALLENGE_LIFETIME,
    )
    with db.begin():
        db.add(RegistrationChallenge(
            challenge_id=response.challenge_id, user_id=request.user_id,
            signing_public_key=request.signing_public_key_b64, nonce=response.challenge_b64,
            created_at=now, expires_at=response.expires_at,
        ))
    return response


def proof_bytes(request: RegistrationRequest, nonce: bytes) -> bytes:
    fields = (
        b"6200 registration v1",
        str(request.challenge_id).encode("utf-8"),
        nonce,
        request.user_id.encode("utf-8"),
        request.display_name.encode("utf-8"),
        request.websocket_url.encode("utf-8"),
        request.signing_public_key_b64,
    )
    return b"".join(len(field).to_bytes(4, "big") + field for field in fields)


def register(db: Session, request: RegistrationRequest) -> RegistrationResponse:
    with db.begin():
        challenge = db.get(RegistrationChallenge, request.challenge_id, with_for_update=True)
        now = datetime.now(UTC)
        if (
            challenge is None or challenge.consumed_at is not None or challenge.expires_at <= now
            or challenge.user_id != request.user_id
            or challenge.signing_public_key != request.signing_public_key_b64
        ):
            raise InvalidChallenge

        key = Ed25519PublicKey.from_public_bytes(challenge.signing_public_key)
        try:
            key.verify(request.proof_signature_b64, proof_bytes(request, challenge.nonce))
        except InvalidSignature:
            raise InvalidChallenge from None

        user = db.scalars(
            insert(User).values(
                user_id=request.user_id, display_name=request.display_name,
                websocket_url=request.websocket_url, signing_public_key=challenge.signing_public_key,
            ).on_conflict_do_nothing(index_elements=[User.user_id]).returning(User)
        ).one_or_none()
        if user is None:
            raise UserIdTaken

        token = token_urlsafe(32)
        credential = insert(ApiCredential).values(
            user_id=user.user_id, token_digest=digest_api_token(token),
        ).on_conflict_do_nothing().returning(ApiCredential.user_id)
        if db.scalar(credential) is None:
            raise TokenCollision

        challenge.consumed_at = now
        response = RegistrationResponse(
            user=UserResponse.model_validate(user, from_attributes=True), api_token=token,
        )
    return response


def prune_expired(db: Session) -> int:
    with db.begin():
        result = db.connection().execute(delete(RegistrationChallenge).where(
            RegistrationChallenge.expires_at <= datetime.now(UTC)
        ))
        return result.rowcount
