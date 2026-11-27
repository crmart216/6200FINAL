from collections.abc import Generator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..models import ApiCredential, User
from ..models.api_credential import digest_api_token
from .database import get_session_factory


@dataclass(frozen=True)
class CurrentIdentity:
    user_id: str
    signing_public_key: bytes


bearer = HTTPBearer(auto_error=False)


def get_db() -> Generator[Session, None, None]:
    factory = get_session_factory()
    session = factory()
    try:
        yield session
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()


def get_current_identity(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> CurrentIdentity:
    if credentials is not None and credentials.scheme.lower() == "bearer":
        digest = digest_api_token(credentials.credentials)
        try:
            with get_session_factory()() as db:
                user = db.scalar(
                    select(User)
                    .join(ApiCredential, ApiCredential.user_id == User.user_id)
                    .where(ApiCredential.token_digest == digest)
                )
                if user is not None:
                    return CurrentIdentity(user.user_id, user.signing_public_key)
        except SQLAlchemyError:
            raise HTTPException(503, "Authentication temporarily unavailable") from None

    raise HTTPException(
        status_code=401,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )