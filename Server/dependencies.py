from collections.abc import Generator
from dataclasses import dataclass
from hmac import compare_digest
from typing import Annotated

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import get_settings
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
        presented = credentials.credentials.encode()
        for identity in get_settings().demo_identities:
            if compare_digest(presented, identity.api_token.get_secret_value().encode()):
                return CurrentIdentity(identity.user_id, identity.signing_public_key)

    raise HTTPException(
        status_code=401,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )