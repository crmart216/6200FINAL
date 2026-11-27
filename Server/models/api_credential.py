from datetime import datetime
from hashlib import sha256

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, LargeBinary, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.schema import Constraint

from Server.core.database import Base


def digest_api_token(token: str) -> bytes:
    """Hash the exact UTF-8 bearer token. Signup and authentication must use this function."""
    return sha256(token.encode("utf-8")).digest()


class ApiCredential(Base):
    __tablename__: str = "api_credentials"
    __table_args__: tuple[Constraint, ...] = (
        UniqueConstraint("token_digest", name="uq_api_credentials_token_digest"),
        CheckConstraint("length(token_digest) = 32", name="ck_api_credential_digest_length"),
    )

    user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.user_id"), primary_key=True)
    token_digest: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())