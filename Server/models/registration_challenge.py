from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, LargeBinary, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.schema import Constraint

from Server.core.database import Base


class RegistrationChallenge(Base):
    __tablename__: str = "registration_challenges"
    __table_args__: tuple[Constraint, ...] = (
        CheckConstraint("length(signing_public_key) = 32", name="ck_registration_challenge_key_length"),
        CheckConstraint("expires_at > created_at", name="ck_registration_challenge_expiry"),
    )

    challenge_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    user_id: Mapped[str] = mapped_column(Text)
    signing_public_key: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))