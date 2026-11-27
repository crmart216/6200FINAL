from uuid import UUID

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKeyConstraint,
    LargeBinary,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.schema import Constraint

from Server.core.database import Base


class Message(Base):
    __tablename__: str = "messages"
    __table_args__: tuple[Constraint, ...] = (
        ForeignKeyConstraint(
            ["group_id", "epoch"],
            ["group_epochs.group_id", "group_epochs.epoch"],
        ),
        UniqueConstraint(
            "group_id",
            "transcript_index",
            name="uq_messages_group_transcript_index",
        ),
        CheckConstraint(
            "transcript_index > 0",
            name="ck_messages_positive_transcript_index",
        ),
    )

    group_id: Mapped[str] = mapped_column(Text, primary_key=True)
    message_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    epoch: Mapped[int] = mapped_column(BigInteger)
    transcript_index: Mapped[int] = mapped_column(BigInteger)
    encrypted_sender_data: Mapped[bytes] = mapped_column(LargeBinary)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)