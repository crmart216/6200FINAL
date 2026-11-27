from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, Text, text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.schema import Constraint

from Server.core.database import Base


class ChatGroup(Base):
    __tablename__: str = "chat_groups"
    __table_args__: tuple[Constraint, ...] = (
        CheckConstraint(
            "next_transcript_index > 0",
            name="ck_chat_groups_positive_next_index",
        ),
    )

    group_id: Mapped[str] = mapped_column(Text, primary_key=True)
    group_name: Mapped[str] = mapped_column(Text)
    founder_user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.user_id"))
    next_transcript_index: Mapped[int] = mapped_column(
        BigInteger, server_default=text("1")
    )