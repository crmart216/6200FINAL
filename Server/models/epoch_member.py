from sqlalchemy import BigInteger, ForeignKey, ForeignKeyConstraint, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.schema import Constraint

from ..database import Base


class EpochMember(Base):
    __tablename__: str = "epoch_members"
    __table_args__: tuple[Constraint, ...] = (
        ForeignKeyConstraint(
            ["group_id", "epoch"],
            ["group_epochs.group_id", "group_epochs.epoch"],
        ),
    )

    group_id: Mapped[str] = mapped_column(Text, primary_key=True)
    epoch: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    user_id: Mapped[str] = mapped_column(
        Text, ForeignKey("users.user_id"), primary_key=True
    )