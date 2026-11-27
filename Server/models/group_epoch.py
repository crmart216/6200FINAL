from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.schema import Constraint

from ..database import Base


class GroupEpoch(Base):
    __tablename__: str = "group_epochs"
    __table_args__: tuple[Constraint, ...] = (
        CheckConstraint("epoch >= 0", name="ck_group_epochs_nonnegative_epoch"),
    )

    group_id: Mapped[str] = mapped_column(
        Text, ForeignKey("chat_groups.group_id"), primary_key=True
    )
    epoch: Mapped[int] = mapped_column(BigInteger, primary_key=True)