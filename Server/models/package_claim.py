from uuid import UUID

from sqlalchemy import ForeignKey, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.schema import Constraint

from Server.core.database import Base


class PackageClaim(Base):
    __tablename__: str = "package_claims"
    __table_args__: tuple[Constraint, ...] = (
        UniqueConstraint(
            "inviter_user_id",
            "request_id",
            name="uq_package_claims_inviter_request",
        ),
    )

    package_id: Mapped[str] = mapped_column(
        Text, ForeignKey("key_packages.package_id"), primary_key=True
    )
    inviter_user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.user_id"))
    request_id: Mapped[UUID] = mapped_column(Uuid)