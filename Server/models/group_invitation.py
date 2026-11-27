from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger, CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint,
    Index, Text, UniqueConstraint, Uuid, func, text,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.schema import Constraint

from Server.core.database import Base

ACTIVE_INVITATION = text("status IN ('pending', 'accepted', 'claimed')")


class GroupInvitation(Base):
    __tablename__: str = "group_invitations"
    __table_args__: tuple[Constraint | Index, ...] = (
        ForeignKeyConstraint(["group_id", "joined_epoch"], ["group_epochs.group_id", "group_epochs.epoch"]),
        UniqueConstraint("package_id", name="uq_group_invitations_package"),
        CheckConstraint(
            "status IN ('pending', 'accepted', 'declined', 'claimed', 'completed', 'expired')",
            name="ck_group_invitation_status",
        ),
        CheckConstraint("expires_at > created_at", name="ck_group_invitation_expiry"),
        CheckConstraint(
            "status NOT IN ('accepted', 'claimed', 'completed') OR package_id IS NOT NULL",
            name="ck_group_invitation_package",
        ),
        CheckConstraint(
            "status NOT IN ('claimed', 'completed') OR claimed_at IS NOT NULL",
            name="ck_group_invitation_claim_time",
        ),
        CheckConstraint(
            "(status = 'completed') = (joined_epoch IS NOT NULL)",
            name="ck_group_invitation_joined_epoch",
        ),
        Index(
            "uq_group_invitations_active", "group_id", "invitee_user_id", unique=True,
            postgresql_where=ACTIVE_INVITATION, sqlite_where=ACTIVE_INVITATION,
        ),
        Index("ix_group_invitations_invitee_status", "invitee_user_id", "status"),
        Index("ix_group_invitations_inviter_status", "inviter_user_id", "status"),
    )

    invitation_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    group_id: Mapped[str] = mapped_column(Text, ForeignKey("chat_groups.group_id"))
    inviter_user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.user_id"))
    invitee_user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.user_id"))
    status: Mapped[str] = mapped_column(Text, server_default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    package_id: Mapped[str | None] = mapped_column(Text, ForeignKey("key_packages.package_id"))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    joined_epoch: Mapped[int | None] = mapped_column(BigInteger)