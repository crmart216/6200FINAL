"""Add registration challenges, API credentials, and group invitations."""

import sqlalchemy as sa
from alembic import op

revision = "0002_registration_invites"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    _ = op.create_table(
        "registration_challenges",
        sa.Column("challenge_id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("signing_public_key", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("length(signing_public_key) = 32", name="ck_registration_challenge_key_length"),
        sa.CheckConstraint("expires_at > created_at", name="ck_registration_challenge_expiry"),
    )
    _ = op.create_table(
        "api_credentials",
        sa.Column("user_id", sa.Text(), sa.ForeignKey("users.user_id"), primary_key=True),
        sa.Column("token_digest", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("token_digest", name="uq_api_credentials_token_digest"),
        sa.CheckConstraint("length(token_digest) = 32", name="ck_api_credential_digest_length"),
    )
    _ = op.create_table(
        "group_invitations",
        sa.Column("invitation_id", sa.Uuid(), primary_key=True),
        sa.Column("group_id", sa.Text(), sa.ForeignKey("chat_groups.group_id"), nullable=False),
        sa.Column("inviter_user_id", sa.Text(), sa.ForeignKey("users.user_id"), nullable=False),
        sa.Column("invitee_user_id", sa.Text(), sa.ForeignKey("users.user_id"), nullable=False),
        sa.Column("status", sa.Text(), server_default="pending", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("package_id", sa.Text(), sa.ForeignKey("key_packages.package_id"), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("joined_epoch", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(
            ["group_id", "joined_epoch"], ["group_epochs.group_id", "group_epochs.epoch"],
        ),
        sa.UniqueConstraint("package_id", name="uq_group_invitations_package"),
        sa.CheckConstraint(
            "status IN ('pending', 'accepted', 'declined', 'claimed', 'completed', 'expired')",
            name="ck_group_invitation_status",
        ),
        sa.CheckConstraint("expires_at > created_at", name="ck_group_invitation_expiry"),
        sa.CheckConstraint(
            "status NOT IN ('accepted', 'claimed', 'completed') OR package_id IS NOT NULL",
            name="ck_group_invitation_package",
        ),
        sa.CheckConstraint(
            "status NOT IN ('claimed', 'completed') OR claimed_at IS NOT NULL",
            name="ck_group_invitation_claim_time",
        ),
        sa.CheckConstraint(
            "(status = 'completed') = (joined_epoch IS NOT NULL)",
            name="ck_group_invitation_joined_epoch",
        ),
    )
    op.create_index(
        "uq_group_invitations_active", "group_invitations", ["group_id", "invitee_user_id"],
        unique=True, postgresql_where=sa.text("status IN ('pending', 'accepted', 'claimed')"),
    )
    op.create_index(
        "ix_group_invitations_invitee_status", "group_invitations", ["invitee_user_id", "status"],
    )
    op.create_index(
        "ix_group_invitations_inviter_status", "group_invitations", ["inviter_user_id", "status"],
    )


def downgrade() -> None:
    op.drop_table("group_invitations")
    op.drop_table("api_credentials")
    op.drop_table("registration_challenges")