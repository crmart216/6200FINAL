"""Create the seven group chat tables."""

from alembic import op
import sqlalchemy as sa

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    _ = op.create_table(
        "users",
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("websocket_url", sa.Text(), nullable=False),
        sa.Column("signing_public_key", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint("user_id"),
    )

    _ = op.create_table(
        "key_packages",
        sa.Column("package_id", sa.Text(), nullable=False),
        sa.Column("owner_user_id", sa.Text(), sa.ForeignKey("users.user_id"), nullable=False),
        sa.Column("credential", sa.LargeBinary(), nullable=False),
        sa.Column("init_public_key", sa.LargeBinary(), nullable=False),
        sa.Column("leaf_public_key", sa.LargeBinary(), nullable=False),
        sa.Column("signing_public_key", sa.LargeBinary(), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint("package_id"),
    )

    _ = op.create_table(
        "package_claims",
        sa.Column(
            "package_id", sa.Text(), sa.ForeignKey("key_packages.package_id"), nullable=False
        ),
        sa.Column("inviter_user_id", sa.Text(), sa.ForeignKey("users.user_id"), nullable=False),
        sa.Column("request_id", sa.Uuid(), nullable=False),
        sa.PrimaryKeyConstraint("package_id"),
        sa.UniqueConstraint(
            "inviter_user_id", "request_id", name="uq_package_claims_inviter_request"
        ),
    )

    _ = op.create_table(
        "chat_groups",
        sa.Column("group_id", sa.Text(), nullable=False),
        sa.Column("group_name", sa.Text(), nullable=False),
        sa.Column("founder_user_id", sa.Text(), sa.ForeignKey("users.user_id"), nullable=False),
        sa.Column(
            "next_transcript_index", sa.BigInteger(), server_default=sa.text("1"), nullable=False
        ),
        sa.PrimaryKeyConstraint("group_id"),
        sa.CheckConstraint(
            "next_transcript_index > 0", name="ck_chat_groups_positive_next_index"
        ),
    )

    _ = op.create_table(
        "group_epochs",
        sa.Column("group_id", sa.Text(), sa.ForeignKey("chat_groups.group_id"), nullable=False),
        sa.Column("epoch", sa.BigInteger(), nullable=False),
        sa.PrimaryKeyConstraint("group_id", "epoch"),
        sa.CheckConstraint("epoch >= 0", name="ck_group_epochs_nonnegative_epoch"),
    )

    _ = op.create_table(
        "epoch_members",
        sa.Column("group_id", sa.Text(), nullable=False),
        sa.Column("epoch", sa.BigInteger(), nullable=False),
        sa.Column("user_id", sa.Text(), sa.ForeignKey("users.user_id"), nullable=False),
        sa.PrimaryKeyConstraint("group_id", "epoch", "user_id"),
        sa.ForeignKeyConstraint(
            ["group_id", "epoch"], ["group_epochs.group_id", "group_epochs.epoch"]
        ),
    )

    _ = op.create_table(
        "messages",
        sa.Column("group_id", sa.Text(), nullable=False),
        sa.Column("message_id", sa.Uuid(), nullable=False),
        sa.Column("epoch", sa.BigInteger(), nullable=False),
        sa.Column("transcript_index", sa.BigInteger(), nullable=False),
        sa.Column("encrypted_sender_data", sa.LargeBinary(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint("group_id", "message_id"),
        sa.ForeignKeyConstraint(
            ["group_id", "epoch"], ["group_epochs.group_id", "group_epochs.epoch"]
        ),
        sa.UniqueConstraint(
            "group_id", "transcript_index", name="uq_messages_group_transcript_index"
        ),
        sa.CheckConstraint("transcript_index > 0", name="ck_messages_positive_transcript_index"),
    )


def downgrade() -> None:
    op.drop_table("messages")
    op.drop_table("epoch_members")
    op.drop_table("group_epochs")
    op.drop_table("chat_groups")
    op.drop_table("package_claims")
    op.drop_table("key_packages")
    op.drop_table("users")