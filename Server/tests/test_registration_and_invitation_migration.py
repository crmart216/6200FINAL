import os
from base64 import b64encode
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from psycopg import Error
from sqlalchemy import Connection, Engine, create_engine, insert, inspect, select, update
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from Server.core.config import DemoIdentity
from Server.core.database import Base
from Server.models import ApiCredential, ChatGroup, GroupEpoch, GroupInvitation, KeyPackage, User
from Server.tools.backfill_api_credentials import BackfillConflict, BackfillCounts, backfill

INITIAL = "0001_initial_schema"
HEAD = "0002_registration_invites"
NEW_TABLES = {"registration_challenges", "api_credentials", "group_invitations"}


def config(connection: Connection | None = None) -> Config:
    cfg = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    if connection is not None:
        cfg.attributes["connection"] = connection
    return cfg


@pytest.fixture
def migration_engine() -> Iterator[Engine]:
    if os.getenv("RUN_POSTGRES_TESTS") != "1":
        pytest.skip("Enable PostgreSQL to test upgrades and backfill")
    raw = os.getenv("SERVER_MIGRATION_TEST_URL")
    if not raw or make_url(raw).database != "chat_demo_migration_test":
        pytest.fail("Set SERVER_MIGRATION_TEST_URL to the disposable chat_demo_migration_test database")

    schema = "signup_" + uuid4().hex
    admin = create_engine(raw)
    engine = create_engine(raw, connect_args={"options": f"-c search_path={schema}"})
    try:
        with admin.begin() as conn:
            assert conn.exec_driver_sql("SELECT current_database()").scalar_one() == "chat_demo_migration_test"
            _ = conn.exec_driver_sql(f"CREATE SCHEMA {schema}")
        try:
            yield engine
        finally:
            engine.dispose()
            with admin.begin() as conn:
                _ = conn.exec_driver_sql(f"DROP SCHEMA {schema} CASCADE")
    finally:
        admin.dispose()


@pytest.fixture
def migrated(migration_engine: Engine) -> Engine:
    with migration_engine.begin() as conn:
        command.upgrade(config(conn), "head")
    return migration_engine


def user(user_id: str) -> User:
    return User(
        user_id=user_id, display_name=user_id, websocket_url="ws://example.test:8000",
        signing_public_key=b"k" * 32,
    )


def test_revision_and_metadata() -> None:
    scripts = ScriptDirectory.from_config(config())
    assert scripts.get_heads() == [HEAD]
    revision = scripts.get_revision(HEAD)
    assert revision is not None and revision.down_revision == INITIAL
    assert len(Base.metadata.tables) == 10
    assert NEW_TABLES <= Base.metadata.tables.keys()


@pytest.mark.parametrize("existing", [False, True], ids=["fresh", "existing"])
def test_upgrade_paths(migration_engine: Engine, existing: bool) -> None:
    with migration_engine.begin() as conn:
        cfg = config(conn)
        if existing:
            command.upgrade(cfg, INITIAL)
            _ = conn.execute(insert(User).values(
                user_id="alice", display_name="Alice", websocket_url="ws://example.test",
                signing_public_key=b"k" * 32,
            ))
            _ = conn.execute(insert(ChatGroup).values(
                group_id="chat", group_name="Original", founder_user_id="alice",
            ))

        command.upgrade(cfg, "head")
        assert MigrationContext.configure(conn).get_current_revision() == HEAD
        assert set(inspect(conn).get_table_names()) == set(Base.metadata.tables) | {"alembic_version"}
        if existing:
            assert conn.scalar(select(User.display_name)) == "Alice"
            assert conn.scalar(select(ChatGroup.group_name)) == "Original"
            command.downgrade(cfg, INITIAL)
            assert NEW_TABLES.isdisjoint(inspect(conn).get_table_names())
            assert conn.scalar(select(ChatGroup.group_name)) == "Original"


def test_invitation_constraints(migrated: Engine) -> None:
    with Session(migrated) as db, db.begin():
        db.add_all([user("alice"), user("bob")])
        db.flush()
        for group_id in ("first", "second"):
            db.add(ChatGroup(group_id=group_id, group_name=group_id, founder_user_id="alice"))
        db.flush()
        db.add_all([
            GroupEpoch(group_id="first", epoch=0),
            GroupEpoch(group_id="second", epoch=1),
            KeyPackage(
                package_id="package", owner_user_id="bob", credential=b"bob",
                init_public_key=b"init", leaf_public_key=b"leaf", signing_public_key=b"k" * 32,
                signature=b"signature",
            ),
        ])
        db.flush()

        now = datetime.now(UTC)
        first = uuid4()
        values = {
            "group_id": "first", "inviter_user_id": "alice", "invitee_user_id": "bob",
            "expires_at": now + timedelta(hours=1),
        }
        add = insert(GroupInvitation).values(**values)
        _ = db.execute(add.values(invitation_id=first))
        assert db.scalar(select(GroupInvitation.status)) == "pending"

        with pytest.raises(IntegrityError, match="uq_group_invitations_active"), db.begin_nested():
            _ = db.execute(add.values(invitation_id=uuid4()))

        _ = db.execute(update(GroupInvitation).where(GroupInvitation.invitation_id == first).values(
            status="expired", package_id="package",
        ))
        _ = db.execute(add.values(invitation_id=uuid4()))
        with pytest.raises(IntegrityError, match="uq_group_invitations_package"), db.begin_nested():
            _ = db.execute(add.values(
                invitation_id=uuid4(), group_id="second", status="accepted", package_id="package",
            ))

        _ = db.execute(update(GroupInvitation).where(GroupInvitation.invitation_id == first).values(
            package_id=None,
        ))
        with pytest.raises(IntegrityError) as error, db.begin_nested():
            _ = db.execute(add.values(
                invitation_id=uuid4(), status="completed", package_id="package",
                claimed_at=now, joined_epoch=1,
            ))
        assert isinstance(error.value.orig, Error)
        assert error.value.orig.sqlstate == "23503"


def identity(user_id: str, token: str, key: bytes = b"k" * 32) -> DemoIdentity:
    return DemoIdentity.model_validate({
        "user_id": user_id, "api_token": token,
        "signing_public_key_b64": b64encode(key).decode("ascii"),
    })


def test_backfill_insert_skip_and_retry(migrated: Engine) -> None:
    with Session(migrated) as db, db.begin():
        db.add(user("alice"))
    token = " test-☃ "
    identities = [identity("alice", token), identity("missing", "unused")]
    with Session(migrated) as db:
        assert backfill(db, identities) == BackfillCounts(1, 0, ("missing",))
        assert backfill(db, identities) == BackfillCounts(0, 1, ("missing",))
        rows = list(db.scalars(select(ApiCredential)))
        assert [(row.user_id, row.token_digest) for row in rows] == [
            ("alice", sha256(token.encode("utf-8")).digest())
        ]


@pytest.mark.parametrize(
    ("case", "reason"),
    [("key", "Signing key mismatch"), ("token", "Existing credential differs"),
     ("owner", "assigned to another user")],
)
def test_backfill_conflicts_roll_back(migrated: Engine, case: str, reason: str) -> None:
    token = "conflicting-token"
    existing = sha256(token.encode("utf-8")).digest() if case == "owner" else b"x" * 32
    owner = "existing" if case == "owner" else "zed"
    with Session(migrated) as db, db.begin():
        db.add_all([user("alice"), user("zed"), user("existing")])
        db.flush()
        if case != "key":
            db.add(ApiCredential(user_id=owner, token_digest=existing))

    identities = [identity("alice", "valid-token"), identity(
        "zed", token, b"z" * 32 if case == "key" else b"k" * 32,
    )]
    with Session(migrated) as db:
        with pytest.raises(BackfillConflict, match=reason) as error:
            _ = backfill(db, identities)
        assert token not in str(error.value)
        rows = list(db.scalars(select(ApiCredential)))
        assert [(row.user_id, row.token_digest) for row in rows] == (
            [] if case == "key" else [(owner, existing)]
        )


def test_duplicate_token_digest_is_rejected(migrated: Engine) -> None:
    with Session(migrated) as db, db.begin():
        db.add_all([user("alice"), user("bob")])
        db.flush()
        _ = db.execute(insert(ApiCredential).values(user_id="alice", token_digest=b"x" * 32))
        with pytest.raises(IntegrityError, match="uq_api_credentials_token_digest"), db.begin_nested():
            _ = db.execute(insert(ApiCredential).values(user_id="bob", token_digest=b"x" * 32))
