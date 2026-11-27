import os
import subprocess
import sys
from pathlib import Path
from uuid import UUID

import pytest
from sqlalchemy import UniqueConstraint
from sqlalchemy.dialects.postgresql import dialect
from sqlalchemy.schema import CreateTable

from Server import models
from Server.core.database import Base


COLUMNS = {
    "users": {
        "user_id": "TEXT",
        "display_name": "TEXT",
        "websocket_url": "TEXT",
        "signing_public_key": "BYTEA",
    },
    "key_packages": {
        "package_id": "TEXT",
        "owner_user_id": "TEXT",
        "credential": "BYTEA",
        "init_public_key": "BYTEA",
        "leaf_public_key": "BYTEA",
        "signing_public_key": "BYTEA",
        "signature": "BYTEA",
    },
    "package_claims": {
        "package_id": "TEXT",
        "inviter_user_id": "TEXT",
        "request_id": "UUID",
    },
    "chat_groups": {
        "group_id": "TEXT",
        "group_name": "TEXT",
        "founder_user_id": "TEXT",
        "next_transcript_index": "BIGINT",
    },
    "group_epochs": {
        "group_id": "TEXT",
        "epoch": "BIGINT",
    },
    "epoch_members": {
        "group_id": "TEXT",
        "epoch": "BIGINT",
        "user_id": "TEXT",
    },
    "messages": {
        "group_id": "TEXT",
        "message_id": "UUID",
        "epoch": "BIGINT",
        "transcript_index": "BIGINT",
        "encrypted_sender_data": "BYTEA",
        "ciphertext": "BYTEA",
    },
}

PRIMARY_KEYS = {
    "users": ("user_id",),
    "key_packages": ("package_id",),
    "package_claims": ("package_id",),
    "chat_groups": ("group_id",),
    "group_epochs": ("group_id", "epoch"),
    "epoch_members": ("group_id", "epoch", "user_id"),
    "messages": ("group_id", "message_id"),
}

EPOCH_REFERENCE = (
    ("group_id", "group_epochs.group_id"),
    ("epoch", "group_epochs.epoch"),
)

FOREIGN_KEYS: dict[str, set[tuple[tuple[str, str], ...]]] = {
    "users": set(),
    "key_packages": {
        (("owner_user_id", "users.user_id"),),
    },
    "package_claims": {
        (("package_id", "key_packages.package_id"),),
        (("inviter_user_id", "users.user_id"),),
    },
    "chat_groups": {
        (("founder_user_id", "users.user_id"),),
    },
    "group_epochs": {
        (("group_id", "chat_groups.group_id"),),
    },
    "epoch_members": {
        EPOCH_REFERENCE,
        (("user_id", "users.user_id"),),
    },
    "messages": {EPOCH_REFERENCE},
}


def test_all_models_use_shared_metadata() -> None:
    assert set(Base.metadata.tables) == set(COLUMNS)

    classes = (
        models.User,
        models.KeyPackage,
        models.PackageClaim,
        models.ChatGroup,
        models.GroupEpoch,
        models.EpochMember,
        models.Message,
    )
    for cls in classes:
        assert cls.__table__ is Base.metadata.tables[cls.__tablename__]


@pytest.mark.parametrize("name", COLUMNS)
def test_required_columns_and_postgresql_types(name: str) -> None:
    table = Base.metadata.tables[name]
    ddl = str(CreateTable(table).compile(dialect=dialect()))
    assert set(table.columns.keys()) == set(COLUMNS[name])

    python_types = {"TEXT": str, "BYTEA": bytes, "BIGINT": int, "UUID": UUID}
    for column_name, sql_type in COLUMNS[name].items():
        column = table.c[column_name]
        assert column.nullable is False
        assert column.type.python_type is python_types[sql_type]
        assert column.type.compile(dialect=dialect()) == sql_type
        assert f"{column_name} {sql_type} " in ddl


@pytest.mark.parametrize("name", PRIMARY_KEYS)
def test_ordered_primary_keys(name: str) -> None:
    assert tuple(Base.metadata.tables[name].primary_key.columns.keys()) == PRIMARY_KEYS[name]


@pytest.mark.parametrize("name", FOREIGN_KEYS)
def test_foreign_keys_preserve_constraint_groups(name: str) -> None:
    constraints = Base.metadata.tables[name].foreign_key_constraints
    references = [
        tuple(
            (fk.parent.name, f"{fk.column.table.name}.{fk.column.name}")
            for fk in constraint.elements
        )
        for constraint in constraints
    ]

    assert len(references) == len(FOREIGN_KEYS[name])
    assert set(references) == FOREIGN_KEYS[name]


def test_retry_and_transcript_uniqueness() -> None:
    for name, expected in (
        ("package_claims", ("inviter_user_id", "request_id")),
        ("messages", ("group_id", "transcript_index")),
    ):
        assert [
            tuple(constraint.columns.keys())
            for constraint in Base.metadata.tables[name].constraints
            if isinstance(constraint, UniqueConstraint)
        ] == [expected]


def test_counter_checks_and_database_default() -> None:
    for name, condition in (
        ("chat_groups", "next_transcript_index > 0"),
        ("group_epochs", "epoch >= 0"),
        ("messages", "transcript_index > 0"),
    ):
        ddl = str(CreateTable(Base.metadata.tables[name]).compile(dialect=dialect()))
        assert f"CHECK ({condition})" in ddl

    ddl = str(CreateTable(Base.metadata.tables["chat_groups"]).compile(dialect=dialect()))
    assert "next_transcript_index BIGINT DEFAULT 1 NOT NULL" in ddl


def test_client_supplies_uuid_values() -> None:
    for name, column in (("messages", "message_id"), ("package_claims", "request_id")):
        assert Base.metadata.tables[name].c[column].default is None
        assert Base.metadata.tables[name].c[column].server_default is None


def test_models_import_and_compile_without_configuration() -> None:
    env = os.environ.copy()
    for key in ("SERVER_DATABASE_URL", "SERVER_DEMO_IDENTITIES"):
        _ = env.pop(key, None)

    code = """
from unittest.mock import patch
from sqlalchemy.dialects.postgresql import dialect
from sqlalchemy.schema import CreateTable

with patch("psycopg.connect", side_effect=AssertionError("Unexpected DB connection")):
    import Server.models
    from Server.core.database import Base

    assert len(Base.metadata.tables) == 7
    for table in Base.metadata.sorted_tables:
        assert "CREATE TABLE" in str(CreateTable(table).compile(dialect=dialect()))
"""
    _ = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        env=env,
        cwd=Path(__file__).resolve().parents[2],
    )