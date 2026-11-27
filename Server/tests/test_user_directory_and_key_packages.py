import os
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from Security.models.key_models.key_package import PublicKeyPackage
from Security.models.user import User as ClientUser
from Security.services.group_services.key_services.key_package_service import KeyPackageService
from Server.core import dependencies
from Server.core.database import Base
from Server.main import app
from Server.models import ApiCredential, KeyPackage, User
from Server.models.api_credential import digest_api_token
from Server.schemas.public_key_package import PublicKeyPackagePayload, encode_binary


@pytest.fixture
def engine(tmp_path: Path, request: pytest.FixtureRequest) -> Iterator[Engine]:
    if getattr(request, "param", "sqlite") == "sqlite":
        db = create_engine(f"sqlite:///{tmp_path / 'directory.db'}")
        try:
            Base.metadata.create_all(db)
            yield db
        finally:
            db.dispose()
        return

    if os.getenv("RUN_POSTGRES_TESTS") != "1":
        pytest.skip("Enable PostgreSQL to test independent concurrent sessions")

    raw = os.getenv("SERVER_MIGRATION_TEST_URL")
    if not raw or make_url(raw).database != "chat_demo_migration_test":
        pytest.fail(
            "Set SERVER_MIGRATION_TEST_URL to the disposable chat_demo_migration_test database"
        )

    schema = "directory_" + uuid4().hex
    admin = create_engine(raw)
    db = create_engine(raw, connect_args={"options": f"-c search_path={schema}"})

    try:
        with admin.begin() as conn:
            assert conn.scalar(select(func.current_database())) == "chat_demo_migration_test"
            _ = conn.exec_driver_sql(f"CREATE SCHEMA {schema}")

        try:
            with db.begin() as conn:
                cfg = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
                cfg.attributes["connection"] = conn
                command.upgrade(cfg, "head")
            yield db
        finally:
            db.dispose()
            with admin.begin() as conn:
                _ = conn.exec_driver_sql(f"DROP SCHEMA {schema} CASCADE")
    finally:
        admin.dispose()


@pytest.fixture
def bob() -> ClientUser:
    return ClientUser("bob", "Bob")


@pytest.fixture
def alice() -> ClientUser:
    return ClientUser("alice", "Alice")


@pytest.fixture
def client(
    engine: Engine,
    alice: ClientUser,
    bob: ClientUser,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[TestClient]:
    factory = sessionmaker(engine)
    with factory.begin() as db:
        for account in (alice, bob):
            seed_account(db, account.user_id, account.signing_key.public_key().public_bytes_raw(),
                         "test-" + account.user_id)
    monkeypatch.setattr(dependencies, "get_session_factory", lambda: factory)
    with TestClient(app) as c:
        yield c


def seed_account(db: Session, user_id: str, public_key: bytes, token: str) -> None:
    db.add(User(
        user_id=user_id, display_name=user_id.title(), websocket_url="ws://localhost:5555",
        signing_public_key=public_key,
    ))
    db.flush()
    db.add(ApiCredential(user_id=user_id, token_digest=digest_api_token(token)))


def auth(user: str) -> dict[str, str]:
    return {"Authorization": "Bearer test-" + user}


def register(c: TestClient, user: str, url: str = "ws://localhost:5555") -> None:
    response = c.put(
        "/api/users/" + user,
        headers=auth(user),
        json={"display_name": user.title(), "websocket_url": url},
    )
    assert response.status_code == 200


def publish(c: TestClient, package: PublicKeyPackage, owner: str = "bob") -> int:
    data = PublicKeyPackagePayload.model_validate(package, from_attributes=True)
    return c.put(
        f"/api/users/{owner}/key-packages/{package.package_id}",
        headers=auth(owner),
        json=data.model_dump(mode="json"),
    ).status_code


def test_discovery_and_access(client: TestClient, alice: ClientUser, bob: ClientUser) -> None:
    register(client, "bob")
    register(client, "alice")
    register(client, "bob", "wss://bob.local/chat")

    assert client.get("/api/users", headers=auth("alice")).json() == [
        {"user_id": "alice", "display_name": "Alice", "websocket_url": "ws://localhost:5555",
         "signing_public_key_b64": encode_binary(alice.signing_key.public_key().public_bytes_raw())},
        {"user_id": "bob", "display_name": "Bob", "websocket_url": "wss://bob.local/chat",
         "signing_public_key_b64": encode_binary(bob.signing_key.public_key().public_bytes_raw())},
    ]
    assert client.get("/api/users").status_code == 401
    assert client.get("/api/users", headers=auth("unknown")).status_code == 401

    body = {"display_name": "Bob", "websocket_url": "ws://bob.local"}
    assert client.put("/api/users/bob", headers=auth("alice"), json=body).status_code == 403

    package, = KeyPackageService().generate_packages(bob, b"bob", 1)
    assert publish(client, package, "alice") == 422
    data = PublicKeyPackagePayload.model_validate(package, from_attributes=True)
    path = "/api/users/bob/key-packages/" + package.package_id
    assert client.put(
        path, headers=auth("alice"), json=data.model_dump(mode="json")
    ).status_code == 403

    for change in (
        {"display_name": " "},
        {"websocket_url": "http://bob"},
        {"websocket_url": "ws://"},
    ):
        assert client.put(
            "/api/users/bob", headers=auth("bob"), json=body | change
        ).status_code == 422


def test_package_validation(client: TestClient, bob: ClientUser) -> None:
    package, = KeyPackageService().generate_packages(bob, b"bob", 1)
    assert publish(client, package, "unregistered") == 401

    register(client, "bob")
    body = PublicKeyPackagePayload.model_validate(
        package, from_attributes=True
    ).model_dump(mode="json")
    path = "/api/users/bob/key-packages/" + package.package_id

    for change in (
        {"credential": "%%%"},
        {"package_id": "different"},
        {"credential": "YQ=="},
    ):
        assert client.put(path, headers=auth("bob"), json=body | change).status_code == 422

    other, = KeyPackageService().generate_packages(ClientUser("bob", "Bob"), b"bob", 1)
    assert publish(client, other) == 422
    assert publish(client, replace(package, signature=bytes(64))) == 422


@pytest.mark.parametrize("engine", ["sqlite", "postgres"], indirect=True)
def test_directory_round_trip_and_retries(
    client: TestClient, alice: ClientUser, bob: ClientUser, engine: Engine
) -> None:
    register(client, "alice")
    register(client, "bob")
    first, second = KeyPackageService().generate_packages(bob, b"bob", 2)

    assert publish(client, first) == publish(client, first) == 200

    assert publish(client, second) == 200
    assert first.package_id in bob.private_packages

    changed = replace(second, package_id=first.package_id)
    assert publish(
        client, replace(changed, signature=bob.signing_key.sign(changed.serialize_unsigned()))
    ) == 409

    other, = KeyPackageService().generate_packages(alice, b"alice", 1)
    collision = replace(other, package_id=first.package_id)
    signed = replace(
        collision, signature=alice.signing_key.sign(collision.serialize_unsigned())
    )
    assert publish(client, signed, "alice") == 409

    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(KeyPackage)) == 2
        stored = db.get_one(KeyPackage, first.package_id)
        assert PublicKeyPackagePayload.model_validate(stored, from_attributes=True) == (
            PublicKeyPackagePayload.model_validate(first, from_attributes=True)
        )
