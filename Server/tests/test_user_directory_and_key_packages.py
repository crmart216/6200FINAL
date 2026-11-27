import json
import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from Security.models.key_models.key_package import PublicKeyPackage
from Security.models.user import User as ClientUser
from Security.services.group_services.key_services.key_package_service import KeyPackageService
from Server.core.config import get_settings
from Server.core.database import Base
from Server.core.dependencies import get_db
from Server.main import app
from Server.models import PackageClaim
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
    identities = [
        {
            "user_id": u.user_id,
            "api_token": "test-" + u.user_id,
            "signing_public_key_b64": encode_binary(
                u.signing_key.public_key().public_bytes_raw()
            ),
        }
        for u in (alice, bob, ClientUser("eve", "Eve"))
    ]
    monkeypatch.setenv("SERVER_DEMO_IDENTITIES", json.dumps(identities))
    monkeypatch.setenv("SERVER_DATABASE_URL", "postgresql+psycopg://unused/test")
    get_settings.cache_clear()

    def sessions() -> Iterator[Session]:
        with Session(engine) as db:
            yield db

    monkeypatch.setitem(app.dependency_overrides, get_db, sessions)
    try:
        with TestClient(app) as c:
            yield c
    finally:
        get_settings.cache_clear()


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


def claim(c: TestClient, request_id: UUID, invitee: str = "bob"):
    return c.post(
        f"/api/users/{invitee}/key-packages/claims",
        headers=auth("alice"),
        json={"request_id": str(request_id)},
    )


def test_discovery_and_access(client: TestClient, bob: ClientUser) -> None:
    register(client, "bob")
    register(client, "alice")
    register(client, "bob", "wss://bob.local/chat")

    assert client.get("/api/users", headers=auth("alice")).json() == [
        {"user_id": "alice", "display_name": "Alice", "websocket_url": "ws://localhost:5555"},
        {"user_id": "bob", "display_name": "Bob", "websocket_url": "wss://bob.local/chat"},
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
    assert publish(client, package) == 404

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

    req = uuid4()
    response = claim(client, req)
    assert response.status_code == 200

    payload = PublicKeyPackagePayload.model_validate_json(response.content)
    assert payload == PublicKeyPackagePayload.model_validate(first, from_attributes=True)
    assert first.package_id in bob.private_packages

    assert publish(client, first) == 200
    assert claim(client, uuid4()).status_code == 409
    assert claim(client, uuid4(), "unknown").status_code == 404

    assert publish(client, second) == 200
    assert claim(client, req).json() == response.json()
    assert claim(client, req, "alice").status_code == 409

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
        assert db.scalar(select(func.count()).select_from(PackageClaim)) == 1


@pytest.mark.parametrize("engine", ["postgres"], indirect=True)
@pytest.mark.parametrize("scenario", ["different-requests", "retry", "different-invitees"])
def test_simultaneous_claims(
    client: TestClient,
    alice: ClientUser,
    bob: ClientUser,
    engine: Engine,
    scenario: str,
) -> None:
    register(client, "alice")
    register(client, "bob")
    package, = KeyPackageService().generate_packages(bob, b"bob", 1)
    assert publish(client, package) == 200

    first_id = uuid4()
    second_id = uuid4() if scenario == "different-requests" else first_id
    second_target = "bob"
    if scenario == "different-invitees":
        second_target = "alice"
        other, = KeyPackageService().generate_packages(alice, b"alice", 1)
        assert publish(client, other, "alice") == 200

    gate = Barrier(2)

    def send(request_id: UUID, invitee: str):
        _ = gate.wait(timeout=5)
        return claim(client, request_id, invitee)

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(send, first_id, "bob")
        b = pool.submit(send, second_id, second_target)
        results = [a.result(), b.result()]

    expected = [200, 200] if scenario == "retry" else [200, 409]
    assert sorted(r.status_code for r in results) == expected
    if scenario == "retry":
        assert results[0].json() == results[1].json()

    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(PackageClaim)) == 1