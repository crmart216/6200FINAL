import base64
import json
import os
import subprocess
import sys
import traceback
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from Server.core import dependencies
from Server.core.config import get_settings
from Server.core.database import get_engine, get_session_factory
from Server.core.dependencies import CurrentIdentity, get_current_identity, get_db

from .test_user_directory_and_key_packages import engine as engine, seed_account


def clear_caches() -> None:
    get_session_factory.cache_clear()
    if get_engine.cache_info().currsize:
        get_engine().dispose()
    get_engine.cache_clear()
    get_settings.cache_clear()


@pytest.fixture
def identities(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[dict[str, str]]]:
    clear_caches()
    rows: list[dict[str, str]] = []

    for name in ("Alice", "Bob"):
        key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        rows.append({
            "user_id": name,
            "api_token": f"test-token-{name}",
            "signing_public_key_b64": base64.b64encode(key).decode(),
        })

    monkeypatch.setenv(
        "SERVER_DATABASE_URL",
        "postgresql+psycopg://demo:test-password@127.0.0.1:1/chat_demo",
    )
    monkeypatch.setenv("SERVER_DEMO_IDENTITIES", json.dumps(rows))

    try:
        yield rows
    finally:
        clear_caches()


def test_base_imports_without_server_configuration() -> None:
    env = os.environ.copy()
    for name in ("SERVER_DATABASE_URL", "SERVER_DEMO_IDENTITIES"):
        _ = env.pop(name, None)

    _ = subprocess.run(
        [sys.executable, "-c", "from Server.core.database import Base"],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        check=True,
    )


def test_settings_load_pinned_keys_and_mask_secrets(
    identities: list[dict[str, str]],
) -> None:
    settings = get_settings()
    assert settings is get_settings()
    assert [(i.user_id, i.signing_public_key) for i in settings.demo_identities] == [
        (row["user_id"], base64.b64decode(row["signing_public_key_b64"]))
        for row in identities
    ]

    for secret in ("test-password", *(row["api_token"] for row in identities)):
        assert secret not in repr(settings)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("signing_public_key_b64", "!", id="invalid-base64"),
        pytest.param("signing_public_key_b64", "YQ==", id="short-key"),
        pytest.param("user_id", "Alice", id="duplicate-user"),
        pytest.param("api_token", "test-token-Alice", id="duplicate-token"),
        pytest.param("user_id", " ", id="blank-user"),
        pytest.param("api_token", "", id="empty-token"),
    ],
)
def test_invalid_identity_rejected_without_secret_leak(
    identities: list[dict[str, str]],
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
) -> None:
    monkeypatch.setenv(
        "SERVER_DEMO_IDENTITIES",
        json.dumps([identities[0], identities[1] | {field: value}]),
    )

    with pytest.raises(ValueError) as error:
        _ = get_settings()

    message = "".join(traceback.format_exception(error.value))
    for secret in ("test-password", *(row["api_token"] for row in identities)):
        assert secret not in message


@pytest.mark.usefixtures("identities")
def test_cached_factory_creates_distinct_offline_sessions() -> None:
    engine = get_engine()
    factory = get_session_factory()

    assert engine is get_engine()
    assert factory is get_session_factory()

    with factory() as first, factory() as second:
        assert first is not second
        assert first.get_bind() is second.get_bind() is engine


@pytest.fixture
def session_events(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    events: list[str] = []

    class RecordingSession:
        def __init__(self) -> None:
            events.append("open")

        def rollback(self) -> None:
            events.append("rollback")

        def close(self) -> None:
            events.append("close")

    monkeypatch.setattr(
        "Server.core.dependencies.get_session_factory",
        lambda: RecordingSession,
    )
    return events


def test_successful_requests_each_close_their_session(session_events: list[str]) -> None:
    with contextmanager(get_db)() as first, contextmanager(get_db)() as second:
        assert first is not second

    assert session_events == ["open", "open", "close", "close"]


def test_failed_request_rolls_back_closes_and_propagates(session_events: list[str]) -> None:
    failure = RuntimeError("request failed")

    with pytest.raises(RuntimeError) as raised, contextmanager(get_db)():
        raise failure

    assert raised.value is failure
    assert session_events == ["open", "rollback", "close"]


@pytest.fixture
def client(
    engine: Engine, identities: list[dict[str, str]], monkeypatch: pytest.MonkeyPatch,
) -> Iterator[TestClient]:
    factory = sessionmaker(engine)
    with factory.begin() as db:
        for row in identities:
            seed_account(db, row["user_id"], base64.b64decode(row["signing_public_key_b64"]),
                         row["api_token"])
    monkeypatch.setattr(dependencies, "get_session_factory", lambda: factory)
    app = FastAPI()

    @app.get("/whoami")
    def whoami(
        identity: Annotated[CurrentIdentity, Depends(get_current_identity)],
    ) -> list[str]:
        return [identity.user_id, identity.signing_public_key.hex()]

    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.parametrize("index", [0, 1], ids=["alice", "bob"])
def test_bearer_token_returns_pinned_identity(
    client: TestClient,
    identities: list[dict[str, str]],
    index: int,
) -> None:
    row = identities[index]
    response = client.get(
        "/whoami",
        headers={"Authorization": "Bearer " + row["api_token"]},
    )

    assert response.status_code == 200
    assert response.json() == [
        row["user_id"],
        base64.b64decode(row["signing_public_key_b64"]).hex(),
    ]


@pytest.mark.usefixtures("identities")
@pytest.mark.parametrize(
    "header",
    [None, "Bearer", "Basic example", "Bearer unknown"],
    ids=["missing", "malformed", "wrong-scheme", "unknown"],
)
def test_invalid_credentials_receive_bearer_challenge(
    client: TestClient,
    header: str | None,
) -> None:
    headers = {} if header is None else {"Authorization": header}
    response = client.get("/whoami", headers=headers)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
