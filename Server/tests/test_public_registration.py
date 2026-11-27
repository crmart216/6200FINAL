import struct
from base64 import b64encode
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Barrier
from uuid import UUID, uuid4
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from Server.core import dependencies
from Server.core.config import DemoIdentity, get_settings
from Server.main import app
from Server.models import ApiCredential, RegistrationChallenge, User
from Server.routes import registrations
from Server.schemas.registration_challenge_response import RegistrationChallengeResponse
from Server.services import registration
from Server.tools.backfill_api_credentials import BackfillCounts, backfill

from .test_user_directory_and_key_packages import engine as engine, seed_account

CHALLENGES = "/api/registration-challenges"
SIGNUP = "/api/registrations"


@pytest.fixture
def client(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("SERVER_DATABASE_URL", "postgresql+psycopg://unused/test")
    monkeypatch.delenv("SERVER_DEMO_IDENTITIES", raising=False)
    monkeypatch.setenv("SERVER_PUBLIC_SIGNUP_ENABLED", "true")
    monkeypatch.setattr(dependencies, "get_session_factory", lambda: sessionmaker(engine))
    monkeypatch.setattr(registrations, "challenge_limit", registrations.PeerRateLimit(20))
    monkeypatch.setattr(registrations, "registration_limit", registrations.PeerRateLimit(10))

    get_settings.cache_clear()
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        get_settings.cache_clear()


def b64(value: bytes) -> str:
    return b64encode(value).decode("ascii")


def key_b64(key: Ed25519PrivateKey) -> str:
    return b64(key.public_key().public_bytes_raw())


def signed_request(
    client: TestClient, key: Ed25519PrivateKey, user_id: str = "alice",
) -> dict[str, str]:
    target = {"user_id": user_id, "signing_public_key_b64": key_b64(key)}
    response = client.post(CHALLENGES, json=target)
    assert response.status_code == 201
    reply = RegistrationChallengeResponse.model_validate_json(response.content)
    challenge_id = str(reply.challenge_id)
    nonce = reply.challenge_b64
    assert len(nonce) == 32

    fields = [
        "6200 registration v1".encode(), challenge_id.encode(), nonce, user_id.encode(),
        "Alice ☃".encode(), b"wss://peer.example/socket?name=Alice",
        key.public_key().public_bytes_raw(),
    ]
    proof = b"".join(struct.pack("!I", len(field)) + field for field in fields)
    return target | {
        "challenge_id": challenge_id, "display_name": "  Alice ☃  ",
        "websocket_url": "wss://peer.example/socket?name=Alice",
        "proof_signature_b64": b64(key.sign(proof)),
    }


@pytest.mark.parametrize("engine", ["postgres"], indirect=True)
def test_new_token_authenticates_and_challenge_is_single_use(client: TestClient, engine: Engine) -> None:
    request = signed_request(client, Ed25519PrivateKey.generate(), user_id="alice-é")
    created = client.post(SIGNUP, json=request)
    assert created.status_code == 201
    assert created.headers["Cache-Control"] == "no-store"
    assert created.json()["token_type"] == "Bearer"
    token = cast(str, created.json()["api_token"])
    assert isinstance(token, str) and token
    profile = {
        "user_id": "alice-é", "display_name": "Alice ☃", "websocket_url": request["websocket_url"],
        "signing_public_key_b64": request["signing_public_key_b64"],
    }
    assert created.json()["user"] == profile
    directory = client.get("/api/users", headers={"Authorization": f"Bearer {token}"})
    assert directory.status_code == 200 and directory.json() == [profile]
    with Session(engine) as db:
        credential = db.get_one(ApiCredential, "alice-é")
        assert credential.token_digest == sha256(token.encode()).digest()
        assert db.get_one(RegistrationChallenge, UUID(request["challenge_id"])).consumed_at is not None
    assert client.post(SIGNUP, json=request).status_code == 422


@pytest.mark.parametrize("engine", ["postgres"], indirect=True)
def test_invalid_proofs_leave_challenge_unconsumed(client: TestClient, engine: Engine) -> None:
    request = signed_request(client, Ed25519PrivateKey.generate())
    for changes in (
        {"proof_signature_b64": b64(bytes(64))}, {"proof_signature_b64": "!"},
        {"proof_signature_b64": b64(bytes(63))},
        {"display_name": "Someone else"}, {"websocket_url": "wss://other.example"},
        {"websocket_url": "https://other.example"},
        {"signing_public_key_b64": key_b64(Ed25519PrivateKey.generate())},
        {"user_id": "bob"}, {"challenge_id": str(uuid4())},
    ):
        assert client.post(SIGNUP, json=request | changes).status_code == 422
    with Session(engine) as db:
        challenge = db.get_one(RegistrationChallenge, UUID(request["challenge_id"]))
        assert challenge.consumed_at is None
        assert db.scalars(select(User)).all() == []
        assert db.scalars(select(ApiCredential)).all() == []


@pytest.mark.parametrize("engine", ["postgres"], indirect=True)
def test_expiry_and_pruning_preserve_live_challenges(client: TestClient, engine: Engine) -> None:
    key = Ed25519PrivateKey.generate()
    expired = signed_request(client, key)
    live = signed_request(client, key)
    with Session(engine) as db, db.begin():
        row = db.get_one(RegistrationChallenge, UUID(expired["challenge_id"]))
        row.created_at = datetime.now(UTC) - timedelta(minutes=10)
        row.expires_at = row.created_at + timedelta(minutes=5)

    assert client.post(SIGNUP, json=expired).status_code == 422
    with Session(engine) as db:
        assert registration.prune_expired(db) == 1
        assert db.get(RegistrationChallenge, UUID(expired["challenge_id"])) is None
        assert db.get(RegistrationChallenge, UUID(live["challenge_id"])) is not None
    assert client.post(SIGNUP, json=live).status_code == 201


@pytest.mark.parametrize("engine", ["postgres"], indirect=True)
@pytest.mark.parametrize("shared", [True, False], ids=["same-challenge", "same-user-id"])
def test_concurrent_registration(client: TestClient, engine: Engine, shared: bool) -> None:
    key = Ed25519PrivateKey.generate()
    first = signed_request(client, key)
    second = first if shared else signed_request(client, key)
    barrier = Barrier(2)

    def submit(request: dict[str, str]) -> int:
        _ = barrier.wait(timeout=5)
        return client.post(SIGNUP, json=request).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(submit, (first, second)))
    assert sorted(statuses) == [201, 422 if shared else 409]
    with Session(engine) as db:
        assert [row.user_id for row in db.scalars(select(User))] == ["alice"]
        assert [row.user_id for row in db.scalars(select(ApiCredential))] == ["alice"]
        winner = (first, second)[statuses.index(201)]
        consumed = db.scalars(select(RegistrationChallenge.challenge_id).where(
            RegistrationChallenge.consumed_at.is_not(None)
        )).all()
        assert consumed == [UUID(winner["challenge_id"])]


@pytest.mark.parametrize("engine", ["postgres"], indirect=True)
def test_credential_collision_rolls_back(
    client: TestClient, engine: Engine, monkeypatch: pytest.MonkeyPatch,
) -> None:
    with Session(engine) as db, db.begin():
        seed_account(db, "bob", bytes(32), "already-in-use")
    request = signed_request(client, Ed25519PrivateKey.generate())
    def duplicate_token(_size: int) -> str:
        return "already-in-use"

    monkeypatch.setattr(registration, "token_urlsafe", duplicate_token)
    result = client.post(SIGNUP, json=request)
    assert result.status_code == 503 and "already-in-use" not in result.text
    with Session(engine) as db:
        assert db.get(User, "alice") is None and db.get(ApiCredential, "alice") is None
        assert db.get_one(RegistrationChallenge, UUID(request["challenge_id"])).consumed_at is None


@pytest.mark.parametrize("engine", ["postgres"], indirect=True)
def test_backfilled_identity_can_update_own_profile(client: TestClient, engine: Engine) -> None:
    key = Ed25519PrivateKey.generate()
    raw_key = key.public_key().public_bytes_raw()
    with Session(engine) as db, db.begin():
        db.add(User(user_id="alice", display_name="Alice", websocket_url="ws://old.example",
                    signing_public_key=raw_key))
        seed_account(db, "bob", bytes(32), "bob-token")
    legacy = DemoIdentity.model_validate({
        "user_id": "alice", "api_token": "existing-token", "signing_public_key_b64": key_b64(key),
    })
    with Session(engine) as db:
        assert backfill(db, [legacy]) == BackfillCounts(1, 0)

    assert client.get("/api/users", headers={"Authorization": "Bearer existing-token"}).status_code == 200
    rejected = client.get("/api/users", headers={"Authorization": "Bearer unknown"})
    assert rejected.status_code == 401 and rejected.headers["WWW-Authenticate"] == "Bearer"
    updates = {"display_name": "New name", "websocket_url": "wss://new.example",
               "signing_public_key_b64": b64(bytes(32))}
    assert client.put("/api/users/alice", json=updates,
                      headers={"Authorization": "Bearer bob-token"}).status_code == 403
    response = client.put("/api/users/alice", json=updates,
                          headers={"Authorization": "Bearer existing-token"})
    assert response.status_code == 200 and response.json()["display_name"] == "New name"
    with Session(engine) as db:
        alice = db.get_one(User, "alice")
        assert alice.signing_public_key == raw_key and alice.websocket_url == "wss://new.example"


def test_signup_disabled_by_default(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SERVER_PUBLIC_SIGNUP_ENABLED")
    get_settings.cache_clear()
    assert client.post(CHALLENGES, json={}).status_code == 404
    assert client.post(SIGNUP, json={}).status_code == 404
    assert client.post(SIGNUP, content="{", headers={"Content-Type": "application/json"}).status_code == 404


@pytest.mark.parametrize("path", [CHALLENGES, SIGNUP])
def test_public_endpoints_rate_limit_the_peer(client: TestClient, path: str) -> None:
    limit = registrations.challenge_limit if path == CHALLENGES else registrations.registration_limit
    for _ in range(limit.attempts):
        assert client.post(path, json={}).status_code == 422
    response = client.post(path, content="{", headers={
        "Content-Type": "application/json", "X-Forwarded-For": "192.0.2.5",
    })
    assert response.status_code == 429 and response.headers["Retry-After"] == "60"
