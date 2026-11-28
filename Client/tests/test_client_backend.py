import sqlite3
from base64 import b64decode, b64encode
from collections.abc import Callable, Generator, Iterator
from contextlib import closing, contextmanager
from json import loads
from pathlib import Path
from struct import pack
from typing import cast
from uuid import UUID

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from Client.api_client import ApiClient, ApiHttpError, ApiMalformedResponseError, ApiTransportError
from Client.client_backend import ClientBackend
from Client.identity import IdentityService
from Client.models.user_profile import UserProfile
from Client.state_store import ClientStateStore

_ORIGIN = "http://server:8000"
_URL = "wss://EXAMPLE.test:443/chat?room=study%20group"
_NAME = "Ryán 李"
_TOKEN = "issued-test-token"
_CHALLENGES = "/api/registration-challenges"
_REGISTRATIONS = "/api/registrations"
_FIRST_ID = UUID(int=1)
_SECOND_ID = UUID(int=2)
_NONCE = b"\x00\xff" * 16


@pytest.fixture
def store(tmp_path: Path) -> Iterator[ClientStateStore]:
    with closing(ClientStateStore(tmp_path)) as state_store:
        yield state_store


@contextmanager
def _backend(
    state_store: ClientStateStore, handler: Callable[[httpx.Request], httpx.Response]
) -> Generator[ClientBackend, None, None]:
    with closing(ApiClient(_ORIGIN, transport=httpx.MockTransport(handler))) as api:
        yield ClientBackend(state_store, IdentityService(), api, _URL)


def _no_requests(request: httpx.Request) -> httpx.Response:
    pytest.fail(f"Unexpected HTTP request to {request.url.path}")


def _body(request: httpx.Request) -> dict[str, str]:
    return cast(dict[str, str], loads(request.content))


def _challenge(challenge_id: UUID, nonce: bytes) -> httpx.Response:
    return httpx.Response(201, json={
        "challenge_id": str(challenge_id),
        "challenge_b64": b64encode(nonce).decode("ascii"),
        "expires_at": "2026-12-01T12:00:00Z",
    })


def _registered(data: dict[str, str], **user_changes: str) -> httpx.Response:
    user = {key: data[key] for key in ("user_id", "display_name", "websocket_url", "signing_public_key_b64")}
    user.update(user_changes)
    return httpx.Response(201, json={"user": user, "api_token": _TOKEN, "token_type": "Bearer"})


def test_signup_persists_pending_identity_before_http_and_signs_proof(
    store: ClientStateStore, tmp_path: Path
) -> None:
    paths: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        paths.append(path)
        data = _body(request)
        # A second store observes the committed identity and can acquire a write lock.
        with closing(ClientStateStore(tmp_path)) as observer:
            pending = observer.load_identity()
        assert pending is not None
        assert pending.api_token is None
        assert pending.profile.display_name == _NAME
        assert str(UUID(pending.profile.id)) == pending.profile.id == data["user_id"]
        public_key = b64decode(data["signing_public_key_b64"], validate=True)
        assert public_key == IdentityService.public_key_bytes(pending)

        if path == _CHALLENGES:
            return _challenge(_FIRST_ID, _NONCE)

        assert path == _REGISTRATIONS
        assert data["display_name"] == _NAME
        assert data["challenge_id"] == str(_FIRST_ID)
        assert data["websocket_url"] == _URL
        fields = (
            b"6200 registration v1",
            str(_FIRST_ID).encode("utf-8"),
            _NONCE,
            pending.profile.id.encode("utf-8"),
            _NAME.encode("utf-8"),
            _URL.encode("utf-8"),
            public_key,
        )
        payload = b"".join(pack(">I", len(field)) + field for field in fields)
        signature = b64decode(data["proof_signature_b64"], validate=True)
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
        return _registered(data)

    with _backend(store, handle) as backend:
        assert backend.get_registered_profile() is None
        profile = backend.register(f"  {_NAME}  ")
        assert backend.get_registered_profile() == profile

    assert paths == [_CHALLENGES, _REGISTRATIONS]
    saved = store.load_identity()
    assert saved is not None
    assert saved.profile == profile
    assert saved.api_token == _TOKEN


def test_registered_account_is_restored_after_restart(tmp_path: Path) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == _CHALLENGES:
            return _challenge(_FIRST_ID, _NONCE)
        return _registered(_body(request))

    with closing(ClientStateStore(tmp_path)) as store, _backend(store, handle) as backend:
        profile = backend.register(_NAME)

    with closing(ClientStateStore(tmp_path)) as reopened, _backend(reopened, _no_requests) as backend:
        assert backend.get_registered_profile() == profile
        assert backend.register(f" {_NAME} ") == profile
        with pytest.raises(ValueError, match="does not match"):
            _ = backend.register("Different name")


def test_timeout_then_restart_reuses_identity_and_requests_fresh_challenge(tmp_path: Path) -> None:
    paths: list[str] = []
    challenges: list[dict[str, str]] = []
    submitted_ids: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        data = _body(request)
        paths.append(path)
        if path == _CHALLENGES:
            challenges.append(data)
            if len(challenges) == 1:
                return _challenge(_FIRST_ID, _NONCE)
            return _challenge(_SECOND_ID, b"\xfe" * 32)

        submitted_ids.append(data["challenge_id"])
        if len(submitted_ids) == 1:
            raise httpx.ReadTimeout("Response lost", request=request)
        return _registered(data)

    with closing(ClientStateStore(tmp_path)) as store, _backend(store, handle) as backend:
        with pytest.raises(ApiTransportError) as error:
            _ = backend.register(_NAME)
        assert error.value.timed_out
        assert paths == [_CHALLENGES, _REGISTRATIONS]
        pending = store.load_identity()
        assert pending is not None
        assert pending.api_token is None

    with closing(ClientStateStore(tmp_path)) as reopened, _backend(reopened, handle) as backend:
        assert reopened.load_identity() == pending
        assert backend.get_registered_profile() is None
        assert backend.register(_NAME) == pending.profile
        registered = reopened.load_identity()
        assert registered is not None
        assert registered.signing_private_key == pending.signing_private_key
        assert registered.api_token == _TOKEN

    assert paths == [_CHALLENGES, _REGISTRATIONS] * 2
    assert len(challenges) == 2
    assert challenges[0] == challenges[1]
    assert submitted_ids == [str(_FIRST_ID), str(_SECOND_ID)]


def test_conflict_preserves_pending_identity(store: ClientStateStore) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == _CHALLENGES:
            return _challenge(_FIRST_ID, _NONCE)
        return httpx.Response(409)

    with _backend(store, handle) as backend:
        with pytest.raises(ApiHttpError) as error:
            _ = backend.register(_NAME)
        assert error.value.status_code == 409
        assert backend.get_registered_profile() is None

    pending = store.load_identity()
    assert pending is not None
    assert pending.api_token is None


def test_failed_challenge_keeps_pending_identity_without_submitting_proof(store: ClientStateStore) -> None:
    paths: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(503)

    with _backend(store, handle) as backend:
        with pytest.raises(ApiHttpError) as error:
            _ = backend.register(_NAME)
        assert error.value.status_code == 503
        assert backend.get_registered_profile() is None

    assert paths == [_CHALLENGES]
    pending = store.load_identity()
    assert pending is not None
    assert pending.profile.display_name == _NAME
    assert pending.api_token is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("user_id", "different-user"),
        ("display_name", "Different name"),
        ("websocket_url", "wss://other.test/chat"),
        ("signing_public_key_b64", "AA=="),
    ],
)
def test_mismatched_registration_leaves_identity_pending(
    store: ClientStateStore, field: str, value: str
) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == _CHALLENGES:
            return _challenge(_FIRST_ID, _NONCE)
        return _registered(_body(request), **{field: value})

    with _backend(store, handle) as backend:
        with pytest.raises(ApiMalformedResponseError) as error:
            _ = backend.register(_NAME)
        assert backend.get_registered_profile() is None

    pending = store.load_identity()
    assert pending is not None
    assert pending.api_token is None
    assert _TOKEN not in str(error.value)


@pytest.mark.parametrize("name", ["   ", "Ryan\x00Martin", "a" * 256])
def test_invalid_display_name_fails_locally(store: ClientStateStore, name: str) -> None:
    with _backend(store, _no_requests) as backend:
        with pytest.raises(ValueError, match="Display name"):
            _ = backend.register(name)
    assert store.load_identity() is None


def test_different_name_preserves_pending_identity(store: ClientStateStore) -> None:
    pending = IdentityService.create_pending_identity(UserProfile("saved-user", _NAME))
    store.save_pending_identity(pending)

    with _backend(store, _no_requests) as backend:
        with pytest.raises(ValueError, match="does not match"):
            _ = backend.register("Different name")
    assert store.load_identity() == pending


def test_failed_pending_write_makes_no_requests(store: ClientStateStore, tmp_path: Path) -> None:
    with closing(sqlite3.connect(tmp_path / "client.sqlite")) as connection, connection:
        _ = connection.execute("""
            CREATE TRIGGER fail_pending_insert BEFORE INSERT ON local_identity
            BEGIN
                SELECT RAISE(FAIL, 'pending write failed');
            END
            """)

    with _backend(store, _no_requests) as backend:
        with pytest.raises(sqlite3.IntegrityError, match="pending write failed"):
            _ = backend.register(_NAME)
    assert store.load_identity() is None


def test_failed_token_write_keeps_identity_pending(store: ClientStateStore, tmp_path: Path) -> None:
    with closing(sqlite3.connect(tmp_path / "client.sqlite")) as connection, connection:
        _ = connection.execute("""
            CREATE TRIGGER fail_token_update AFTER UPDATE OF api_token ON local_identity
            BEGIN
                SELECT RAISE(FAIL, 'token write failed');
            END
            """)

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == _CHALLENGES:
            return _challenge(_FIRST_ID, _NONCE)
        return _registered(_body(request))

    with _backend(store, handle) as backend:
        with pytest.raises(sqlite3.IntegrityError, match="token write failed"):
            _ = backend.register(_NAME)
        assert backend.get_registered_profile() is None

    with closing(ClientStateStore(tmp_path)) as reopened:
        pending = reopened.load_identity()
        assert pending is not None
        assert pending.profile.display_name == _NAME
        assert pending.api_token is None


def test_directory_uses_saved_token_and_excludes_self_by_id(store: ClientStateStore) -> None:
    profile = UserProfile("self", _NAME)
    same_name = UserProfile("z-peer", _NAME)
    other = UserProfile("a-peer", "Alice")
    identity = IdentityService.create_pending_identity(profile)
    store.save_pending_identity(identity)
    store.save_registered_identity(profile.id, _TOKEN)

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/api/users"
        assert request.headers["Authorization"] == f"Bearer {_TOKEN}"
        public_key = b64encode(IdentityService.public_key_bytes(identity)).decode("ascii")
        return httpx.Response(200, json=[
            {"user_id": user.id, "display_name": user.display_name, "websocket_url": _URL,
             "signing_public_key_b64": public_key}
            for user in (same_name, profile, other)
        ])

    with _backend(store, handle) as backend:
        assert backend.list_users() == [same_name, other]


@pytest.mark.parametrize("pending", [False, True])
def test_directory_requires_token_before_making_request(store: ClientStateStore, pending: bool) -> None:
    if pending:
        store.save_pending_identity(IdentityService.create_pending_identity(UserProfile("self", _NAME)))
    with _backend(store, _no_requests) as backend:
        with pytest.raises(ValueError, match="Register this client"):
            _ = backend.list_users()


def test_directory_401_preserves_registered_identity(store: ClientStateStore) -> None:
    profile = UserProfile("self", _NAME)
    store.save_pending_identity(IdentityService.create_pending_identity(profile))
    store.save_registered_identity(profile.id, _TOKEN)
    saved = store.load_identity()

    with _backend(store, lambda _request: httpx.Response(401)) as backend:
        with pytest.raises(ApiHttpError) as error:
            _ = backend.list_users()
        assert error.value.status_code == 401
        assert backend.get_registered_profile() == profile

    assert saved is not None
    assert store.load_identity() == saved