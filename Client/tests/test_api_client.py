from contextlib import closing
from datetime import UTC, datetime
from json import loads
from uuid import UUID

import httpx
import pytest

from Client.api_client import ApiClient, ApiHttpError, ApiMalformedResponseError, ApiTransportError
from Client.models.group_registration_result import GroupRegistrationResult
from Client.models.registered_user import RegisteredUser
from Client.models.registration_challenge import RegistrationChallenge
from Client.models.registration_result import RegistrationResult
from Client.models.user_profile import UserProfile

_ORIGIN = "http://server:8000"
_PROFILE = UserProfile("ryan-1", "Ryán 李")
_WEBSOCKET_URL = "wss://EXAMPLE.test:443/chat?room=study%20group"
_CHALLENGE_ID = UUID("f1bf3829-d1a6-42ee-bc1c-fdfee93adbee")
_PUBLIC_KEY = b"\xff" * 32
_PUBLIC_KEY_B64 = "/" * 42 + "8="
_PROOF = b"\x00" * 64
_PROOF_B64 = "A" * 86 + "=="
_TOKEN = "server-issued-test-token"


def _challenge_data() -> dict[str, object]:
    return {
        "challenge_id": str(_CHALLENGE_ID),
        "challenge_b64": "AP8BAg==",
        "expires_at": "2026-11-28T15:00:00Z",
    }


def _registration_data() -> dict[str, object]:
    return {
        "user": {
            "user_id": _PROFILE.id,
            "display_name": _PROFILE.display_name,
            "websocket_url": _WEBSOCKET_URL,
            "signing_public_key_b64": _PUBLIC_KEY_B64,
        },
        "api_token": _TOKEN,
        "token_type": "Bearer",
    }


def test_requests_registration_challenge() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url == httpx.URL(f"{_ORIGIN}/api/registration-challenges")
        assert "Authorization" not in request.headers
        assert loads(request.content) == {
            "user_id": "ryan-1",
            "signing_public_key_b64": _PUBLIC_KEY_B64,
        }
        assert request.extensions["timeout"] == dict.fromkeys(("connect", "read", "write", "pool"), 2.5)
        return httpx.Response(201, json=_challenge_data())

    with closing(ApiClient(_ORIGIN, timeout=2.5, transport=httpx.MockTransport(handle))) as client:
        challenge = client.request_registration_challenge(_PROFILE.id, _PUBLIC_KEY)

    assert challenge == RegistrationChallenge(
        _CHALLENGE_ID, b"\x00\xff\x01\x02", datetime(2026, 11, 28, 15, 0, tzinfo=UTC)
    )


def test_register_sends_signed_values_and_returns_bearer_token() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url == httpx.URL(f"{_ORIGIN}/api/registrations")
        assert "Authorization" not in request.headers
        assert loads(request.content) == {
            "user_id": "ryan-1",
            "display_name": "Ryán 李",
            "websocket_url": "wss://EXAMPLE.test:443/chat?room=study%20group",
            "signing_public_key_b64": _PUBLIC_KEY_B64,
            "challenge_id": "f1bf3829-d1a6-42ee-bc1c-fdfee93adbee",
            "proof_signature_b64": _PROOF_B64,
        }
        return httpx.Response(201, json=_registration_data())

    with closing(ApiClient(_ORIGIN, transport=httpx.MockTransport(handle))) as client:
        result = client.register(_PROFILE, _WEBSOCKET_URL, _PUBLIC_KEY, _CHALLENGE_ID, _PROOF)

    assert result == RegistrationResult(RegisteredUser(_PROFILE, _WEBSOCKET_URL, _PUBLIC_KEY), _TOKEN, "Bearer")
    assert _TOKEN not in repr(result)


@pytest.mark.parametrize(
    ("status", "message"),
    [
        (404, "Public signup is unavailable"),
        (409, "user ID is already in use"),
        (422, "request or registration proof was rejected"),
        (429, "rate limit was reached"),
        (503, "temporarily unavailable"),
        (500, "unexpected signup status"),
    ],
)
def test_http_failures_preserve_status_without_retrying(status: int, message: str) -> None:
    attempts = 0
    retry_after = "60" if status == 429 else None

    def handle(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        headers = {"Retry-After": retry_after} if retry_after is not None else {}
        return httpx.Response(status, headers=headers, json={"detail": f"{_TOKEN} {_PROOF_B64}"})

    with closing(ApiClient(_ORIGIN, transport=httpx.MockTransport(handle))) as client:
        with pytest.raises(ApiHttpError, match=message) as error:
            _ = client.register(_PROFILE, _WEBSOCKET_URL, _PUBLIC_KEY, _CHALLENGE_ID, _PROOF)

    assert attempts == 1
    assert error.value.status_code == status
    assert error.value.retry_after == retry_after
    assert _TOKEN not in str(error.value)
    assert _PROOF_B64 not in str(error.value)


@pytest.mark.parametrize("timed_out", [True, False])
def test_transport_failures_do_not_retry_registration(timed_out: bool) -> None:
    attempts = 0

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if timed_out:
            raise httpx.ReadTimeout(_PROOF_B64, request=request)
        raise httpx.ConnectError(_PROOF_B64, request=request)

    with closing(ApiClient(_ORIGIN, transport=httpx.MockTransport(handle))) as client:
        with pytest.raises(ApiTransportError) as error:
            _ = client.register(_PROFILE, _WEBSOCKET_URL, _PUBLIC_KEY, _CHALLENGE_ID, _PROOF)

    assert attempts == 1
    assert error.value.timed_out is timed_out
    assert error.value.status_code is None
    assert error.value.retry_after is None
    assert _PROOF_B64 not in str(error.value)


@pytest.mark.parametrize(
    "content",
    [
        b"not JSON: private response content",
        b"[]",
        b"{}",
    ],
)
def test_invalid_json_or_missing_fields_is_malformed(content: bytes) -> None:
    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, content=content, headers={"Retry-After": "15"})

    with closing(ApiClient(_ORIGIN, transport=httpx.MockTransport(handle))) as client:
        with pytest.raises(ApiMalformedResponseError) as error:
            _ = client.request_registration_challenge(_PROFILE.id, _PUBLIC_KEY)

    assert error.value.status_code == 201
    assert error.value.retry_after == "15"
    assert content.decode("ascii") not in str(error.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("challenge_id", "bad-uuid"),
        ("challenge_b64", "%%%invalid"),
        ("challenge_b64", "AB=="),
        ("expires_at", "invalid timestamp"),
        ("expires_at", "2026-11-28T15:00:00"),
    ],
)
def test_malformed_challenge_field(field: str, value: str) -> None:
    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={**_challenge_data(), field: value})

    with closing(ApiClient(_ORIGIN, transport=httpx.MockTransport(handle))) as client:
        with pytest.raises(ApiMalformedResponseError) as error:
            _ = client.request_registration_challenge(_PROFILE.id, _PUBLIC_KEY)

    assert error.value.status_code == 201
    assert value not in str(error.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("token_type", "Basic"),
        ("api_token", " "),
        ("user", {"user_id": "ryan-1"}),
    ],
)
def test_malformed_registration_does_not_disclose_token(field: str, value: object) -> None:
    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={**_registration_data(), field: value})

    with closing(ApiClient(_ORIGIN, transport=httpx.MockTransport(handle))) as client:
        with pytest.raises(ApiMalformedResponseError) as error:
            _ = client.register(_PROFILE, _WEBSOCKET_URL, _PUBLIC_KEY, _CHALLENGE_ID, _PROOF)

    assert error.value.status_code == 201
    assert _TOKEN not in str(error.value)


def _directory_user(profile: UserProfile) -> dict[str, str]:
    return {
        "user_id": profile.id,
        "display_name": profile.display_name,
        "websocket_url": _WEBSOCKET_URL,
        "signing_public_key_b64": _PUBLIC_KEY_B64,
    }


def test_directory_auth_is_per_request_and_parsing_preserves_order() -> None:
    profiles = (UserProfile("z-user", "Zoë"), _PROFILE)
    paths: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/api/users":
            assert request.method == "GET"
            assert request.headers["Authorization"] == f"Bearer {_TOKEN}"
            assert request.content == b""
            return httpx.Response(200, json=[_directory_user(profile) for profile in profiles])
        assert request.method == "POST"
        assert "Authorization" not in request.headers
        if request.url.path == "/api/registration-challenges":
            return httpx.Response(201, json=_challenge_data())
        return httpx.Response(201, json=_registration_data())

    with closing(ApiClient(_ORIGIN, transport=httpx.MockTransport(handle))) as client:
        assert client.list_users(_TOKEN) == [
            RegisteredUser(profile, _WEBSOCKET_URL, _PUBLIC_KEY) for profile in profiles
        ]
        _ = client.request_registration_challenge(_PROFILE.id, _PUBLIC_KEY)
        _ = client.register(_PROFILE, _WEBSOCKET_URL, _PUBLIC_KEY, _CHALLENGE_ID, _PROOF)

    assert paths == ["/api/users", "/api/registration-challenges", "/api/registrations"]


def test_empty_directory_is_valid() -> None:
    with closing(ApiClient(_ORIGIN, transport=httpx.MockTransport(
        lambda _request: httpx.Response(200, json=[])
    ))) as client:
        assert client.list_users(_TOKEN) == []


@pytest.mark.parametrize(
    "data",
    [{"users": []}, [None], [{"user_id": "incomplete"}],
     [{**_directory_user(_PROFILE), "signing_public_key_b64": "AB=="}]],
)
def test_malformed_directory_uses_typed_error(data: object) -> None:
    with closing(ApiClient(_ORIGIN, transport=httpx.MockTransport(
        lambda _request: httpx.Response(200, json=data)
    ))) as client:
        with pytest.raises(ApiMalformedResponseError) as error:
            _ = client.list_users(_TOKEN)
    assert error.value.status_code == 200
    assert _TOKEN not in str(error.value)


def test_directory_401_uses_typed_error_without_leaking_response() -> None:
    with closing(ApiClient(_ORIGIN, transport=httpx.MockTransport(
        lambda _request: httpx.Response(401, json={"detail": _TOKEN})
    ))) as client:
        with pytest.raises(ApiHttpError, match="saved credentials") as error:
            _ = client.list_users(_TOKEN)
    assert error.value.status_code == 401
    assert _TOKEN not in str(error.value)


def test_register_group_uses_authenticated_put_with_title_only() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.method == "PUT"
        assert request.url.path == "/api/groups/group-id"
        assert request.headers["Authorization"] == f"Bearer {_TOKEN}"
        assert loads(request.content) == {"group_name": "Équipe"}
        return httpx.Response(200, json={
            "group_id": "group-id", "group_name": "Équipe", "founder_user_id": _PROFILE.id, "current_epoch": 0,
        })

    with closing(ApiClient(_ORIGIN, transport=httpx.MockTransport(handle))) as client:
        assert client.register_group(_TOKEN, "group-id", "Équipe") == GroupRegistrationResult(
            "group-id", "Équipe", _PROFILE.id, 0,
        )


@pytest.mark.parametrize("status", [200, 409])
def test_register_group_preserves_typed_errors(status: int) -> None:
    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={
            "group_id": "group-id", "group_name": "Name", "founder_user_id": _PROFILE.id,
            "current_epoch": False, "detail": _TOKEN,
        })

    with closing(ApiClient(_ORIGIN, transport=httpx.MockTransport(handle))) as client:
        with pytest.raises(ApiMalformedResponseError if status == 200 else ApiHttpError) as error:
            _ = client.register_group(_TOKEN, "group-id", "Name")
    assert error.value.status_code == status
    assert _TOKEN not in str(error.value)
