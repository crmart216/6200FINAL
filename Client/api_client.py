"""Synchronous HTTP transport for signup, the user directory, and group registration."""

from base64 import b64decode, b64encode
from collections.abc import Callable
from datetime import datetime
from math import isfinite
from typing import TypeVar, cast
from urllib.parse import quote
from uuid import UUID

import httpx

from .models.group_registration_result import GroupRegistrationResult
from .models.registered_user import RegisteredUser
from .models.registration_challenge import RegistrationChallenge
from .models.registration_result import RegistrationResult
from .models.user_profile import UserProfile

_T = TypeVar("_T")
_HTTP_MESSAGES = {
    404: "Public signup is unavailable.",
    409: "The user ID is already in use.",
    422: "The signup request or registration proof was rejected.",
    429: "The signup rate limit was reached.",
    503: "The signup service is temporarily unavailable.",
}
_DIRECTORY_HTTP_MESSAGES = {
    401: "The server rejected this client's saved credentials.",
    429: "The directory rate limit was reached.",
    503: "The user directory is temporarily unavailable.",
}


class ApiClientError(Exception):
    """Base class for API failures."""

    def __init__(
        self, message: str, *, status_code: int | None = None, retry_after: str | None = None
    ) -> None:
        super().__init__(message)
        self.status_code: int | None = status_code
        self.retry_after: str | None = retry_after


class ApiTransportError(ApiClientError):
    """The request failed before a response could be read."""

    def __init__(self, *, timed_out: bool) -> None:
        message = "The request timed out." if timed_out else "The request failed in transport."
        super().__init__(message)
        self.timed_out: bool = timed_out


class ApiHttpError(ApiClientError):
    """The server returned an unexpected HTTP status."""

    def __init__(
        self, status_code: int, retry_after: str | None, *,
        directory: bool = False, message: str | None = None,
    ) -> None:
        if message is None:
            if directory:
                message = _DIRECTORY_HTTP_MESSAGES.get(status_code, "The directory request failed.")
            else:
                message = _HTTP_MESSAGES.get(status_code, "The server returned an unexpected signup status.")
        super().__init__(f"{message} (HTTP {status_code})", status_code=status_code, retry_after=retry_after)


class ApiMalformedResponseError(ApiClientError):
    """The server returned a successful status with an invalid response."""

    def __init__(self, status_code: int, retry_after: str | None) -> None:
        super().__init__(
            "The server returned a malformed response.",
            status_code=status_code,
            retry_after=retry_after,
        )


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError
    return cast(dict[str, object], value)


def _text(data: dict[str, object], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str):
        raise ValueError
    return value


def _encode_binary(value: bytes) -> str:
    return b64encode(value).decode("ascii")


def _binary(data: dict[str, object], field: str) -> bytes:
    encoded = _text(data, field)
    decoded = b64decode(encoded, validate=True)
    if _encode_binary(decoded) != encoded:
        raise ValueError
    return decoded


def _parse_challenge(value: object) -> RegistrationChallenge:
    data = _object(value)
    challenge_id = UUID(_text(data, "challenge_id"))
    nonce = _binary(data, "challenge_b64")
    expires_at = datetime.fromisoformat(_text(data, "expires_at"))
    if expires_at.utcoffset() is None:
        raise ValueError
    return RegistrationChallenge(challenge_id, nonce, expires_at)


def _parse_user(value: object) -> RegisteredUser:
    user = _object(value)
    profile = UserProfile(_text(user, "user_id"), _text(user, "display_name"))
    return RegisteredUser(profile, _text(user, "websocket_url"), _binary(user, "signing_public_key_b64"))


def _parse_registration(value: object) -> RegistrationResult:
    data = _object(value)
    registered_user = _parse_user(data.get("user"))
    token = _text(data, "api_token")
    if not token.strip() or _text(data, "token_type") != "Bearer":
        raise ValueError
    return RegistrationResult(registered_user, token)


def _parse_users(value: object) -> list[RegisteredUser]:
    if not isinstance(value, list):
        raise ValueError
    return [_parse_user(entry) for entry in cast(list[object], value)]


def _parse_group(value: object) -> GroupRegistrationResult:
    data = _object(value)
    epoch = data.get("current_epoch")
    if type(epoch) is not int or epoch < 0:
        raise ValueError
    return GroupRegistrationResult(
        _text(data, "group_id"), _text(data, "group_name"), _text(data, "founder_user_id"), epoch
    )


class ApiClient:
    """Call API endpoints using an HTTP(S) origin without /api."""

    def __init__(
        self,
        server_origin: str,
        *,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        origin = httpx.URL(server_origin)
        if (
            origin.scheme not in ("http", "https")
            or not origin.host
            or origin.raw_path != b"/"
            or origin.fragment
            or origin.userinfo
        ):
            raise ValueError("Supply an HTTP(S) server origin without /api, credentials, or URL parameters.")
        if not isfinite(timeout) or timeout <= 0:
            raise ValueError("The HTTP timeout must be finite and positive.")
        self._client: httpx.Client = httpx.Client(
            base_url=origin, timeout=timeout, transport=transport, follow_redirects=False
        )

    def request_registration_challenge(self, user_id: str, signing_public_key: bytes) -> RegistrationChallenge:
        return self._post(
            "/api/registration-challenges",
            {"user_id": user_id, "signing_public_key_b64": _encode_binary(signing_public_key)},
            _parse_challenge,
        )

    def register(
        self,
        profile: UserProfile,
        websocket_url: str,
        signing_public_key: bytes,
        challenge_id: UUID,
        proof_signature: bytes,
    ) -> RegistrationResult:
        return self._post(
            "/api/registrations",
            {
                "user_id": profile.id,
                "display_name": profile.display_name,
                "websocket_url": websocket_url,
                "signing_public_key_b64": _encode_binary(signing_public_key),
                "challenge_id": str(challenge_id),
                "proof_signature_b64": _encode_binary(proof_signature),
            },
            _parse_registration,
        )

    def list_users(self, api_token: str) -> list[RegisteredUser]:
        return self._request(
            "GET", "/api/users", 200, _parse_users, headers={"Authorization": f"Bearer {api_token}"}
        )

    def register_group(self, api_token: str, group_id: str, group_name: str) -> GroupRegistrationResult:
        return self._request(
            "PUT", f"/api/groups/{quote(group_id, safe='')}", 200, _parse_group,
            payload={"group_name": group_name}, headers={"Authorization": f"Bearer {api_token}"},
        )

    def _post(self, path: str, payload: dict[str, str], parse: Callable[[object], _T]) -> _T:
        return self._request("POST", path, 201, parse, payload=payload)

    def _request(
        self,
        method: str,
        path: str,
        expected_status: int,
        parse: Callable[[object], _T],
        *,
        payload: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> _T:
        try:
            response = self._client.request(method, path, json=payload, headers=headers)
        except httpx.TimeoutException:
            raise ApiTransportError(timed_out=True) from None
        except httpx.RequestError:
            raise ApiTransportError(timed_out=False) from None

        retry_after = response.headers["Retry-After"] if "Retry-After" in response.headers else None
        if response.status_code != expected_status:
            message = "The group registration request failed." if method == "PUT" else None
            raise ApiHttpError(response.status_code, retry_after, directory=path == "/api/users", message=message)

        try:
            return parse(cast(object, response.json()))
        except ValueError:
            raise ApiMalformedResponseError(response.status_code, retry_after) from None

    def close(self) -> None:
        self._client.close()
