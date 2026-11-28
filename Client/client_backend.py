"""Coordinate signup, local account restoration, and directory reads."""

from uuid import uuid4

from .api_client import ApiClient, ApiMalformedResponseError
from .identity import IdentityService
from .models.user_profile import UserProfile
from .state_store import ClientStateStore


class ClientBackend:
    """Use caller-owned signup services and the advertised WebSocket URL."""

    def __init__(
        self,
        state_store: ClientStateStore,
        identity_service: IdentityService,
        api_client: ApiClient,
        websocket_url: str,
    ) -> None:
        self._state_store: ClientStateStore = state_store
        self._identity_service: IdentityService = identity_service
        self._api_client: ApiClient = api_client
        self._websocket_url: str = websocket_url

    def get_registered_profile(self) -> UserProfile | None:
        identity = self._state_store.load_identity()
        if identity is None or identity.api_token is None:
            return None
        return identity.profile

    def list_users(self) -> list[UserProfile]:
        identity = self._state_store.load_identity()
        if identity is None or identity.api_token is None:
            raise ValueError("Register this client before refreshing the user directory.")
        return [
            user.profile
            for user in self._api_client.list_users(identity.api_token)
            if user.profile.id != identity.profile.id
        ]

    def register(self, display_name: str) -> UserProfile:
        name = display_name.strip()
        if not name or "\x00" in name or len(name) > 255:
            raise ValueError("Display name must be nonblank, at most 255 characters, and contain no NUL.")

        identity = self._state_store.load_identity()
        if identity is None:
            profile = UserProfile(str(uuid4()), name)
            identity = self._identity_service.create_pending_identity(profile)
            self._state_store.save_pending_identity(identity)
        elif identity.profile.display_name != name:
            raise ValueError("The display name does not match this client's saved identity.")
        elif identity.api_token is not None:
            return identity.profile

        profile = identity.profile
        public_key = self._identity_service.public_key_bytes(identity)
        challenge = self._api_client.request_registration_challenge(profile.id, public_key)
        signature = self._identity_service.sign_registration_proof(
            identity, challenge.challenge_id, challenge.nonce, self._websocket_url
        )
        result = self._api_client.register(
            profile, self._websocket_url, public_key, challenge.challenge_id, signature
        )
        if (
            result.user.profile != profile
            or result.user.websocket_url != self._websocket_url
            or result.user.signing_public_key != public_key
        ):
            raise ApiMalformedResponseError(status_code=201, retry_after=None)

        self._state_store.save_registered_identity(profile.id, result.api_token)
        return profile