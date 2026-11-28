"""Coordinate signup, local account restoration, and directory reads."""

from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from Security.models.group_models.managed_group_state import ManagedGroupState
from Security.models.user import User
from Security.services.group_services.group_service import GroupService
from Security.services.group_services.group_service_helpers.group_state_codec import decode_epoch_zero, encode_epoch_zero
from Security.services.group_services.key_services.key_package_service import KeyPackageService
from Security.services.group_services.key_services.tree_key_service import TreeKeyService

from .api_client import ApiClient, ApiMalformedResponseError
from .identity import IdentityService
from .models.group_summary import GroupSummary
from .models.local_group import LocalGroup
from .models.local_identity import LocalIdentity
from .models.user_profile import UserProfile
from .state_store import ClientStateStore


class GroupStateMismatch(ValueError):
    """The local founder snapshot cannot represent the group."""


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
        self._groups: GroupService = GroupService(KeyPackageService(), TreeKeyService())

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

    def list_groups(self) -> list[GroupSummary]:
        identity, _ = self._registered_identity()
        return self._state_store.list_groups(identity.profile.id)

    def list_pending_groups(self) -> list[GroupSummary]:
        identity, _ = self._registered_identity()
        return self._state_store.list_groups(identity.profile.id, status="pending")

    def create_group(self, name: str) -> GroupSummary:
        title = name.strip()
        if not title or "\x00" in title:
            raise ValueError("Group name must be nonblank and contain no NUL.")
        identity, token = self._registered_identity()
        try:
            signing_key = Ed25519PrivateKey.from_private_bytes(identity.signing_private_key)
        except ValueError:
            raise GroupStateMismatch("The saved account signing key is invalid.") from None
        founder = User(identity.profile.id, identity.profile.display_name, signing_key)
        state = self._groups.create_group(founder, title)
        pending = LocalGroup(GroupSummary(state.group_id, state.title, founder.user_id), encode_epoch_zero(state))
        self._state_store.save_pending_group(pending)
        return self._register_group(pending, token)

    def retry_group_creation(self, group_id: str) -> GroupSummary:
        identity, token = self._registered_identity()
        group = self._owned_group(group_id, identity)
        if group.status == "confirmed":
            return group.summary
        _ = self._decode_group(group, identity)
        return self._register_group(group, token)

    def restore_group_state(self, group_id: str) -> ManagedGroupState:
        identity, _ = self._registered_identity()
        return self._decode_group(self._owned_group(group_id, identity), identity)

    def _registered_identity(self) -> tuple[LocalIdentity, str]:
        identity = self._state_store.load_identity()
        if identity is None or identity.api_token is None:
            raise ValueError("Register this client before managing groups.")
        return identity, identity.api_token

    def _owned_group(self, group_id: str, identity: LocalIdentity) -> LocalGroup:
        group = self._state_store.load_group(group_id)
        if group is None or group.summary.founder_id != identity.profile.id:
            raise ValueError("The local group was not found for this account.")
        return group

    def _decode_group(self, group: LocalGroup, identity: LocalIdentity) -> ManagedGroupState:
        try:
            public_key = self._identity_service.public_key_bytes(identity)
            state = decode_epoch_zero(group.snapshot, public_key)
        except ValueError:
            raise GroupStateMismatch("The saved founder state is invalid for this account.") from None
        if (state.group_id, state.title) != (group.summary.id, group.summary.name):
            raise GroupStateMismatch("The saved founder state does not match the local group.")
        return state

    def _register_group(self, group: LocalGroup, token: str) -> GroupSummary:
        summary = group.summary
        result = self._api_client.register_group(token, summary.id, summary.name)
        if (result.group_id, result.group_name, result.founder_user_id) != (
            summary.id, summary.name, summary.founder_id,
        ):
            raise ApiMalformedResponseError(status_code=200, retry_after=None)
        if result.current_epoch != 0:
            raise GroupStateMismatch("The server group has advanced beyond the saved epoch-zero state.")
        self._state_store.confirm_group(summary.id, summary.founder_id)
        return summary

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
