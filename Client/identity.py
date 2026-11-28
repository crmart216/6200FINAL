"""Create local Ed25519 identities and sign registration proofs."""

from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models.local_identity import LocalIdentity
from .models.user_profile import UserProfile


def _load_private_key(identity: LocalIdentity) -> Ed25519PrivateKey:
    try:
        return Ed25519PrivateKey.from_private_bytes(identity.signing_private_key)
    except ValueError:
        raise ValueError("Stored Ed25519 private key must be 32 raw bytes.") from None


def _registration_proof_bytes(
    profile: UserProfile,
    challenge_id: UUID,
    nonce: bytes,
    websocket_url: str,
    public_key: bytes,
) -> bytes:
    fields = (
        b"6200 registration v1",
        str(challenge_id).encode("utf-8"),
        nonce,
        profile.id.encode("utf-8"),
        profile.display_name.encode("utf-8"),
        websocket_url.encode("utf-8"),
        public_key,
    )
    return b"".join(len(field).to_bytes(4, "big") + field for field in fields)


class IdentityService:
    """Perform key operations for a caller-supplied local identity."""

    @staticmethod
    def create_pending_identity(profile: UserProfile) -> LocalIdentity:
        private_key = Ed25519PrivateKey.generate()
        return LocalIdentity(profile, private_key.private_bytes_raw())

    @staticmethod
    def public_key_bytes(identity: LocalIdentity) -> bytes:
        return _load_private_key(identity).public_key().public_bytes_raw()

    @staticmethod
    def sign_registration_proof(
        identity: LocalIdentity,
        challenge_id: UUID,
        nonce: bytes,
        websocket_url: str,
    ) -> bytes:
        private_key = _load_private_key(identity)
        public_key = private_key.public_key().public_bytes_raw()
        payload = _registration_proof_bytes(identity.profile, challenge_id, nonce, websocket_url, public_key)
        return private_key.sign(payload)