from contextlib import closing
from pathlib import Path
from struct import pack
from uuid import UUID

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from Client.identity import IdentityService
from Client.models.local_identity import LocalIdentity
from Client.models.user_profile import UserProfile
from Client.state_store import ClientStateStore

_PROFILE = UserProfile("ryan-1", "Ryán 李")
_CHALLENGE_ID = UUID("f1bf3829-d1a6-42ee-bc1c-fdfee93adbee")
_NONCE = bytes(range(31)) + b"\xff"
_WEBSOCKET_URL = "wss://example.test:443/chat?room=study%20group"


def _expected_payload(public_key: bytes, *, nonce: bytes = _NONCE, url: str = _WEBSOCKET_URL) -> bytes:
    fields = (
        b"6200 registration v1",
        b"f1bf3829-d1a6-42ee-bc1c-fdfee93adbee",
        nonce,
        b"ryan-1",
        "Ryán 李".encode("utf-8"),
        url.encode("utf-8"),
        public_key,
    )
    return b"".join(pack(">I", len(field)) + field for field in fields)


def test_creates_pending_identity_with_fresh_key() -> None:
    identity = IdentityService.create_pending_identity(_PROFILE)
    another = IdentityService.create_pending_identity(_PROFILE)
    public_key = IdentityService.public_key_bytes(identity)

    assert identity.profile == _PROFILE
    assert identity.api_token is None
    assert len(identity.signing_private_key) == 32
    assert len(public_key) == 32
    assert Ed25519PublicKey.from_public_bytes(public_key).public_bytes_raw() == public_key
    assert IdentityService.public_key_bytes(identity) == public_key
    assert IdentityService.public_key_bytes(another) != public_key


def test_proof_matches_independently_constructed_payload() -> None:
    identity = IdentityService.create_pending_identity(_PROFILE)
    public_key = IdentityService.public_key_bytes(identity)
    signature = IdentityService.sign_registration_proof(identity, _CHALLENGE_ID, _NONCE, _WEBSOCKET_URL)

    assert len(signature) == 64
    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, _expected_payload(public_key))


def test_proof_rejects_changed_fields_and_verification_key() -> None:
    identity = IdentityService.create_pending_identity(_PROFILE)
    public_key = IdentityService.public_key_bytes(identity)
    verifier = Ed25519PublicKey.from_public_bytes(public_key)
    signature = IdentityService.sign_registration_proof(identity, _CHALLENGE_ID, _NONCE, _WEBSOCKET_URL)

    with pytest.raises(InvalidSignature):
        verifier.verify(signature, _expected_payload(public_key, nonce=_NONCE[:-1] + b"\xfe"))
    with pytest.raises(InvalidSignature):
        verifier.verify(signature, _expected_payload(public_key, url="wss://example.test/chat"))

    another = IdentityService.create_pending_identity(_PROFILE)
    other_key = Ed25519PublicKey.from_public_bytes(IdentityService.public_key_bytes(another))
    with pytest.raises(InvalidSignature):
        other_key.verify(signature, _expected_payload(public_key))


def test_reloaded_pending_identity_signs_with_original_key(tmp_path: Path) -> None:
    original = IdentityService.create_pending_identity(_PROFILE)
    original_public_key = IdentityService.public_key_bytes(original)
    with closing(ClientStateStore(tmp_path)) as store:
        store.save_pending_identity(original)

    with closing(ClientStateStore(tmp_path)) as reopened:
        restored = reopened.load_identity()

    assert restored is not None
    assert restored == original
    assert IdentityService.public_key_bytes(restored) == original_public_key
    signature = IdentityService.sign_registration_proof(restored, _CHALLENGE_ID, _NONCE, _WEBSOCKET_URL)
    Ed25519PublicKey.from_public_bytes(original_public_key).verify(signature, _expected_payload(original_public_key))


def test_invalid_stored_private_key_is_rejected() -> None:
    identity = LocalIdentity(_PROFILE, b"bad-key-material")
    error = "Stored Ed25519 private key must be 32 raw bytes."

    with pytest.raises(ValueError) as public_key_error:
        _ = IdentityService.public_key_bytes(identity)
    assert str(public_key_error.value) == error

    with pytest.raises(ValueError) as signature_error:
        _ = IdentityService.sign_registration_proof(identity, _CHALLENGE_ID, _NONCE, _WEBSOCKET_URL)
    assert str(signature_error.value) == error