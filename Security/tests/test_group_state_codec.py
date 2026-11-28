from base64 import b64encode
from dataclasses import replace
from hashlib import sha256
from json import dumps, loads
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from Security.models.group_models.group_state import EPOCH_MESSAGE_LIMIT, SenderRatchet
from Security.models.group_models.managed_group_state import ManagedGroupState
from Security.models.group_models.ratchet_tree import RatchetTree
from Security.models.user import User
from Security.services.group_services.group_service import GroupService
from Security.services.group_services.group_service_helpers.group_state_codec import decode_epoch_zero, encode_epoch_zero
from Security.services.group_services.key_services.key_package_service import KeyPackageService, TrustedIdentity
from Security.services.group_services.key_services.tree_key_service import TreeKeyService
from Security.services.message_services.message_service import MessageService

_TITLE = 'Étude, "6200" 🔑'


@pytest.fixture
def founder() -> tuple[User, ManagedGroupState]:
    user = User("alice", "Alice")
    service = GroupService(KeyPackageService(), TreeKeyService())
    return user, service.create_group(user, _TITLE)


def _signing_key(user: User) -> bytes:
    return user.signing_key.public_key().public_bytes_raw()


def _document(state: ManagedGroupState) -> dict[str, object]:
    return cast(dict[str, object], loads(encode_epoch_zero(state)))


def test_round_trip_preserves_exact_founder_state(founder: tuple[User, ManagedGroupState]) -> None:
    user, original = founder
    snapshot = encode_epoch_zero(original)
    restored = decode_epoch_zero(snapshot, _signing_key(user))

    assert (restored.group_id, restored.title) == (original.group_id, _TITLE)
    assert (restored.epoch, restored.own_leaf_index) == (0, 0)
    assert restored.member_signing_keys == original.member_signing_keys == (_signing_key(user),)
    assert restored.transcript_hash == original.transcript_hash
    assert not restored.has_sender_ratchets()
    assert restored.epoch_message_count == 0
    assert not restored.rotation_due

    original_leaf, = original.ratchet_tree.iter_leaves()
    restored_leaf, = restored.ratchet_tree.iter_leaves()
    assert restored_leaf is restored.ratchet_tree.root
    assert restored_leaf.node_index == 0 and restored_leaf.parent is None and restored_leaf.is_leaf()
    assert restored_leaf.public_key == original_leaf.public_key

    original_private = original.private_tree_keys_snapshot()[0]
    restored_keys = restored.private_tree_keys_snapshot()
    assert restored_keys.keys() == {0}
    assert restored_keys[0].private_bytes_raw() == original_private.private_bytes_raw()
    assert restored_keys[0].public_key().public_bytes_raw() == restored_leaf.public_key

    saved_secrets, restored_secrets = original.epoch_secrets, restored.epoch_secrets
    assert saved_secrets is not None and restored_secrets is not None
    assert restored_secrets.init_secret == saved_secrets.init_secret
    assert restored_secrets.encryption_secret == saved_secrets.encryption_secret
    assert restored_secrets.sender_data_secret == saved_secrets.sender_data_secret
    assert restored_secrets.confirmation_key == saved_secrets.confirmation_key
    assert restored_secrets.membership_key == saved_secrets.membership_key
    assert encode_epoch_zero(restored) == snapshot

    # Recreate the pre-codec genesis bytes independently, including JSON escaping.
    previous_genesis = dumps(
        ["6200 genesis v1", original.group_id, _TITLE, original_leaf.public_key.hex(), _signing_key(user).hex()],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert restored.transcript_hash == sha256(previous_genesis).digest()


def test_restored_founder_can_add_first_member(founder: tuple[User, ManagedGroupState]) -> None:
    user, original = founder
    restored = decode_epoch_zero(encode_epoch_zero(original), _signing_key(user))
    packages = KeyPackageService()
    groups = GroupService(packages, TreeKeyService())
    invitee = User("bob", "Bob")
    package, = packages.generate_packages(invitee, b"bob", 1)
    result = groups.add_member(user, restored, package, TrustedIdentity(b"bob", _signing_key(invitee)))
    joined = groups.accept_welcome(invitee, result.welcome, expected_inviter=TrustedIdentity(b"alice", _signing_key(user)))

    assert joined.group_id == restored.group_id
    assert joined.epoch == result.state.epoch == 1
    messages = MessageService()
    packet = messages.encrypt(user, result.state, "Welcome")
    assert messages.decrypt(joined, packet) == "Welcome"


def test_encode_rejects_sender_progress_even_at_epoch_zero(founder: tuple[User, ManagedGroupState]) -> None:
    user, state = founder
    _ = MessageService().encrypt(user, state, "Epoch-zero message")
    assert state.epoch == 0
    assert state.epoch_message_count == 1
    with pytest.raises(ValueError, match="sender ratchet progress"):
        _ = encode_epoch_zero(state)


def test_encode_rejects_a_ratchet_entry_with_zero_messages(founder: tuple[User, ManagedGroupState]) -> None:
    _, state = founder
    state.set_sender_ratchet(0, SenderRatchet(chain_secret=bytes(32)))
    assert state.epoch_message_count == 0
    with pytest.raises(ValueError, match="sender ratchet progress"):
        _ = encode_epoch_zero(state)


def test_restored_founder_can_rotate_after_seven_messages(founder: tuple[User, ManagedGroupState]) -> None:
    user, original = founder
    state = decode_epoch_zero(encode_epoch_zero(original), _signing_key(user))
    groups = GroupService(KeyPackageService(), TreeKeyService())
    messages = MessageService()

    with pytest.raises(ValueError, match="limit has not been reached"):
        _ = groups.rotate_epoch(user, state)
    assert EPOCH_MESSAGE_LIMIT == 7
    for number in range(1, EPOCH_MESSAGE_LIMIT + 1):
        assert messages.encrypt(user, state, str(number)).epoch == 0
        assert state.epoch_message_count == number
        assert state.rotation_due == (number == EPOCH_MESSAGE_LIMIT)
    with pytest.raises(ValueError, match="rotation required"):
        _ = messages.encrypt(user, state, "Before rotation")

    result = groups.rotate_epoch(user, state)
    assert result.commit.proposals[0].action == "rotate"
    assert result.state.epoch == 1
    assert result.state.epoch_message_count == 0
    assert not result.state.has_sender_ratchets()
    with pytest.raises(ValueError, match="founder at leaf 0 in epoch 0"):
        _ = encode_epoch_zero(result.state)
    assert messages.encrypt(user, result.state, "After rotation").epoch == 1


def test_encode_rejects_inconsistent_founder_state(founder: tuple[User, ManagedGroupState]) -> None:
    _, state = founder
    for invalid, message in (
        (replace(state, epoch=1), "founder at leaf 0 in epoch 0"),
        (replace(state, own_leaf_index=1), "founder at leaf 0 in epoch 0"),
        (replace(state, _epoch_secrets=None), "initialized epoch secrets"),
        (replace(state, ratchet_tree=RatchetTree()), "single founder leaf"),
        (replace(state, _private_tree_keys={}), "exactly the founder"),
        (replace(state, _private_tree_keys={0: X25519PrivateKey.generate()}), "does not match the tree"),
        (replace(state, member_signing_keys=()), "single founder signing key"),
        (replace(state, transcript_hash=bytes(32)), "transcript hash mismatch"),
    ):
        with pytest.raises(ValueError, match=message):
            _ = encode_epoch_zero(invalid)

    tree = state.ratchet_tree
    leaf_key = tree.get_leaf(0).public_key
    tree.blank_leaf(0)
    with pytest.raises(ValueError, match="occupied founder leaf"):
        _ = encode_epoch_zero(state)
    _ = tree.insert_leaf(leaf_key)
    with pytest.raises(ValueError, match="single founder leaf"):
        _ = encode_epoch_zero(state)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("version", 2, "Unsupported"),
        ("version", True, "invalid epoch-zero snapshot version"),
        ("epoch", 1, "founder at leaf 0 in epoch 0"),
        ("epoch", False, "founder at leaf 0 in epoch 0"),
        ("own_leaf_index", 1, "founder at leaf 0 in epoch 0"),
        ("group_id", 7, "Invalid group ID or title"),
        ("title", "tampered title", "transcript hash mismatch"),
        ("leaf_private_key", "invalid base64!", "Invalid binary"),
        ("founder_signing_public_key", "AA==", "Invalid binary"),
        ("transcript_hash", b64encode(bytes(32)).decode("ascii"), "transcript hash mismatch"),
        ("epoch_secrets", {"init_secret": "AA=="}, "Invalid fields"),
        ("sender_ratchets", {}, "Invalid fields"),
    ],
)
def test_decode_rejects_invalid_snapshot_fields(
    founder: tuple[User, ManagedGroupState], field: str, value: object, message: str
) -> None:
    user, state = founder
    document = _document(state)
    document[field] = value
    with pytest.raises(ValueError, match=message):
        _ = decode_epoch_zero(dumps(document).encode(), _signing_key(user))


def test_decode_rejects_missing_field_and_invalid_epoch_secret(founder: tuple[User, ManagedGroupState]) -> None:
    user, state = founder
    signing_key = _signing_key(user)
    document = _document(state)
    del document["title"]
    with pytest.raises(ValueError, match="Invalid fields"):
        _ = decode_epoch_zero(dumps(document).encode(), signing_key)

    document = _document(state)
    secrets = cast(dict[str, object], document["epoch_secrets"])
    secrets["confirmation_key"] = "AA=="
    with pytest.raises(ValueError, match="Invalid binary"):
        _ = decode_epoch_zero(dumps(document).encode(), signing_key)


@pytest.mark.parametrize("snapshot", [b"\xff", b"not JSON", b'{"version":1,"version":1}'])
def test_invalid_json_does_not_leak_input(
    founder: tuple[User, ManagedGroupState], snapshot: bytes
) -> None:
    user, _ = founder
    with pytest.raises(ValueError, match="Invalid UTF-8 JSON") as error:
        _ = decode_epoch_zero(snapshot, _signing_key(user))
    assert error.value.__context__ is None


def test_decode_rejects_another_accounts_signing_key(founder: tuple[User, ManagedGroupState]) -> None:
    _, state = founder
    with pytest.raises(ValueError, match="signing key does not match the account"):
        _ = decode_epoch_zero(encode_epoch_zero(state), _signing_key(User("bob", "Bob")))