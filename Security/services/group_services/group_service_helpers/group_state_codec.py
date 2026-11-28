"""Serialize an unused founder's epoch-zero state, including its group secrets."""

from base64 import b64decode, b64encode
from hmac import compare_digest
from json import dumps, loads
from typing import cast

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ....models.group_models.group_state import EpochSecrets
from ....models.group_models.managed_group_state import ManagedGroupState
from ....models.group_models.ratchet_tree import RatchetTree
from .commit_codec import CommitCodec

_VERSION = 1
_BINARY_SIZE = 32
_FIELDS = frozenset({
    "version", "group_id", "title", "epoch", "own_leaf_index", "leaf_private_key",
    "epoch_secrets", "founder_signing_public_key", "transcript_hash",
})
_SECRET_FIELDS = frozenset({
    "init_secret", "encryption_secret", "sender_data_secret", "confirmation_key", "membership_key",
})


def _fixed_bytes(value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) != _BINARY_SIZE:
        raise ValueError("Expected 32 bytes for epoch-zero key material or transcript hash.")
    return value


def _encode_binary(value: bytes) -> str:
    return b64encode(_fixed_bytes(value)).decode("ascii")


def _decode_binary(value: object) -> bytes:
    if isinstance(value, str):
        try:
            decoded = b64decode(value, validate=True)
        except ValueError:
            pass
        else:
            if len(decoded) == _BINARY_SIZE and _encode_binary(decoded) == value:
                return decoded
    raise ValueError("Invalid binary field in epoch-zero snapshot.")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate snapshot field.")
    return result


def _fields(value: object, required: frozenset[str]) -> dict[str, object]:
    if isinstance(value, dict):
        values = cast(dict[str, object], value)
        if values.keys() == required:
            return values
    raise ValueError("Invalid fields in epoch-zero snapshot.")


def _check_scope(epoch: object, own_leaf_index: object) -> None:
    if type(epoch) is not int or epoch != 0 or type(own_leaf_index) is not int or own_leaf_index != 0:
        raise ValueError("Epoch-zero snapshots require the founder at leaf 0 in epoch 0.")


def _check_genesis(
    group_id: str, title: str, leaf_public_key: bytes, signing_public_key: bytes, transcript_hash: bytes
) -> None:
    expected = CommitCodec().genesis_transcript_hash(group_id, title, leaf_public_key, signing_public_key)
    if not compare_digest(_fixed_bytes(transcript_hash), expected):
        raise ValueError("Epoch-zero genesis transcript hash mismatch.")


def encode_epoch_zero(state: ManagedGroupState) -> bytes:
    """Encode an unused founder state as version-1 UTF-8 JSON."""
    _check_scope(state.epoch, state.own_leaf_index)
    # The epoch message count is derived from these entries, even if it is currently zero.
    if state.has_sender_ratchets():
        raise ValueError("Epoch-zero snapshots cannot include sender ratchet progress.")
    secrets = state.epoch_secrets
    if secrets is None:
        raise ValueError("Epoch-zero snapshots require initialized epoch secrets.")

    leaves = tuple(state.ratchet_tree.iter_leaves())
    if len(leaves) != 1:
        raise ValueError("Epoch-zero snapshots require a single founder leaf.")
    leaf = leaves[0]
    if (
        state.ratchet_tree.root is not leaf or leaf.node_index != 0
        or leaf.parent is not None or not leaf.is_leaf() or not leaf.public_key
    ):
        raise ValueError("Epoch-zero snapshots require an occupied founder leaf as the root.")

    private_keys = state.private_tree_keys_snapshot()
    if private_keys.keys() != {0}:
        raise ValueError("Epoch-zero snapshots require exactly the founder's private leaf key.")
    private_key = private_keys[0]
    if private_key.public_key().public_bytes_raw() != leaf.public_key:
        raise ValueError("The founder's private leaf key does not match the tree.")

    if len(state.member_signing_keys) != 1:
        raise ValueError("Epoch-zero snapshots require a single founder signing key.")
    signing_key = _fixed_bytes(state.require_active_signing_key(0))
    _check_genesis(state.group_id, state.title, leaf.public_key, signing_key, state.transcript_hash)

    document = {
        "version": _VERSION,
        "group_id": state.group_id,
        "title": state.title,
        "epoch": state.epoch,
        "own_leaf_index": state.own_leaf_index,
        "leaf_private_key": _encode_binary(private_key.private_bytes_raw()),
        "epoch_secrets": {
            "init_secret": _encode_binary(secrets.init_secret),
            "encryption_secret": _encode_binary(secrets.encryption_secret),
            "sender_data_secret": _encode_binary(secrets.sender_data_secret),
            "confirmation_key": _encode_binary(secrets.confirmation_key),
            "membership_key": _encode_binary(secrets.membership_key),
        },
        "founder_signing_public_key": _encode_binary(signing_key),
        "transcript_hash": _encode_binary(state.transcript_hash),
    }
    return dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def decode_epoch_zero(snapshot: bytes, expected_signing_public_key: bytes) -> ManagedGroupState:
    """Restore a founder's version-1 snapshot for the supplied account signing key."""
    try:
        parsed = cast(object, loads(snapshot.decode("utf-8"), object_pairs_hook=_unique_object))
    except (ValueError, RecursionError):
        pass
    else:
        return _restore_epoch_zero(parsed, expected_signing_public_key)
    raise ValueError("Invalid UTF-8 JSON in epoch-zero snapshot.")


def _restore_epoch_zero(parsed: object, expected_signing_public_key: bytes) -> ManagedGroupState:
    if not isinstance(parsed, dict):
        raise ValueError("Invalid fields in epoch-zero snapshot.")
    values = cast(dict[str, object], parsed)
    version = values.get("version")
    if type(version) is not int:
        raise ValueError("Missing or invalid epoch-zero snapshot version.")
    if version != _VERSION:
        raise ValueError("Unsupported epoch-zero snapshot version.")
    document = _fields(values, _FIELDS)
    _check_scope(document["epoch"], document["own_leaf_index"])
    group_id, title = document["group_id"], document["title"]
    if not isinstance(group_id, str) or not isinstance(title, str):
        raise ValueError("Invalid group ID or title in epoch-zero snapshot.")

    signing_key = _decode_binary(document["founder_signing_public_key"])
    if not compare_digest(signing_key, _fixed_bytes(expected_signing_public_key)):
        raise ValueError("Epoch-zero founder signing key does not match the account.")
    private_key = X25519PrivateKey.from_private_bytes(_decode_binary(document["leaf_private_key"]))
    leaf_public_key = private_key.public_key().public_bytes_raw()
    transcript_hash = _decode_binary(document["transcript_hash"])
    _check_genesis(group_id, title, leaf_public_key, signing_key, transcript_hash)

    saved = _fields(document["epoch_secrets"], _SECRET_FIELDS)
    secrets = EpochSecrets(
        init_secret=_decode_binary(saved["init_secret"]),
        encryption_secret=_decode_binary(saved["encryption_secret"]),
        sender_data_secret=_decode_binary(saved["sender_data_secret"]),
        confirmation_key=_decode_binary(saved["confirmation_key"]),
        membership_key=_decode_binary(saved["membership_key"]),
    )
    tree = RatchetTree()
    _ = tree.insert_leaf(leaf_public_key)
    return ManagedGroupState(
        group_id=group_id,
        title=title,
        epoch=0,
        own_leaf_index=0,
        ratchet_tree=tree,
        _private_tree_keys={0: private_key},
        _epoch_secrets=secrets,
        member_signing_keys=(signing_key,),
        transcript_hash=transcript_hash,
    )