from collections.abc import Iterator
from hashlib import sha256
from hmac import compare_digest
from json import dumps, loads
from typing import TypedDict, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite

from ....models.group_models.managed_group_state import ManagedGroupState
from ....models.group_models.ratchet_tree import RatchetTree, TreeNode
from ....models.key_models.key_package import PrivateKeyPackage, PublicKeyPackage
from ....models.key_models.protocols.welcome import Welcome
from ....models.user import User
from ..key_services.key_package_service import TrustedIdentity
from .epoch_key_schedule import EpochKeySchedule

class _WelcomeInfo(TypedDict):
    package_id: str
    group_id: str
    title: str
    epoch: int
    sender_leaf_index: int
    leaf_index: int
    signing_keys: list[str]
    leaves: list[str]
    parents: dict[str, str]
    transcript_hash: str
    seed_hash: str

class WelcomeService:
    """Build and open authenticated invitations for the Add flow."""

    def __init__(self) -> None:
        self._hpke: Suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

    def build_welcome(
        self,
        inviter: User,
        invitee: PublicKeyPackage,
        next_state: ManagedGroupState,
        seed: bytes,
    ) -> Welcome:
        """Sign the staged group info and encrypt it and the epoch seed."""
        leaf_count = len(next_state.member_signing_keys)
        tree = next_state.ratchet_tree
        body = self._encode({
            "package_id": invitee.package_id,
            "group_id": next_state.group_id,
            "title": next_state.title,
            "epoch": next_state.epoch,
            "sender_leaf_index": next_state.own_leaf_index,
            "leaf_index": leaf_count - 1,
            "signing_keys": [key.hex() for key in next_state.member_signing_keys],
            "leaves": [
                tree.get_leaf(index).public_key.hex() for index in range(leaf_count)
            ],
            "parents": {
                str(node.node_index): node.public_key.hex()
                for node in self._parents(tree)
            },
            "transcript_hash": next_state.transcript_hash.hex(),
            "seed_hash": sha256(seed).hexdigest(),
        })
        recipient: X25519PublicKey = X25519PublicKey.from_public_bytes(invitee.init_public_key)
        signed_info = inviter.signing_key.sign(body) + body

        return Welcome(
            package_id=invitee.package_id,
            encrypted_group_secrets=self._hpke.encrypt(
                seed,
                recipient,
                info=self._welcome_context(invitee.package_id, "secrets"),
            ),
            encrypted_group_info=self._hpke.encrypt(
                signed_info,
                recipient,
                info=self._welcome_context(invitee.package_id, "info"),
            ),
        )

    def open_welcome(
        self,
        invitee: User,
        package: PrivateKeyPackage,
        welcome: Welcome,
        expected_inviter: TrustedIdentity,
    ) -> ManagedGroupState:
        """Verify the invitation and reconstruct the invitee's local state."""
        if package.package_id != welcome.package_id:
            raise ValueError("Welcome does not match the supplied private package.")

        signed: bytes = self._hpke.decrypt(
            welcome.encrypted_group_info,
            package.init_private_key,
            info=self._welcome_context(welcome.package_id, "info"),
        )
        signature, body = signed[:64], signed[64:]
        inviter_key: Ed25519PublicKey = Ed25519PublicKey.from_public_bytes(
            data=expected_inviter.signing_public_key
        )
        inviter_key.verify(signature, body)
        info = cast(_WelcomeInfo, loads(body))

        if info["package_id"] != welcome.package_id:
            raise ValueError("Welcome package mismatch.")
        if info["group_id"] in invitee.groups:
            raise ValueError("Group already exists locally.")

        signing_keys: tuple[bytes, ...] = tuple(bytes.fromhex(key) for key in info["signing_keys"])
        leaves: list[bytes] = [bytes.fromhex(key) for key in info["leaves"]]
        own_index = info["leaf_index"]
        sender = info["sender_leaf_index"]
        transcript: bytes = bytes.fromhex(info["transcript_hash"])
        own_signing_key: bytes = invitee.signing_key.public_key().public_bytes_raw()
        own_leaf_key: bytes = package.leaf_private_key.public_key().public_bytes_raw()

        if (
            info["epoch"] < 1
            or len(transcript) != 32
            or len(signing_keys) != len(leaves)
            or len(set(signing_keys)) != len(signing_keys)
            or any(len(key) != 32 for key in (*signing_keys, *leaves))
            or own_index != len(leaves) - 1
            or not 0 <= sender < own_index
            or signing_keys[sender] != expected_inviter.signing_public_key
            or signing_keys[own_index] != own_signing_key
            or leaves[own_index] != own_leaf_key
        ):
            raise ValueError("Welcome group state does not match the invite.")

        seed: bytes = self._hpke.decrypt(
            welcome.encrypted_group_secrets,
            package.init_private_key,
            info=self._welcome_context(welcome.package_id, "secrets"),
        )
        if len(seed) != 32 or not compare_digest(
            sha256(seed).hexdigest(), info["seed_hash"]
        ):
            raise ValueError("Welcome epoch secret does not match the signed group info.")

        tree: RatchetTree = self._restore_tree(leaves, info["parents"])
        return ManagedGroupState(
            group_id=info["group_id"],
            title=info["title"],
            epoch=info["epoch"],
            own_leaf_index=own_index,
            ratchet_tree=tree,
            _private_tree_keys={
                tree.get_leaf(own_index).node_index: package.leaf_private_key
            },
            _epoch_secrets=EpochKeySchedule.derive_epoch_secrets(seed),
            member_signing_keys=signing_keys,
            transcript_hash=transcript,
        )

    def _restore_tree(
        self, leaves: list[bytes], parent_keys: dict[str, str]
    ) -> RatchetTree:
        tree: RatchetTree = RatchetTree()
        for leaf in leaves:
            # insert_member() only reads the package's leaf public key.
            _ = tree.insert_member(PublicKeyPackage("", b"", b"", leaf, b""))

        parents: dict[str, TreeNode] = {str(node.node_index): node for node in self._parents(tree)}
        if parents.keys() != parent_keys.keys():
            raise ValueError("Welcome parent indices do not match the tree.")

        for index, encoded_key in parent_keys.items():
            key: bytes = bytes.fromhex(encoded_key)
            if len(key) not in (0, 32):
                raise ValueError("Invalid Welcome parent key.")
            parents[index].public_key = key

        return tree

    @staticmethod
    def _parents(tree: RatchetTree) -> Iterator[TreeNode]:
        pending: list[TreeNode] = [tree.root] if tree.root is not None else []
        while pending:
            node: TreeNode = pending.pop()
            if not node.is_leaf():
                yield node
            pending.extend(
                child for child in (node.left, node.right) if child is not None
            )

    def _welcome_context(self, package_id: str, part: str) -> bytes:
        return self._encode(value=["6200 welcome v1", package_id, part])

    @staticmethod
    def _encode(value: object) -> bytes:
        return dumps(obj=value, sort_keys=True, separators=(",", ":")).encode("utf-8")