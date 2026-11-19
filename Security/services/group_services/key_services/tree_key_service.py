from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from secrets import token_bytes
from struct import pack

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from ....models.group_models.group_state import GroupState
from ....models.group_models.ratchet_tree import RatchetTree, TreeNode
from ....models.key_models.protocols.proposal import UpdatePath, UpdatePathNode


@dataclass(repr=False)
class TreeUpdateSecrets:
    commit_secret: bytes
    private_tree_keys: dict[int, X25519PrivateKey]


@dataclass
class BuiltUpdate:
    update_path: UpdatePath
    secrets: TreeUpdateSecrets = field(repr=False)


class TreeKeyService:
    """Build and process update paths for the course project's ratchet tree."""

    def __init__(self) -> None:
        self._hpke_suite: Suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

    def derive_path_secret(
        self, 
        path_secret: 
        bytes
    ) -> bytes:
        """Derive the next path secret."""
        return self._expand(path_secret, b"path")

    def build_update(
        self, 
        state: GroupState, 
        next_tree: RatchetTree, 
        context: bytes
    ) -> BuiltUpdate:
        """Build the public update and return the committer's new private keys."""
        sender = next_tree.get_leaf(state.own_leaf_index)
        steps = self._path_steps(state, next_tree, state.own_leaf_index)
        leaf_key = X25519PrivateKey.generate()
        private_keys = {sender.node_index: leaf_key}
        nodes: list[UpdatePathNode] = []
        secret = token_bytes(32)

        for parent, recipients in steps:
            node_key = X25519PrivateKey.from_private_bytes(
                self._expand(secret, b"node")
            )
            private_keys[parent.node_index] = node_key
            encrypted = {
                index: self._hpke_suite.encrypt(
                    secret,
                    X25519PublicKey.from_public_bytes(public_key),
                    info=self._hpke_info(context, parent.node_index, index),
                )
                for index, public_key in recipients.items()
            }
            nodes.append(
                UpdatePathNode(
                    parent.node_index,
                    node_key.public_key().public_bytes_raw(),
                    encrypted,
                )
            )
            secret = self.derive_path_secret(secret)

        return BuiltUpdate(
            UpdatePath(leaf_key.public_key().public_bytes_raw(), nodes),
            TreeUpdateSecrets(self._expand(secret, b"commit"), private_keys),
        )

    def process_updates(
        self,
        state: GroupState,
        next_tree: RatchetTree,
        sender_leaf_index: int,
        path: UpdatePath,
        context: bytes,
    ) -> TreeUpdateSecrets:
        """Recover local keys and the commit secret from an authenticated Commit."""
        if sender_leaf_index == state.own_leaf_index:
            raise ValueError("Use build_update's result for the local commit.")

        steps = self._path_steps(state, next_tree, sender_leaf_index)
        if len(path.leaf_public_key) != 32 or len(path.nodes) != len(steps):
            raise ValueError("Invalid update-path shape.")

        recipient = state.ratchet_tree.get_leaf(state.own_leaf_index)
        recipient_key = state.private_tree_keys_snapshot().get(recipient.node_index)
        if recipient_key is None:
            raise ValueError("The local leaf private key is missing.")

        secret: bytes | None = None
        private_keys: dict[int, X25519PrivateKey] = {}

        for (parent, recipients), update in zip(steps, path.nodes, strict=True):
            if (
                update.node_index != parent.node_index
                or len(update.public_key) != 32
                or update.encrypted_path_secrets.keys() != recipients.keys()
            ):
                raise ValueError("Update path does not match the expected tree.")

            if recipient.node_index in recipients:
                secret = self._hpke_suite.decrypt(
                    update.encrypted_path_secrets[recipient.node_index],
                    recipient_key,
                    info=self._hpke_info(
                        context, parent.node_index, recipient.node_index
                    ),
                )
                if len(secret) != 32:
                    raise ValueError("Invalid path secret length.")

            if secret is not None:
                node_key = X25519PrivateKey.from_private_bytes(
                    self._expand(secret, b"node")
                )
                if node_key.public_key().public_bytes_raw() != update.public_key:
                    raise ValueError("Derived public key does not match the update.")

                private_keys[parent.node_index] = node_key
                secret = self.derive_path_secret(secret)

        if secret is None:
            raise ValueError("The update path has no secret for this member.")

        return TreeUpdateSecrets(self._expand(secret, b"commit"), private_keys)

    def _path_steps(
        self, 
        state: GroupState, 
        next_tree: RatchetTree, 
        sender_leaf_index: int
    ) -> list[tuple[TreeNode, dict[int, bytes]]]:
        """Find each parent and its eligible sibling-subtree leaves."""
        old_keys = {
            leaf.node_index: leaf.public_key
            for leaf in state.ratchet_tree.iter_leaves()
            if leaf.public_key
        }
        node = next_tree.get_leaf(sender_leaf_index)
        if not node.public_key or old_keys.get(node.node_index) != node.public_key:
            raise ValueError("The committer must be an existing member.")

        steps: list[tuple[TreeNode, dict[int, bytes]]] = []
        while node.parent is not None:
            parent = node.parent
            sibling = parent.right if parent.left is node else parent.left
            recipients = {
                leaf.node_index: leaf.public_key
                for leaf in self._iter_leaves(sibling)
                if old_keys.get(leaf.node_index) == leaf.public_key
            }
            steps.append((parent, recipients))
            node = parent

        return steps

    def _iter_leaves(self, node: TreeNode | None) -> Iterator[TreeNode]:
        if node is None:
            return
        if node.is_leaf():
            yield node
            return

        yield from self._iter_leaves(node.left)
        yield from self._iter_leaves(node.right)

    @staticmethod
    def _expand(secret: bytes, label: bytes) -> bytes:
        return HKDFExpand(
            algorithm=hashes.SHA256(),
            length=32,
            info=b"6200 tree update v1/" + label,
        ).derive(secret)

    @staticmethod
    def _hpke_info(context: bytes, parent_index: int, recipient_index: int) -> bytes:
        indices = pack(">II", parent_index, recipient_index)
        return b"6200 tree update v1/hpke" + indices + context