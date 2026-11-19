from json import dumps

from ....models.group_models.managed_group_state import ManagedGroupState
from ....models.key_models.key_package import PublicKeyPackage
from ....models.key_models.protocols.commit import Commit


class CommitCodec:
    """Encode the canonical bytes used to authenticate an Add commit."""

    def encode_context(self, state: ManagedGroupState) -> bytes:
        """Bind the update to the group, epoch, and previous transcript."""
        return self._encode([
            "6200 commit v1",
            state.group_id,
            state.epoch,
            state.transcript_hash.hex(),
        ])

    def encode_body(
        self, context: bytes, commit: Commit, invitee: PublicKeyPackage
    ) -> bytes:
        """Encode the Add package and update path for signing and verification."""
        path = commit.update_path
        nodes = [
            [
                node.node_index,
                node.public_key.hex(),
                {
                    str(index): ciphertext.hex()
                    for index, ciphertext in node.encrypted_path_secrets.items()
                },
            ]
            for node in path.nodes
        ]
        return self._encode([
            context.hex(),
            commit.sender_leaf_index,
            "add",
            invitee.serialize_unsigned().hex(),
            invitee.signature.hex(),
            path.leaf_public_key.hex(),
            nodes,
        ])

    @staticmethod
    def _encode(value: object) -> bytes:
        return dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")