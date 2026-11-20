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
        self,
        context: bytes,
        commit: Commit,
        invitee: PublicKeyPackage | None = None,
    ) -> bytes:
        """Encode one membership proposal and its full ordered update path."""
        if len(commit.proposals) != 1:
            raise ValueError("A membership Commit requires exactly one proposal.")

        proposal = commit.proposals[0]
        if (
            proposal.group_id != commit.group_id
            or proposal.epoch != commit.epoch
            or proposal.sender_leaf_index != commit.sender_leaf_index
        ):
            raise ValueError("Proposal group, epoch, or sender differs from the Commit.")

        payload = proposal.require_payload()
        payload_fields: list[str | int]
        if isinstance(payload, PublicKeyPackage):
            if invitee is not None and invitee != payload:
                raise ValueError("The invitee argument differs from the Add proposal.")
            payload_fields = [
                payload.serialize_unsigned().hex(),
                payload.signature.hex(),
            ]
        else:
            if invitee is not None:
                raise ValueError("A Remove Commit cannot carry an invitee argument.")
            payload_fields = [payload]

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
            proposal.action,
            *payload_fields,
            path.leaf_public_key.hex(),
            nodes,
        ])

    @staticmethod
    def _encode(value: object) -> bytes:
        return dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")