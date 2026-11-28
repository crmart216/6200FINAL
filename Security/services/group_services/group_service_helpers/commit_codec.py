from hashlib import sha256
from json import dumps

from ....models.group_models.managed_group_state import ManagedGroupState
from ....models.key_models.key_package import PublicKeyPackage
from ....models.key_models.protocols.commit import Commit


"""Serialize the fields used to authenticate membership changes. Both the committer and
receiving members encode the same prior group context, Add or Remove proposal, and
ordered update path so they can compute and verify the Commit signature and
confirmation tag."""
class CommitCodec:
    """Serialize the fields used to authenticate membership changes."""

    def genesis_transcript_hash(
        self, group_id: str, title: str, leaf_public_key: bytes, signing_public_key: bytes
    ) -> bytes:
        """Hash the canonical founder state at the start of the transcript."""
        genesis = self._encode([
            "6200 genesis v1", group_id, title, leaf_public_key.hex(), signing_public_key.hex(),
        ])
        return sha256(genesis).digest()

    def encode_context(self, state: ManagedGroupState) -> bytes:
        """Return canonical context bytes for the managed state’s group ID, epoch and prior transcript hash."""
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
        """Return canonical bytes for the context and membership Commit, checking any supplied invitee package against the proposal."""
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
                raise ValueError("Only an Add Commit can carry an invitee argument.")
            # Rotate carries no membership payload; its action is signed below.
            payload_fields = [] if payload is None else [payload]

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
        """Return the supplied JSON-serializable value as compact UTF-8 JSON bytes with sorted object keys."""
        return dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")