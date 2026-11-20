from Security.models.group_models.ratchet_tree import TreeNode
from dataclasses import dataclass
from .group_state import GroupState

@dataclass(eq=False)
class ManagedGroupState(GroupState):
    member_signing_keys: tuple[bytes | None, ...] = ()
    transcript_hash: bytes = b""

    def require_active_signing_key(self, leaf_index: int) -> bytes:
        """Return the public signing key for an occupied leaf."""
        if not 0 <= leaf_index < len(self.member_signing_keys):
            raise ValueError(f"Leaf index {leaf_index} is out of range.")

        signing_key: bytes | None = self.member_signing_keys[leaf_index]
        leaf: TreeNode = self.ratchet_tree.get_leaf(leaf_index)
        if not signing_key or not leaf.public_key:
            raise ValueError(f"Leaf index {leaf_index} is vacant.")

        return signing_key