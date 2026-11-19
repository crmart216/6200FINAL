# Security/models/protocol_messages.py

from __future__ import annotations

from dataclasses import dataclass

from .key_package import PublicKeyPackage



@dataclass
class Welcome:
    """Carry the encrypted group state a new member needs to join."""

    package_id: str
    encrypted_group_secrets: bytes
    encrypted_group_info: bytes


@dataclass
class Commit:
    """Bundle the proposals and tree update for a group epoch transition."""

    group_id: str
    epoch: int
    sender_leaf_index: int
    proposals: list[Proposal]
    update_path: UpdatePath
    confirmation_tag: bytes


@dataclass
class Proposal:
    """Describe a change that a commit can apply to the group."""

    group_id: str
    epoch: int
    sender_leaf_index: int
    action: str

    # An Add proposal carries the invitee's public key package.
    invitee: PublicKeyPackage | None = None


@dataclass
class UpdatePath:
    """Carry the committer's tree update inside a Commit."""

    leaf_public_key: bytes

    # Ordered from the committer's lowest updated parent toward the root.
    nodes: list[UpdatePathNode]


@dataclass
class UpdatePathNode:
    """Carry the new public key and encrypted path secret for one parent node."""

    node_index: int
    public_key: bytes

    # Maps each recipient tree node index to its encrypted path secret.
    # A recipient node can be a leaf or an internal node.
    encrypted_path_secrets: dict[int, bytes]


