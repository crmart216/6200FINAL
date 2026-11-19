from __future__ import annotations
from dataclasses import dataclass, field
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from .ratchet_tree import RatchetTree

@dataclass(eq=False)
class GroupState:
    
    group_id: str
    title: str
    epoch: int
    own_leaf_index: int
    ratchet_tree: RatchetTree

    # Indexed by tree node index. The public tree stores public keys. 
    # Public Key Tree stores every user and node in the group chat with their public key
    # This is used to match the private keys the user knows to a public key for a node in the tree.

    _private_tree_keys: dict[int, X25519PrivateKey] = field(default_factory=dict, repr=False)

    # Stores secrets for the current epoch. This is used to derive the secrets for the next epoch.
    _epoch_secrets: EpochSecrets | None = field(default=None, repr=False)

    # Each dictionary key is a sender's leaf index
    _sender_ratchets: dict[int, SenderRatchet] = field(default_factory=dict, repr=False)

    
@dataclass(frozen=True, eq=False, repr=False)
class EpochSecrets:
    init_secret: bytes
    encryption_secret: bytes
    sender_data_secret: bytes
    confirmation_key: bytes
    membership_key: bytes

@dataclass(eq=False)
class SenderRatchet:
    chain_secret: bytes = field(repr=False)
    next_generation: int = 0