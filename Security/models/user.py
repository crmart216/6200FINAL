# Security/models/user.py

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .group_state import GroupState
from .key_package import PrivateKeyPackage


@dataclass(eq=False)
class User:
    """Store a user's local identity, private key packages, and group states."""

    user_id: str
    display_name: str

    # Generate a key for a new user or pass the existing key when loading one.
    _signing_key: Ed25519PrivateKey = field(
        default_factory=Ed25519PrivateKey.generate,
        repr=False,
    )

    # Indexed by package_id so an incoming Welcome can find its private keys.
    _private_packages: dict[str, PrivateKeyPackage] = field(
        default_factory=dict,
        repr=False,
    )

    # Indexed by group_id. Each entry holds this user's local group state.
    _groups: dict[str, GroupState] = field(
        default_factory=dict,
        repr=False,
    )