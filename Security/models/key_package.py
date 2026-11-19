# Security/models/key_package.py

from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# Pass the encoded credential bytes until the Credential model is implemented.
type Credential = bytes


@dataclass(frozen=True)
class PublicKeyPackage:
    """Public identity and keys that another member uses to invite this user."""

    package_id: str
    credential: Credential
    init_public_key: bytes
    leaf_public_key: bytes
    signing_public_key: bytes
    signature: bytes = b""  # Create the signed copy with dataclasses.replace().

    def serialize_unsigned(self) -> bytes:
        """Encode the fields covered by the signature in a fixed order."""
        fields = (
            self.package_id.encode("utf-8"),
            self.credential,
            self.init_public_key,
            self.leaf_public_key,
            self.signing_public_key,
        )

        # Each field starts with its length as a 4-byte big-endian integer.
        return b"6200 KeyPackage v1\x00" + b"".join(
            len(value).to_bytes(4, "big") + value for value in fields
        )


@dataclass(frozen=True, eq=False)
class PrivateKeyPackage:
    """Keep the matching private keys in the package owner's local state."""

    package_id: str
    _init_private_key: X25519PrivateKey = field(repr=False)
    _leaf_private_key: X25519PrivateKey = field(repr=False)