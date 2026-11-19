from dataclasses import dataclass, replace
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from ....models.key_models.key_package import PrivateKeyPackage, PublicKeyPackage
from ....models.user import User


@dataclass(frozen=True)
class TrustedIdentity:
    """The credential and signing key obtained from a trusted identity source."""

    credential: bytes
    signing_public_key: bytes


class KeyPackageService:
    """Manage signed public key packages and their local private counterparts."""

    def generate_packages(
        self, 
        user: User, 
        credential: object, 
        count: int
    ) -> list[PublicKeyPackage]:
        """Generate and sign public packages and store their private counterparts."""
        if count < 0:
            raise ValueError("Package count must be non-negative.")
        if not isinstance(credential, bytes):
            raise TypeError("Credential must be encoded as bytes.")

        signing_key: Ed25519PrivateKey = user.signing_key
        signing_public_key: bytes = signing_key.public_key().public_bytes_raw()
        public_packages: list[PublicKeyPackage] = []
        private_packages: dict[str, PrivateKeyPackage] = {}

        for _ in range(count):
            package_id: str = uuid4().hex
            init_key: X25519PrivateKey = X25519PrivateKey.generate()
            leaf_key: X25519PrivateKey = X25519PrivateKey.generate()

            unsigned: PublicKeyPackage = PublicKeyPackage(
                package_id=package_id,
                credential=credential,
                init_public_key=init_key.public_key().public_bytes_raw(),
                leaf_public_key=leaf_key.public_key().public_bytes_raw(),
                signing_public_key=signing_public_key,
            )
            signature: bytes = signing_key.sign(data=unsigned.serialize_unsigned())
            public_packages.append(replace(unsigned, signature=signature))

            private_packages[package_id] = PrivateKeyPackage(
                package_id=package_id,
                _init_private_key=init_key,
                _leaf_private_key=leaf_key,
            )

        user.private_packages.update(private_packages)
        return public_packages

    def verify_package(
        self, package: PublicKeyPackage, expected: TrustedIdentity
    ) -> bool:
        """Verify the package against the expected identity and check its keys."""
        if (
            not package.package_id
            or package.credential != expected.credential
            or package.signing_public_key != expected.signing_public_key
            or package.init_public_key == package.leaf_public_key
        ):
            return False

        try:
            verifier: Ed25519PublicKey = Ed25519PublicKey.from_public_bytes(expected.signing_public_key)
            verifier.verify(package.signature, data=package.serialize_unsigned())

            probe_key: X25519PrivateKey = X25519PrivateKey.generate()
            for raw_key in (package.init_public_key, package.leaf_public_key):
                # Require canonical X25519 encodings and reject unusable keys.
                if len(raw_key) != 32 or int.from_bytes(raw_key, "little") >= 2**255 - 19:
                    return False
                _ = probe_key.exchange(X25519PublicKey.from_public_bytes(raw_key))
        except (InvalidSignature, ValueError, TypeError, OverflowError):
            return False

        return True

    def consume_package(self, user: User, package_id: str) -> None:
        """Remove a private package after successful Welcome processing."""
        del user.private_packages[package_id]

    def replenish_packages(
        self,
        user: User,
        credential: bytes,
        available_count: int,
        target_count: int,
    ) -> list[PublicKeyPackage]:
        """Generate enough packages to bring the available count up to the target."""
        if available_count < 0 or target_count < 0:
            raise ValueError("Package counts must be non-negative.")

        return self.generate_packages(
            user, credential, max(0, target_count - available_count)
        )