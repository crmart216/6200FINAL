from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from ....models.group_models.group_state import EpochSecrets


"""Derive the secrets shared by members in a group epoch. A membership transition
combines the prior initialization secret, the tree update’s commit secret and a
digest of the encoded Commit body. Separate labels expand the resulting seed into
five values with distinct protocol roles."""
class EpochKeySchedule:
    """Derive the seed and secrets used for a group epoch."""

    @staticmethod
    def derive_next_seed(
        init_secret: bytes, commit_secret: bytes, commit_body: bytes
    ) -> bytes:
        """Return a 32-byte epoch seed derived from the current initialization secret, commit secret and hash of the encoded Commit body."""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=init_secret,
            info=b"6200 epoch transition v1/" + sha256(commit_body).digest(),
        ).derive(commit_secret)

    @staticmethod
    def derive_epoch_secrets(seed: bytes) -> EpochSecrets:
        """Expand the supplied seed and return the epoch’s initialization, encryption, sender-data, confirmation and membership secrets."""
        def expand(label: bytes) -> bytes:
            """Return 32 bytes derived from the enclosing epoch seed for the supplied purpose label."""
            return HKDFExpand(
                algorithm=hashes.SHA256(),
                length=32,
                info=b"6200 epoch v1/" + label,
            ).derive(seed)

        return EpochSecrets(
            init_secret=expand(b"init"),
            encryption_secret=expand(b"encryption"),
            sender_data_secret=expand(b"sender-data"),
            confirmation_key=expand(b"confirmation"),
            membership_key=expand(b"membership"),
        )