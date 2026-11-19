from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from ....models.group_models.group_state import EpochSecrets


class EpochKeySchedule:
    """Derive the seed and secrets used for a group epoch."""

    @staticmethod
    def derive_next_seed(
        init_secret: bytes, commit_secret: bytes, commit_body: bytes
    ) -> bytes:
        """Bind the next seed to the current init secret and the commit."""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=init_secret,
            info=b"6200 epoch transition v1/" + sha256(commit_body).digest(),
        ).derive(commit_secret)

    @staticmethod
    def derive_epoch_secrets(seed: bytes) -> EpochSecrets:
        """Expand an epoch seed into the five secrets used by GroupState."""
        def expand(label: bytes) -> bytes:
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