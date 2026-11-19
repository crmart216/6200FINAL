from dataclasses import dataclass


@dataclass(frozen=True)
class ApplicationMessage:
    """Carry an encrypted chat message for a specific group and epoch."""

    group_id: str
    epoch: int
    encrypted_sender_data: bytes 
    ciphertext: bytes             