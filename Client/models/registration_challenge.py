from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class RegistrationChallenge:
    challenge_id: UUID
    nonce: bytes
    expires_at: datetime