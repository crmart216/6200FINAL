from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from .public_key_package import Binary


class RegistrationChallengeResponse(BaseModel):
    challenge_id: UUID
    challenge_b64: Binary
    expires_at: datetime