from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel

InvitationStatus = Literal["pending", "accepted", "declined", "claimed", "completed", "expired"]
InvitationDirection = Literal["incoming", "outgoing"]


class InvitationResponse(BaseModel):
    invitation_id: UUID
    group_id: str
    group_name: str
    inviter_user_id: str
    invitee_user_id: str
    status: InvitationStatus
    created_at: datetime
    expires_at: datetime
    joined_epoch: int | None = None