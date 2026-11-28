from dataclasses import dataclass

from .group_summary import GroupSummary
from .types import InvitationStatus
from .user_profile import UserProfile


@dataclass(frozen=True, slots=True)
class Invitation:
    id: str
    group: GroupSummary
    inviter: UserProfile
    invitee: UserProfile
    status: InvitationStatus = "pending"