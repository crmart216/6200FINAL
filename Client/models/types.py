from typing import Literal

from .group_joined import GroupJoined
from .group_members_updated import GroupMembersUpdated
from .message_received import MessageReceived

InvitationDecision = Literal["accept", "decline"]
InvitationStatus = Literal["pending", "joining", "joined", "declined"]
BackendEvent = GroupJoined | MessageReceived | GroupMembersUpdated