from dataclasses import dataclass

from .user_profile import UserProfile


@dataclass(frozen=True, slots=True)
class ChatMessage:
    id: str
    group_id: str
    sender: UserProfile
    text: str