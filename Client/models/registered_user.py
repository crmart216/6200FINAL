from dataclasses import dataclass

from .user_profile import UserProfile


@dataclass(frozen=True, slots=True)
class RegisteredUser:
    profile: UserProfile
    websocket_url: str
    signing_public_key: bytes