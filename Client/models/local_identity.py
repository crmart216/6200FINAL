from dataclasses import dataclass, field

from .user_profile import UserProfile


@dataclass(frozen=True, slots=True)
class LocalIdentity:
    profile: UserProfile
    signing_private_key: bytes = field(repr=False)
    api_token: str | None = field(default=None, repr=False)