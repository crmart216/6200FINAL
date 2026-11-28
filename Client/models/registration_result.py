from dataclasses import dataclass, field
from typing import Literal

from .registered_user import RegisteredUser


@dataclass(frozen=True, slots=True)
class RegistrationResult:
    user: RegisteredUser
    api_token: str = field(repr=False)
    token_type: Literal["Bearer"] = "Bearer"