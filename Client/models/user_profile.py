from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class UserProfile:
    id: str
    display_name: str