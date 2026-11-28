from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GroupMember:
    id: str
    display_name: str
    is_founder: bool