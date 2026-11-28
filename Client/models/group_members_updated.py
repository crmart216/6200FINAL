from dataclasses import dataclass

from .group_member import GroupMember


@dataclass(frozen=True, slots=True)
class GroupMembersUpdated:
    group_id: str
    members: tuple[GroupMember, ...]