from dataclasses import dataclass

from .group_summary import GroupSummary


@dataclass(frozen=True, slots=True)
class GroupJoined:
    group: GroupSummary