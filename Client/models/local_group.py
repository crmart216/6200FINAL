from dataclasses import dataclass, field
from typing import Literal

from .group_summary import GroupSummary

GroupStatus = Literal["pending", "confirmed"]


@dataclass(frozen=True, slots=True)
class LocalGroup:
    summary: GroupSummary
    snapshot: bytes = field(repr=False)
    status: GroupStatus = "pending"
