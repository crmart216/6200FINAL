from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GroupSummary:
    id: str
    name: str
    founder_id: str