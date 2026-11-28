from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GroupRegistrationResult:
    group_id: str
    group_name: str
    founder_user_id: str
    current_epoch: int
