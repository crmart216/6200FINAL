from typing import Annotated

from pydantic import BaseModel, StringConstraints


GroupName = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, pattern=r"^[^\x00]+$"),
]


class GroupRegistration(BaseModel):
    group_name: GroupName


class GroupResponse(BaseModel):
    group_id: str
    group_name: str
    founder_user_id: str
    current_epoch: int