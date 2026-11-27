from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class EpochRosterUpdate(BaseModel):
    member_user_ids: Annotated[list[str], Field(min_length=1)]
    invitation_id: UUID | None = None

    @field_validator("member_user_ids")
    @classmethod
    def validate_members(cls, members: list[str]) -> list[str]:
        if any(not member.strip() or "\x00" in member for member in members):
            raise ValueError("Every member must have a nonblank user ID")
        if len(set(members)) != len(members):
            raise ValueError("Member user IDs must be unique")
        return members


class EpochRosterResponse(BaseModel):
    group_id: str
    epoch: int
    member_user_ids: list[str]