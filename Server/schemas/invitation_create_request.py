from pydantic import BaseModel, field_validator


class InvitationCreateRequest(BaseModel):
    invitee_user_id: str

    @field_validator("invitee_user_id")
    @classmethod
    def validate_user_id(cls, value: str) -> str:
        if not value.strip() or "\x00" in value:
            raise ValueError("Invitee user ID must be nonblank and contain no NUL")
        return value