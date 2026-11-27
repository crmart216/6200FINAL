from typing import Literal

from pydantic import BaseModel, Field

from .user_response import UserResponse


class RegistrationResponse(BaseModel):
    user: UserResponse
    api_token: str = Field(repr=False)
    token_type: Literal["Bearer"] = "Bearer"