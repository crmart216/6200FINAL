from pydantic import BaseModel, Field

from .public_key_package import Binary


class UserResponse(BaseModel):
    user_id: str
    display_name: str
    websocket_url: str
    signing_public_key_b64: Binary = Field(validation_alias="signing_public_key")