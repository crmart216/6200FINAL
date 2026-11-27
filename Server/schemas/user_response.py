from pydantic import BaseModel


class UserResponse(BaseModel):
    user_id: str
    display_name: str
    websocket_url: str