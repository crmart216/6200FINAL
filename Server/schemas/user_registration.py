from typing import Annotated

from pydantic import BaseModel, StringConstraints, WebsocketUrl, field_validator


class UserRegistration(BaseModel):
    display_name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
    websocket_url: str

    @field_validator("websocket_url")
    @classmethod
    def validate_listener(cls, value: str) -> str:
        if not value.lower().startswith(("ws://", "wss://")) or not WebsocketUrl(value).host:
            raise ValueError("Expected a ws:// or wss:// URL with a hostname")
        return value