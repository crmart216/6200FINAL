from typing import Annotated

from pydantic import BaseModel, BeforeValidator, Field, field_validator

from .public_key_package import Binary, decode_binary, encode_binary


def decode_canonical_base64(value: object) -> bytes:
    decoded = decode_binary(value)
    if isinstance(value, str) and encode_binary(decoded) != value:
        raise ValueError("Use canonical standard Base64")
    return decoded


PublicSigningKey = Annotated[
    Binary, BeforeValidator(decode_canonical_base64), Field(min_length=32, max_length=32),
]


class RegistrationChallengeRequest(BaseModel):
    user_id: Annotated[str, Field(max_length=255)]
    signing_public_key_b64: PublicSigningKey

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, value: str) -> str:
        if not value.strip() or "\x00" in value:
            raise ValueError("User ID must be nonblank and contain no NUL")
        return value