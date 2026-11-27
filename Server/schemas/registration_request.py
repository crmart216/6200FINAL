from typing import Annotated
from uuid import UUID

from pydantic import BeforeValidator, Field, field_validator

from .public_key_package import Binary
from .registration_challenge_request import RegistrationChallengeRequest, decode_canonical_base64
from .user_registration import UserRegistration

ProofSignature = Annotated[
    Binary, BeforeValidator(decode_canonical_base64), Field(min_length=64, max_length=64),
]


class RegistrationRequest(RegistrationChallengeRequest, UserRegistration):
    challenge_id: UUID
    proof_signature_b64: ProofSignature

    @field_validator("display_name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if "\x00" in value or len(value) > 255:
            raise ValueError("Display name must be at most 255 characters and contain no NUL")
        return value

    @field_validator("websocket_url")
    @classmethod
    def validate_url_length_and_controls(cls, value: str) -> str:
        if len(value) > 2048 or any(char.isspace() or ord(char) < 32 for char in value):
            raise ValueError("WebSocket URL must be at most 2048 characters with no whitespace or controls")
        return value