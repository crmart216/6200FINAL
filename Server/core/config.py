import base64
import binascii
from functools import lru_cache
from typing import ClassVar, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict, SettingsError
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


class DemoIdentity(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        hide_input_in_errors=True,
    )

    user_id: str
    api_token: SecretStr
    signing_public_key_b64: str

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("user_id is required")
        return value

    @field_validator("api_token")
    @classmethod
    def validate_token(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("api_token is required")
        return value

    @field_validator("signing_public_key_b64")
    @classmethod
    def validate_public_key(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("Invalid public key encoding") from None
        if len(decoded) != 32:
            raise ValueError("Expected a 32-byte Ed25519 public key")
        return value

    @property
    def signing_public_key(self) -> bytes:
        return base64.b64decode(self.signing_public_key_b64, validate=True)


class Settings(BaseSettings):
    model_config: ClassVar[SettingsConfigDict] = SettingsConfigDict(
        env_prefix="SERVER_",
        frozen=True,
        hide_input_in_errors=True,
    )

    database_url: SecretStr
    demo_identities: tuple[DemoIdentity, ...] = ()
    public_signup_enabled: bool = False

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: SecretStr) -> SecretStr:
        try:
            url = make_url(value.get_secret_value())
        except (ArgumentError, ValueError):
            raise ValueError("Invalid database URL") from None
        if url.drivername != "postgresql+psycopg":
            raise ValueError("Expected a postgresql+psycopg URL")
        return value

    @model_validator(mode="after")
    def validate_unique_identities(self) -> Self:
        identities = self.demo_identities
        if len({identity.user_id for identity in identities}) != len(identities):
            raise ValueError("Duplicate user ID")
        if len({identity.api_token for identity in identities}) != len(identities):
            raise ValueError("Duplicate API token")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    try:
        # BaseSettings supplies required fields from the environment.
        return Settings()  # pyright: ignore[reportCallIssue]
    except (SettingsError, ValidationError):
        pass

    # Raise outside the handler so the original inputs cannot enter a traceback.
    raise ValueError("Invalid SERVER_DATABASE_URL, SERVER_DEMO_IDENTITIES, or SERVER_PUBLIC_SIGNUP_ENABLED")