import base64
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, Field, PlainSerializer, WithJsonSchema


def decode_binary(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        raise ValueError("Expected a standard Base64 string")
    return base64.b64decode(value, validate=True)


def encode_binary(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


Binary = Annotated[
    bytes,
    BeforeValidator(decode_binary),
    PlainSerializer(encode_binary, return_type=str, when_used="json"),
    WithJsonSchema({"type": "string", "format": "byte"}),
]


class PublicKeyPackagePayload(BaseModel):
    package_id: Annotated[str, Field(min_length=1)]
    credential: Binary
    init_public_key: Binary
    leaf_public_key: Binary
    signing_public_key: Binary
    signature: Binary