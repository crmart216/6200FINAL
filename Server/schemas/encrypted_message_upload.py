from typing import Annotated

from pydantic import BaseModel, Field

from .public_key_package import Binary

NonemptyBinary = Annotated[Binary, Field(min_length=1)]


class EncryptedMessageUpload(BaseModel):
    epoch: Annotated[int, Field(strict=True, ge=0, le=2**63 - 1)]
    encrypted_sender_data: NonemptyBinary
    ciphertext: NonemptyBinary