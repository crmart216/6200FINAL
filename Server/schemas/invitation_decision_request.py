from typing import Literal, Self

from pydantic import BaseModel, model_validator

from .public_key_package import PublicKeyPackagePayload


class InvitationDecisionRequest(BaseModel):
    decision: Literal["accept", "decline"]
    key_package: PublicKeyPackagePayload | None = None

    @model_validator(mode="after")
    def validate_package(self) -> Self:
        if self.decision == "accept" and self.key_package is None:
            raise ValueError("Acceptance requires a key package")
        if self.decision == "decline" and "key_package" in self.model_fields_set:
            raise ValueError("Decline does not take a key package")
        return self