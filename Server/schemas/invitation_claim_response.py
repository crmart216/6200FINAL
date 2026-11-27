from uuid import UUID

from pydantic import BaseModel

from .public_key_package import PublicKeyPackagePayload


class InvitationClaimResponse(BaseModel):
    invitation_id: UUID
    key_package: PublicKeyPackagePayload