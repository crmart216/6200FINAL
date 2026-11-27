from uuid import UUID

from pydantic import BaseModel


class PackageClaimRequest(BaseModel):
    request_id: UUID