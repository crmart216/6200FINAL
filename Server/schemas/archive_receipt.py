from uuid import UUID

from pydantic import BaseModel


class ArchiveReceipt(BaseModel):
    group_id: str
    message_id: UUID
    transcript_index: int