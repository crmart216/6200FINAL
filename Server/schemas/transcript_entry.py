from uuid import UUID

from pydantic import BaseModel


class TranscriptEntry(BaseModel):
    transcript_index: int
    message_id: UUID
    epoch: int