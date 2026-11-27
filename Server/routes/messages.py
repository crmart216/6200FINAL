from collections.abc import Generator
from contextlib import contextmanager
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Path

from ..schemas.archive_receipt import ArchiveReceipt
from ..schemas.archived_message_response import ArchivedMessageResponse
from ..schemas.encrypted_message_upload import EncryptedMessageUpload
from ..schemas.transcript_entry import TranscriptEntry
from ..services import archive
from .groups import Caller, Database, GroupId, group_errors

router = APIRouter()
Index = Annotated[int, Path(gt=0, le=2**63 - 1)]


@contextmanager
def archive_errors() -> Generator[None, None, None]:
    with group_errors():
        try:
            yield
        except archive.ArchiveNotFound as exc:
            raise HTTPException(404, str(exc)) from exc


@router.put("/{group_id}/messages/{message_id}")
def upload(
    group_id: GroupId, 
    message_id: UUID, 
    packet: EncryptedMessageUpload,
    caller: Caller, 
    db: Database
) -> ArchiveReceipt:
    with archive_errors():
        return archive.upload(db, group_id, message_id, caller.user_id, packet)


@router.get("/{group_id}/messages")
def transcript(
    group_id: GroupId, 
    caller: Caller, 
    db: Database
) -> list[TranscriptEntry]:
    with archive_errors():
        return archive.transcript(db, group_id, caller.user_id)


@router.get("/{group_id}/messages/{index}")
def retrieve(
    group_id: GroupId, 
    index: Index, 
    caller: Caller,
    db: Database
) -> ArchivedMessageResponse:
    with archive_errors():
        return archive.retrieve(db, group_id, index, caller.user_id)