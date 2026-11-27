from collections.abc import Generator
from contextlib import contextmanager
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Body, HTTPException, Path

from ..schemas.archive_receipt import ArchiveReceipt
from ..schemas.archived_message_response import ArchivedMessageResponse
from ..schemas.encrypted_message_upload import EncryptedMessageUpload
from ..schemas.transcript_entry import TranscriptEntry
from ..services import archive
from .groups import Caller, Database, GroupId, group_errors

router = APIRouter(tags=["Messages"], responses={401: {"description": "Missing or invalid bearer token"}})
Index = Annotated[int, Path(gt=0, le=2**63 - 1)]


UploadBody = Annotated[EncryptedMessageUpload, Body(examples=[{
    "epoch": 0, "encrypted_sender_data": "AQI=", "ciphertext": "AwQ="
}])]


@contextmanager
def archive_errors() -> Generator[None, None, None]:
    with group_errors():
        try:
            yield
        except archive.ArchiveNotFound as exc:
            raise HTTPException(404, str(exc)) from exc


@router.put("/{group_id}/messages/{message_ref}", summary="Archive an encrypted message",
            responses={403: {"description": "Caller was outside the packet epoch"},
                        404: {"description": "Unknown group or epoch"},
                        409: {"description": "Message UUID already holds different content"}})

def upload(
    group_id: GroupId, 
    message_ref: UUID, 
    packet: UploadBody,
    caller: Caller, 
    db: Database
) -> ArchiveReceipt:
    """Supply a client UUID and standard Base64 for encrypted_sender_data and ciphertext.
    Identical retries return the original server-assigned transcript index.
    """
    with archive_errors():
        return archive.upload(db, group_id, message_ref, caller.user_id, packet)


@router.get("/{group_id}/messages", summary="List readable transcript entries",
            responses={403: {"description": "Current membership required"},
                        404: {"description": "Unknown group"}})

def transcript(
    group_id: GroupId, 
    caller: Caller, 
    db: Database
) -> list[TranscriptEntry]:
    """Current members see entries from their own epochs in ascending order with original indices."""
    with archive_errors():
        return archive.transcript(db, group_id, caller.user_id)


@router.get("/{group_id}/messages/{message_ref}", summary="Retrieve ciphertext by transcript index",
            responses={403: {"description": "Current membership required"},
                        404: {"description": "Unknown group or index outside readable history"}})

def retrieve(
    group_id: GroupId, 
    message_ref: Index, 
    caller: Caller,
    db: Database
) -> ArchivedMessageResponse:
    """Supply a positive transcript index. Reading requires current and message-epoch membership."""
    with archive_errors():
        return archive.retrieve(db, group_id, message_ref, caller.user_id)