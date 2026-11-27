from sqlalchemy.sql.selectable import Select

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import ChatGroup, EpochMember, GroupEpoch, Message
from ..schemas.archive_receipt import ArchiveReceipt
from ..schemas.archived_message_response import ArchivedMessageResponse
from ..schemas.encrypted_message_upload import EncryptedMessageUpload
from ..schemas.transcript_entry import TranscriptEntry
from .groups import Conflict, Forbidden, current_epoch


class ArchiveNotFound(Exception):
    pass


def upload(
    db: Session, 
    group_id: str, 
    message_id: UUID, 
    caller: str,
    packet: EncryptedMessageUpload
) -> ArchiveReceipt:
    with db.begin():
        group = db.get(ChatGroup, group_id, with_for_update=True)
        if group is None:
            raise ArchiveNotFound("Unknown group")
        if db.get(GroupEpoch, (group_id, packet.epoch)) is None:
            raise ArchiveNotFound("Unknown epoch")
        if db.get(EpochMember, (group_id, packet.epoch, caller)) is None:
            raise Forbidden("Membership in the packet's epoch is required")

        message = db.get(Message, (group_id, message_id))
        if message is None:
            message = Message(group_id=group_id, message_id=message_id,
                                        transcript_index=group.next_transcript_index,
                                        epoch=packet.epoch, ciphertext=packet.ciphertext,
                                        encrypted_sender_data=packet.encrypted_sender_data)
            db.add(message)
            group.next_transcript_index += 1
        elif (message.epoch != packet.epoch or message.ciphertext != packet.ciphertext or message.encrypted_sender_data != packet.encrypted_sender_data):
            raise Conflict("Message ID already holds a different packet")

        return ArchiveReceipt.model_validate(message, from_attributes=True)


def readable_messages(db: Session, group_id: str, caller: str) -> Select[Message]:
    # A shared lock keeps the current roster stable until the read completes.
    if db.get(ChatGroup, group_id, with_for_update={"read": True}) is None:
        raise ArchiveNotFound("Unknown group")
    if db.get(EpochMember, (group_id, current_epoch(db, group_id), caller)) is None:
        raise Forbidden("Current group membership is required")

    epochs = select(EpochMember.epoch).where(
        EpochMember.group_id == group_id, EpochMember.user_id == caller
    )
    return select(Message).where(Message.group_id == group_id, Message.epoch.in_(epochs))


def transcript(db: Session, group_id: str, caller: str) -> list[TranscriptEntry]:
    with db.begin():
        query = readable_messages(db, group_id, caller).with_only_columns(
            Message.transcript_index, Message.message_id, Message.epoch
        ).order_by(Message.transcript_index)
        return [TranscriptEntry.model_validate(row) for row in db.execute(query).mappings()]


def retrieve(db: Session, group_id: str, index: int, caller: str) -> ArchivedMessageResponse:
    with db.begin():
        query = readable_messages(db, group_id, caller).where(Message.transcript_index == index)
        message = db.scalars(query).one_or_none()
        if message is None:
            raise ArchiveNotFound("Unknown transcript entry")
        return ArchivedMessageResponse.model_validate(message, from_attributes=True)