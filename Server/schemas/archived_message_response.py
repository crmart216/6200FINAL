from .public_key_package import Binary
from .transcript_entry import TranscriptEntry


class ArchivedMessageResponse(TranscriptEntry):
    group_id: str
    encrypted_sender_data: Binary
    ciphertext: Binary