from dataclasses import dataclass
from .group_state import GroupState

@dataclass(eq=False)
class ManagedGroupState(GroupState):
    member_signing_keys: tuple[bytes, ...] = ()
    transcript_hash: bytes = b""