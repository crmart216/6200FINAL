from dataclasses import dataclass

from Security.models.group_models.managed_group_state import ManagedGroupState
from Security.models.key_models.protocols.commit import SignedCommit

@dataclass
class RemoveMemberResult:
    commit: SignedCommit
    state: ManagedGroupState