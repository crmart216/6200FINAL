from dataclasses import dataclass
from ..key_models.protocols.commit import SignedCommit
from ..key_models.protocols.welcome import Welcome
from .managed_group_state import ManagedGroupState

@dataclass
class AddMemberResult:
    commit: SignedCommit
    welcome: Welcome
    state: ManagedGroupState
