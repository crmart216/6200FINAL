from dataclasses import dataclass

from Security.models.group_models.managed_group_state import ManagedGroupState
from Security.models.key_models.protocols.commit import SignedCommit


@dataclass
class EpochRotationResult:
    """A signed rotation Commit and the committer's staged next state."""

    commit: SignedCommit
    state: ManagedGroupState
