from collections.abc import Iterator
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from hmac import compare_digest, digest
from json import dumps
from secrets import token_bytes
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from Security.models.group_models.remove_member_result import RemoveMemberResult

from ...models.group_models.add_member_result import AddMemberResult
from ...models.group_models.group_state import EpochSecrets
from ...models.group_models.managed_group_state import ManagedGroupState
from ...models.group_models.ratchet_tree import RatchetTree, TreeNode
from ...models.key_models.key_package import PublicKeyPackage
from ...models.key_models.protocols.commit import Commit, SignedCommit
from ...models.key_models.protocols.proposal import Proposal
from ...models.key_models.protocols.welcome import Welcome
from ...models.user import User
from .group_service_helpers.commit_codec import CommitCodec
from .group_service_helpers.epoch_key_schedule import EpochKeySchedule
from .group_service_helpers.welcome_service import WelcomeService
from .key_services.key_package_service import KeyPackageService, TrustedIdentity
from .key_services.tree_key_service import TreeKeyService, TreeUpdateSecrets


"""Coordinate group creation and membership changes. Creation stores the founder's
initial state, and accepting a Welcome stores the invitee's state. Adding or
removing a member returns a staged state for the committer and a signed Commit for
other continuing members. Only the founder can remove a member."""
class GroupService:
    """Coordinate group creation and membership changes."""

    def __init__(
        self, key_packages: KeyPackageService, tree_keys: TreeKeyService
    ) -> None:
        """Configure the group service with the supplied key-package and tree-key services and return None."""
        self._key_packages: KeyPackageService = key_packages
        self._tree_keys: TreeKeyService = tree_keys
        self._commit_codec: CommitCodec = CommitCodec()
        self._welcomes: WelcomeService = WelcomeService()

    def create_group(self, creator: User, title: str) -> ManagedGroupState:
        """Create a group with the given title for the creator, store its epoch-zero state on the creator, and return that state."""
        group_id = uuid4().hex
        leaf_key = X25519PrivateKey.generate()
        public_key = leaf_key.public_key().public_bytes_raw()
        signing_key = creator.signing_key.public_key().public_bytes_raw()

        tree = RatchetTree()
        self._insert_leaf(tree, public_key)
        genesis = dumps(
            ["6200 genesis v1", group_id, title, public_key.hex(), signing_key.hex()],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        state = ManagedGroupState(
            group_id=group_id,
            title=title,
            epoch=0,
            own_leaf_index=0,
            ratchet_tree=tree,
            _private_tree_keys={0: leaf_key},
            _epoch_secrets=EpochKeySchedule.derive_epoch_secrets(token_bytes(32)),
            member_signing_keys=(signing_key,),
            transcript_hash=sha256(genesis).digest(),
        )
        creator.groups[group_id] = state
        return state

    def add_member(
        self,
        committer: User,
        state: ManagedGroupState,
        invitee: PublicKeyPackage,
        expected: TrustedIdentity,
    ) -> AddMemberResult:
        """Verify the invitee package against the expected identity and return the committer’s signed Add Commit, Welcome and next state from the supplied state."""
        sender = state.own_leaf_index
        signing_key = committer.signing_key
        if signing_key.public_key().public_bytes_raw() != state.member_signing_keys[sender]:
            raise ValueError("The committer does not own this group state.")
        if not self._key_packages.verify_package(invitee, expected):
            raise ValueError("The invitee's key package failed verification.")

        tree = self._stage_add(state, invitee)
        context = self._commit_codec.encode_context(state)
        built = self._tree_keys.build_update(state, tree, context)

        proposal = Proposal(state.group_id, state.epoch, sender, "add", invitee)
        commit = SignedCommit(
            group_id=state.group_id,
            epoch=state.epoch,
            sender_leaf_index=sender,
            proposals=[proposal],
            update_path=built.update_path,
            confirmation_tag=b"",
            signature=b"",
        )

        body = self._commit_codec.encode_body(context, commit, invitee)
        seed = EpochKeySchedule.derive_next_seed(
            self._init_secret(state), built.secrets.commit_secret, body
        )
        secrets = EpochKeySchedule.derive_epoch_secrets(seed)
        tag = digest(secrets.confirmation_key, body, "sha256")
        commit = replace(
            commit,
            confirmation_tag=tag,
            signature=signing_key.sign(body + tag),
        )
        roster = (*state.member_signing_keys, invitee.signing_public_key)
        next_state = self._finish(
            state, tree, commit, roster, built.secrets, secrets, body
        )
        welcome = self._welcomes.build_welcome(committer, invitee, next_state, seed)
        return AddMemberResult(commit, welcome, next_state)

    def remove_member(
        self,
        committer: User,
        state: ManagedGroupState,
        target_leaf_index: int,
    ) -> RemoveMemberResult:
        """Use the founder and current state to remove the target leaf index and return the signed Remove Commit and staged next state."""
        sender = state.own_leaf_index
        if sender != 0:
            raise ValueError("Only the founder at leaf 0 may remove members.")

        signing_key = committer.signing_key
        public_key = signing_key.public_key().public_bytes_raw()
        if public_key != state.require_active_signing_key(sender):
            raise ValueError("The committer does not own the founder's signing key.")

        tree, roster = self._stage_remove(state, target_leaf_index)
        context = self._commit_codec.encode_context(state)
        built = self._tree_keys.build_update(state, tree, context)

        proposal = Proposal(
            group_id=state.group_id,
            epoch=state.epoch,
            sender_leaf_index=sender,
            action="remove",
            target_leaf_index=target_leaf_index,
        )
        commit = SignedCommit(
            group_id=state.group_id,
            epoch=state.epoch,
            sender_leaf_index=sender,
            proposals=[proposal],
            update_path=built.update_path,
            confirmation_tag=b"",
            signature=b"",
        )

        body = self._commit_codec.encode_body(context, commit)
        seed = EpochKeySchedule.derive_next_seed(
            self._init_secret(state), built.secrets.commit_secret, body
        )
        secrets = EpochKeySchedule.derive_epoch_secrets(seed)
        tag = digest(secrets.confirmation_key, body, "sha256")
        commit = replace(
            commit,
            confirmation_tag=tag,
            signature=signing_key.sign(body + tag),
        )

        next_state = self._finish(
            state, tree, commit, roster, built.secrets, secrets, body
        )
        return RemoveMemberResult(commit=commit, state=next_state)

    def _stage_remove(
        self,
        state: ManagedGroupState,
        target_leaf_index: int,
    ) -> tuple[RatchetTree, tuple[bytes | None, ...]]:
        """Return a copied tree and signing roster with the target leaf index marked vacant in both, preserving indices from the supplied state."""
        if type(target_leaf_index) is not int:
            raise ValueError("The removal target must be an integer leaf index.")
        if target_leaf_index == 0:
            raise ValueError("The founder cannot remove itself.")

        # Reject negative, out-of-range, and already-vacant targets.
        _ = state.require_active_signing_key(target_leaf_index)

        tree = deepcopy(state.ratchet_tree)
        tree.blank_leaf(target_leaf_index)
        roster = list(state.member_signing_keys)
        roster[target_leaf_index] = None
        return tree, tuple(roster)

    def apply_commit(
        self,
        state: ManagedGroupState,
        commit: Commit,
    ) -> ManagedGroupState:
        """Verify a remote membership Commit against the current state and return the continuing member’s next group state."""
        if not isinstance(commit, SignedCommit):
            raise ValueError("Expected a signed Commit.")
        if (commit.group_id, commit.epoch) != (state.group_id, state.epoch):
            raise ValueError("Commit group or epoch mismatch.")

        sender = commit.sender_leaf_index
        if type(sender) is not int or sender == state.own_leaf_index:
            raise ValueError("Invalid remote committer.")
        sender_key = state.require_active_signing_key(sender)

        if len(commit.proposals) != 1:
            raise ValueError("Expected exactly one membership proposal.")
        proposal = commit.proposals[0]

        context = self._commit_codec.encode_context(state)
        # The codec checks the proposal's group, epoch, sender, action, and payload.
        body = self._commit_codec.encode_body(context, commit)
        verifier = Ed25519PublicKey.from_public_bytes(sender_key)
        verifier.verify(commit.signature, body + commit.confirmation_tag)

        roster: tuple[bytes | None, ...]
        if proposal.action == "add":
            invitee = proposal.invitee
            if invitee is None:
                raise ValueError("The Add proposal is missing its invitee.")

            identity = TrustedIdentity(invitee.credential, invitee.signing_public_key)
            if not self._key_packages.verify_package(invitee, identity):
                raise ValueError("Invalid key package in the Add proposal.")

            tree = self._stage_add(state, invitee)
            roster = (*state.member_signing_keys, invitee.signing_public_key)

        elif proposal.action == "remove":
            if sender != 0:
                raise ValueError("Only the founder at leaf 0 may remove members.")

            target = proposal.target_leaf_index
            if target is None:
                raise ValueError("The Remove proposal is missing its target.")
            if target == state.own_leaf_index:
                raise ValueError("The removed member cannot advance to the next epoch.")

            tree, roster = self._stage_remove(state, target)

        else:
            raise ValueError(f"Unsupported membership action: {proposal.action!r}.")

        update = self._tree_keys.process_updates(
            state, tree, sender, commit.update_path, context
        )
        seed = EpochKeySchedule.derive_next_seed(
            self._init_secret(state), update.commit_secret, body
        )
        secrets = EpochKeySchedule.derive_epoch_secrets(seed)
        expected_tag = digest(secrets.confirmation_key, body, "sha256")
        if not compare_digest(commit.confirmation_tag, expected_tag):
            raise ValueError("Commit confirmation failed.")

        return self._finish(state, tree, commit, roster, update, secrets, body)

    def accept_welcome(
        self, user: User, welcome: Welcome, *, expected_inviter: TrustedIdentity
    ) -> ManagedGroupState:
        """Open the user’s Welcome with the expected inviter identity, consume the private package, and store and return the joined state."""
        package = user.private_packages[welcome.package_id]
        state = self._welcomes.open_welcome(user, package, welcome, expected_inviter)
        self._key_packages.consume_package(user, welcome.package_id)
        user.groups[state.group_id] = state
        return state

    def _stage_add(
        self, state: ManagedGroupState, invitee: PublicKeyPackage
    ) -> RatchetTree:
        """Return a copy of the current state’s tree with the invitee package inserted after checking for a duplicate signing key."""
        if invitee.signing_public_key in state.member_signing_keys:
            raise ValueError("This signing identity is already in the group.")

        tree = deepcopy(state.ratchet_tree)
        _ = tree.insert_member(invitee)
        return tree

    def _finish(
        self,
        state: ManagedGroupState,
        tree: RatchetTree,
        commit: SignedCommit,
        roster: tuple[bytes | None, ...],
        update: TreeUpdateSecrets,
        secrets: EpochSecrets,
        body: bytes,
    ) -> ManagedGroupState:
        """Apply the signed Commit to the staged tree and combine the prior state, roster, update keys, epoch secrets and encoded body into the next managed state."""
        nodes = {node.node_index: node for node in self._nodes(tree)}
        sender = tree.get_leaf(commit.sender_leaf_index)
        sender.public_key = commit.update_path.leaf_public_key

        for entry in commit.update_path.nodes:
            nodes[entry.node_index].public_key = entry.public_key

        keys = {
            index: key
            for index, key in state.private_tree_keys_snapshot().items()
            if index in nodes
            and nodes[index].public_key == key.public_key().public_bytes_raw()
        }
        keys.update(update.private_tree_keys)

        return ManagedGroupState(
            group_id=state.group_id,
            title=state.title,
            epoch=state.epoch + 1,
            own_leaf_index=state.own_leaf_index,
            ratchet_tree=tree,
            _private_tree_keys=keys,
            _epoch_secrets=secrets,
            member_signing_keys=roster,
            transcript_hash=sha256(body + commit.confirmation_tag).digest(),
        )

    @staticmethod
    def _insert_leaf(tree: RatchetTree, public_key: bytes) -> None:
        # RatchetTree.insert_member only reads the package's leaf public key.
        """Insert a leaf with the given public key into the supplied tree and return None."""
        _ = tree.insert_member(PublicKeyPackage("", b"", b"", public_key, b""))

    @staticmethod
    def _nodes(tree: RatchetTree) -> Iterator[TreeNode]:
        """Yield every node reachable from the supplied tree’s root."""
        pending: list[TreeNode] = [tree.root] if tree.root is not None else []
        while pending:
            node = pending.pop()
            yield node
            pending.extend(
                child for child in (node.left, node.right) if child is not None
            )

    @staticmethod
    def _init_secret(state: ManagedGroupState) -> bytes:
        """Return the current initialization secret from the supplied managed state."""
        return state.require_init_secret()