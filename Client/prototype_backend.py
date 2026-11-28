"""In-memory translation layer for the Tkinter prototype."""

from collections.abc import Callable
from dataclasses import replace
from queue import Queue
from uuid import uuid4

from .models.chat_message import ChatMessage
from .models.group_joined import GroupJoined
from .models.group_member import GroupMember
from .models.group_members_updated import GroupMembersUpdated
from .models.group_summary import GroupSummary
from .models.invitation import Invitation
from .models.message_received import MessageReceived
from .models.types import BackendEvent, InvitationDecision, InvitationStatus
from .models.user_profile import UserProfile

_RESPONSE_STATUSES: dict[str, InvitationStatus] = {"accept": "joining", "decline": "declined"}


class PrototypeBackend:
    """Schedule delayed changes on the same event loop that calls this object."""

    def __init__(self, schedule: Callable[[int, Callable[[], None]], object]) -> None:
        self._schedule: Callable[[int, Callable[[], None]], object] = schedule
        self.events: Queue[BackendEvent] = Queue()
        self._session: UserProfile | None = None
        self._users: dict[str, UserProfile] = {
            user.id: user for user in (
                UserProfile("alice", "Alice Chen"),
                UserProfile("bob", "Bob Patel"),
                UserProfile("jordan-lee", "Jordan Lee"),
                UserProfile("jordan-k-lee", "Jordan Lee"),
            )
        }
        self._groups: dict[str, GroupSummary] = {}
        self._members: dict[str, list[str]] = {}
        self._invitations: dict[str, Invitation] = {}
        self._fail_next: bool = False

    def load_session(self) -> UserProfile | None:
        return self._session

    def register(self, display_name: str) -> UserProfile:
        name = self._required(display_name, "Enter a display name.")
        if self._session is not None:
            raise ValueError("This demo already has a registered user.")
        user = UserProfile(uuid4().hex, name)
        self._session = self._users[user.id] = user
        project = self.create_group("6200 Project Chat")
        self._members[project.id].extend(["alice", "bob"])
        alice = self._users["alice"]
        study = GroupSummary("study-group", "Study Group", alice.id)
        self._groups[study.id] = study
        self._members[study.id] = [alice.id, "jordan-lee"]
        self._invitations["study-invite"] = Invitation("study-invite", study, alice, user)
        return user

    def list_users(self) -> list[UserProfile]:
        user = self._current_user()
        return [peer for peer in self._users.values() if peer.id != user.id]

    def list_groups(self) -> list[GroupSummary]:
        user = self._current_user()
        return [group for group in self._groups.values() if user.id in self._members[group.id]]

    def create_group(self, name: str) -> GroupSummary:
        founder = self._current_user()
        group = GroupSummary(uuid4().hex, self._required(name, "Enter a group name."), founder.id)
        self._groups[group.id] = group
        self._members[group.id] = [founder.id]
        return group

    def list_group_members(self, group_id: str) -> list[GroupMember]:
        group = self._joined_group(group_id)
        return [
            GroupMember(user_id, self._users[user_id].display_name, user_id == group.founder_id)
            for user_id in self._members[group.id]
        ]

    def invite_user(self, group_id: str, user_id: str) -> Invitation:
        group = self._owned_group(group_id)
        invitee = self._users.get(user_id)
        if invitee is None or user_id in self._members[group.id]:
            raise ValueError("Choose a registered user outside this group.")
        if any(
            item.group.id == group.id and item.invitee.id == user_id and item.status == "pending"
            for item in self._invitations.values()
        ):
            raise ValueError("This user already has a pending invitation.")
        item = Invitation(uuid4().hex, group, self._current_user(), invitee)
        self._invitations[item.id] = item
        return item

    def list_invitations(self) -> list[Invitation]:
        _ = self._current_user()
        return list(self._invitations.values())

    def respond_to_invitation(self, invitation_id: str, decision: InvitationDecision) -> Invitation:
        user = self._current_user()
        item = self._invitations.get(invitation_id)
        if item is None or item.invitee.id != user.id or item.status != "pending":
            raise ValueError("Choose a pending incoming invitation.")
        status = _RESPONSE_STATUSES.get(decision)
        if status is None:
            raise ValueError("Choose accept or decline.")
        updated = replace(item, status=status)
        self._invitations[item.id] = updated
        if decision == "accept":
            def join() -> None:
                self._members[item.group.id].append(user.id)
                self._invitations[item.id] = replace(updated, status="joined")
                self.events.put(GroupJoined(item.group))

            _ = self._schedule(1000, join)
        return updated

    def send_message(self, group_id: str, text: str) -> ChatMessage:
        group = self._joined_group(group_id)
        text = self._required(text, "Write a message first.")
        if self._fail_next:
            self._fail_next = False
            raise ValueError("Simulated send failed. Try again.")
        return ChatMessage(uuid4().hex, group.id, self._current_user(), text)

    def remove_member(self, group_id: str, user_id: str) -> None:
        group = self._owned_group(group_id)
        members = self._members[group.id]
        if user_id == group.founder_id or user_id not in members:
            raise ValueError("Choose a member other than the founder.")
        members.remove(user_id)
        self.events.put(GroupMembersUpdated(group.id, tuple(self.list_group_members(group.id))))

    def simulate_send_failure(self) -> None:
        self._fail_next = True

    def simulate_incoming(self, group_id: str) -> None:
        group = self._joined_group(group_id)
        current = self._current_user()
        peer_id = next((user_id for user_id in self._members[group.id] if user_id != current.id), None)
        if peer_id is None:
            raise ValueError("Choose a conversation with another member to simulate a reply.")

        def receive() -> None:
            if peer_id in self._members[group.id]:
                message = ChatMessage(
                    uuid4().hex, group.id, self._users[peer_id], "Are we still on for our next project check-in?"
                )
                self.events.put(MessageReceived(message))

        _ = self._schedule(500, receive)

    @staticmethod
    def _required(value: str, error: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError(error)
        return value

    def _current_user(self) -> UserProfile:
        if self._session is None:
            raise ValueError("Register first.")
        return self._session

    def _joined_group(self, group_id: str) -> GroupSummary:
        user = self._current_user()
        members = self._members.get(group_id)
        if members is None or user.id not in members:
            raise ValueError("Choose a group you have joined.")
        return self._groups[group_id]

    def _owned_group(self, group_id: str) -> GroupSummary:
        group = self._joined_group(group_id)
        if group.founder_id != self._current_user().id:
            raise ValueError("Only the founder can manage membership.")
        return group