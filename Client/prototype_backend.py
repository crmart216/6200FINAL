"""In-memory translation layer for the Tkinter prototype."""

from collections.abc import Callable
from dataclasses import dataclass, replace
from queue import Queue
from uuid import uuid4


@dataclass(frozen=True)
class User:
    id: str
    display_name: str


@dataclass(frozen=True)
class Group:
    id: str
    name: str
    founder_id: str


@dataclass(frozen=True)
class Invitation:
    id: str
    group: Group
    inviter: User
    invitee: User
    status: str = "pending"


@dataclass(frozen=True)
class Message:
    id: str
    group_id: str
    sender: User
    text: str


@dataclass(frozen=True)
class Event:
    kind: str
    group_id: str
    message: Message | None = None


class PrototypeBackend:
    """Schedule delayed changes on the same event loop that calls this object."""

    def __init__(self, schedule: Callable[[int, Callable[[], None]], object]) -> None:
        self._schedule: Callable[[int, Callable[[], None]], object] = schedule
        self.events: Queue[Event] = Queue()
        self._session: User | None = None
        self._users: dict[str, User] = {
            user.id: user for user in (
                User("alice", "Alice Chen"),
                User("bob", "Bob Patel"),
                User("jordan-lee", "Jordan Lee"),
                User("jordan-k-lee", "Jordan Lee"),
            )
        }
        self._groups: dict[str, Group] = {}
        self._members: dict[str, list[str]] = {}
        self._invitations: dict[str, Invitation] = {}
        self._fail_next: bool = False

    def load_session(self) -> User | None:
        return self._session

    def register(self, display_name: str) -> User:
        name = self._required(display_name, "Enter a display name.")
        if self._session is not None:
            raise ValueError("This demo already has a registered user.")
        user = User(uuid4().hex, name)
        self._session = self._users[user.id] = user
        project = self.create_group("6200 Project Chat")
        self._members[project.id].extend(["alice", "bob"])
        alice = self._users["alice"]
        study = Group("study-group", "Study Group", alice.id)
        self._groups[study.id] = study
        self._members[study.id] = [alice.id, "jordan-lee"]
        self._invitations["study-invite"] = Invitation("study-invite", study, alice, user)
        return user

    def list_users(self) -> list[User]:
        user = self._current_user()
        return [peer for peer in self._users.values() if peer.id != user.id]

    def list_groups(self) -> list[Group]:
        user = self._current_user()
        return [group for group in self._groups.values() if user.id in self._members[group.id]]

    def create_group(self, name: str) -> Group:
        founder = self._current_user()
        group = Group(uuid4().hex, self._required(name, "Enter a group name."), founder.id)
        self._groups[group.id] = group
        self._members[group.id] = [founder.id]
        return group

    def list_group_members(self, group_id: str) -> list[User]:
        group = self._joined_group(group_id)
        return [self._users[user_id] for user_id in self._members[group.id]]

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

    def respond_to_invitation(self, invitation_id: str, decision: str) -> Invitation:
        user = self._current_user()
        item = self._invitations.get(invitation_id)
        if item is None or item.invitee.id != user.id or item.status != "pending":
            raise ValueError("Choose a pending incoming invitation.")
        if decision not in ("accept", "decline"):
            raise ValueError("Choose accept or decline.")
        updated = replace(item, status="joining" if decision == "accept" else "declined")
        self._invitations[item.id] = updated
        if decision == "accept":
            def join() -> None:
                self._members[item.group.id].append(user.id)
                self._invitations[item.id] = replace(updated, status="joined")
                self.events.put(Event("group_joined", item.group.id))

            _ = self._schedule(1000, join)
        return updated

    def send_message(self, group_id: str, text: str) -> Message:
        group = self._joined_group(group_id)
        text = self._required(text, "Write a message first.")
        if self._fail_next:
            self._fail_next = False
            raise ValueError("Simulated send failed. Try again.")
        return Message(uuid4().hex, group.id, self._current_user(), text)

    def remove_member(self, group_id: str, user_id: str) -> None:
        group = self._owned_group(group_id)
        members = self._members[group.id]
        if user_id == group.founder_id or user_id not in members:
            raise ValueError("Choose a member other than the founder.")
        members.remove(user_id)
        self.events.put(Event("group_members_updated", group.id))

    def simulate_send_failure(self) -> None:
        self._fail_next = True

    def simulate_incoming(self, group_id: str) -> None:
        group = self._joined_group(group_id)
        current = self._current_user()
        peer = next((member for member in self.list_group_members(group_id) if member != current), None)
        if peer is None:
            raise ValueError("Choose a conversation with another member to simulate a reply.")

        def receive() -> None:
            if peer.id in self._members[group.id]:
                message = Message(uuid4().hex, group.id, peer, "Are we still on for our next project check-in?")
                self.events.put(Event("message_received", group.id, message))

        _ = self._schedule(500, receive)

    @staticmethod
    def _required(value: str, error: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError(error)
        return value

    def _current_user(self) -> User:
        if self._session is None:
            raise ValueError("Register first.")
        return self._session

    def _joined_group(self, group_id: str) -> Group:
        user = self._current_user()
        members = self._members.get(group_id)
        if members is None or user.id not in members:
            raise ValueError("Choose a group you have joined.")
        return self._groups[group_id]

    def _owned_group(self, group_id: str) -> Group:
        group = self._joined_group(group_id)
        if group.founder_id != self._current_user().id:
            raise ValueError("Only the founder can manage membership.")
        return group
