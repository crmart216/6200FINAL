from collections.abc import Callable
from queue import Empty
from typing import TypeAlias

import pytest

from Client.models.chat_message import ChatMessage
from Client.models.group_joined import GroupJoined
from Client.models.group_member import GroupMember
from Client.models.group_members_updated import GroupMembersUpdated
from Client.models.group_summary import GroupSummary
from Client.models.invitation import Invitation
from Client.models.message_received import MessageReceived
from Client.models.user_profile import UserProfile
from Client.prototype_backend import PrototypeBackend


Demo: TypeAlias = tuple[PrototypeBackend, list[tuple[int, Callable[[], None]]]]


@pytest.fixture
def demo() -> Demo:
    scheduled: list[tuple[int, Callable[[], None]]] = []

    def schedule(delay: int, callback: Callable[[], None]) -> None:
        scheduled.append((delay, callback))

    return PrototypeBackend(schedule), scheduled


def test_signup_and_sample_data(demo: Demo) -> None:
    backend, _ = demo
    assert backend.load_session() is None
    with pytest.raises(ValueError, match="display name"):
        _ = backend.register("   ")
    user = backend.register("  Ryan Martin  ")
    assert backend.load_session() == user
    assert user.display_name == "Ryan Martin"
    assert isinstance(user, UserProfile)
    peers = backend.list_users()
    assert all(isinstance(peer, UserProfile) for peer in peers)
    namesakes = [peer.id for peer in peers if peer.display_name == "Jordan Lee"]
    assert len(set(namesakes)) == 2
    assert len(backend.list_invitations()) == 1


def test_group_creation_and_targeted_invitation(demo: Demo) -> None:
    backend, _ = demo
    user = backend.register("Ryan")
    with pytest.raises(ValueError, match="group name"):
        _ = backend.create_group(" ")
    group = backend.create_group(" Lab Team ")
    assert isinstance(group, GroupSummary)
    assert group.name == "Lab Team"
    assert group in backend.list_groups()
    assert backend.list_group_members(group.id) == [GroupMember(user.id, user.display_name, True)]
    item = backend.invite_user(group.id, "jordan-k-lee")
    assert isinstance(item, Invitation)
    assert item.status == "pending"
    assert item.invitee.id == "jordan-k-lee"
    assert item in backend.list_invitations()
    assert backend.list_group_members(group.id) == [GroupMember(user.id, user.display_name, True)]
    with pytest.raises(ValueError, match="already has"):
        _ = backend.invite_user(group.id, item.invitee.id)


def test_accept_waits_for_separate_join_event(demo: Demo) -> None:
    backend, scheduled = demo
    user = backend.register("Ryan")
    invitation, = backend.list_invitations()
    assert backend.respond_to_invitation(invitation.id, "accept").status == "joining"
    assert backend.list_invitations()[0].status == "joining"
    assert invitation.group not in backend.list_groups()
    with pytest.raises(Empty):
        _ = backend.events.get_nowait()
    with pytest.raises(ValueError, match="pending incoming"):
        _ = backend.respond_to_invitation(invitation.id, "accept")
    (delay, finish_join), = scheduled
    assert delay > 0
    finish_join()
    event = backend.events.get_nowait()
    assert event == GroupJoined(invitation.group)
    assert invitation.group in backend.list_groups()
    assert GroupMember(user.id, user.display_name, False) in backend.list_group_members(invitation.group.id)
    assert backend.list_invitations()[0].status == "joined"


def test_decline_does_not_schedule_join(demo: Demo) -> None:
    backend, scheduled = demo
    _ = backend.register("Ryan")
    invitation, = backend.list_invitations()
    assert backend.respond_to_invitation(invitation.id, "decline").status == "declined"
    assert invitation.group not in backend.list_groups()
    assert not scheduled
    assert backend.events.empty()


def test_message_submission_and_one_shot_failure(demo: Demo) -> None:
    backend, _ = demo
    user = backend.register("Ryan")
    group, = backend.list_groups()
    with pytest.raises(ValueError, match="Write a message"):
        _ = backend.send_message(group.id, " ")
    backend.simulate_send_failure()
    with pytest.raises(ValueError, match="Simulated send failed"):
        _ = backend.send_message(group.id, "Checking in.")
    message = backend.send_message(group.id, "Checking in.")
    assert isinstance(message, ChatMessage)
    assert (message.group_id, message.sender, message.text) == (group.id, user, "Checking in.")
    assert backend.send_message(group.id, "Checking in.").id != message.id
    assert backend.events.empty()  # The frontend renders the returned message once.


def test_simulated_incoming_message(demo: Demo) -> None:
    backend, scheduled = demo
    user = backend.register("Ryan")
    group, = backend.list_groups()
    backend.simulate_incoming(group.id)
    assert backend.events.empty()
    (delay, receive), = scheduled
    assert delay > 0
    receive()
    event = backend.events.get_nowait()
    assert isinstance(event, MessageReceived)
    assert event.message.group_id == group.id
    assert event.message.sender != user
    assert backend.events.empty()


def test_founder_removal_updates_roster_and_emits_event(demo: Demo) -> None:
    backend, scheduled = demo
    founder = backend.register("Ryan")
    group, = backend.list_groups()
    with pytest.raises(ValueError, match="other than the founder"):
        backend.remove_member(group.id, founder.id)
    assert backend.events.empty()
    backend.remove_member(group.id, "bob")
    event = backend.events.get_nowait()
    expected = (
        GroupMember(founder.id, founder.display_name, True),
        GroupMember("alice", "Alice Chen", False),
    )
    assert event == GroupMembersUpdated(group.id, expected)
    assert backend.list_group_members(group.id) == list(expected)

    invitation, = backend.list_invitations()
    _ = backend.respond_to_invitation(invitation.id, "accept")
    scheduled.pop()[1]()
    _ = backend.events.get_nowait()
    with pytest.raises(ValueError, match="Only the founder"):
        backend.remove_member(invitation.group.id, "jordan-lee")
    assert backend.events.empty()