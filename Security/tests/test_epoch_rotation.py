from dataclasses import replace

import pytest
from cryptography.exceptions import InvalidSignature

from Security.models.key_models.protocols.proposal import Proposal
from Security.models.user import User
from Security.services.group_services.group_service import GroupService
from Security.services.group_services.key_services.key_package_service import (
    KeyPackageService, TrustedIdentity,
)
from Security.services.group_services.key_services.tree_key_service import TreeKeyService
from Security.services.message_services.message_service import MessageService


def identity(user):
    return TrustedIdentity(user.user_id.encode(), user.signing_key.public_key().public_bytes_raw())


@pytest.fixture
def chat():
    packages = KeyPackageService()
    groups = GroupService(packages, TreeKeyService())
    messages = MessageService()
    alice, bob, charlie = [User(name, name) for name in ("alice", "bob", "charlie")]
    state = groups.create_group(alice, "Rotation test")
    gid = state.group_id
    members = [alice]
    for peer in (bob, charlie):
        expected = identity(peer)
        package, = packages.generate_packages(peer, expected.credential, 1)
        result = groups.add_member(alice, alice.groups[gid], package, expected)
        for existing in members[1:]:
            existing.groups[gid] = groups.apply_commit(existing.groups[gid], result.commit)
        groups.accept_welcome(peer, result.welcome, expected_inviter=identity(alice))
        alice.groups[gid] = result.state
        members.append(peer)
    return groups, messages, members, gid


def send(messages, members, gid, sender, text):
    packet = messages.encrypt(sender, sender.groups[gid], text)
    for peer in members:
        if peer is not sender:
            assert messages.decrypt(peer.groups[gid], packet) == text
    return packet


def rotate(groups, members, gid):
    alice = members[0]
    result = groups.rotate_epoch(alice, alice.groups[gid])
    for peer in members[1:]:
        peer.groups[gid] = groups.apply_commit(peer.groups[gid], result.commit)
    alice.groups[gid] = result.state
    return result.commit


def test_seven_messages_rotate_and_repeat(chat):
    groups, messages, members, gid = chat
    alice = members[0]
    original_epoch = alice.groups[gid].epoch
    roster = alice.groups[gid].member_signing_keys
    for cycle in range(2):
        old_secret = alice.groups[gid].epoch_secrets.encryption_secret
        for i in range(7):
            packet = send(messages, members, gid, members[i % 3], str(i))
            assert packet.epoch == original_epoch + cycle
            assert all(p.groups[gid].epoch_message_count == i + 1 for p in members)
            assert all(p.groups[gid].rotation_due == (i == 6) for p in members)
        with pytest.raises(ValueError, match="rotation required"):
            messages.encrypt(alice, alice.groups[gid], "too early")
        commit = rotate(groups, members, gid)
        assert commit.proposals[0].action == "rotate"
        assert all(p.groups[gid].epoch == original_epoch + cycle + 1 for p in members)
        assert all(p.groups[gid].epoch_message_count == 0 for p in members)
        assert all(p.groups[gid].member_signing_keys == roster for p in members)
        new_secret = alice.groups[gid].epoch_secrets.encryption_secret
        assert new_secret != old_secret
        assert all(p.groups[gid].epoch_secrets.encryption_secret == new_secret for p in members)
        with pytest.raises(ValueError, match="epoch mismatch"):
            messages.decrypt(members[1].groups[gid], packet)
        with pytest.raises(ValueError, match="epoch mismatch"):
            groups.apply_commit(members[1].groups[gid], commit)
    assert send(messages, members, gid, members[1], "new epoch works").epoch == original_epoch + 2


def test_early_rotation_and_replay_do_not_advance(chat):
    groups, messages, members, gid = chat
    alice, bob, charlie = members
    with pytest.raises(ValueError, match="limit has not been reached"):
        groups.rotate_epoch(alice, alice.groups[gid])
    packet = send(messages, members, gid, alice, "first")
    with pytest.raises(ValueError, match="replayed or out of order"):
        messages.decrypt(bob.groups[gid], packet)
    assert bob.groups[gid].epoch_message_count == 1
    for i in range(5):
        send(messages, members, gid, members[i % 3], str(i))
    seventh = messages.encrypt(alice, alice.groups[gid], "seventh")
    assert messages.decrypt(charlie.groups[gid], seventh) == "seventh"
    result = groups.rotate_epoch(alice, alice.groups[gid])
    with pytest.raises(ValueError, match="remaining epoch messages"):
        groups.apply_commit(bob.groups[gid], result.commit)
    assert bob.groups[gid].epoch_message_count == 6
    assert messages.decrypt(bob.groups[gid], seventh) == "seventh"
    with pytest.raises(ValueError, match="Only the founder"):
        groups.rotate_epoch(bob, bob.groups[gid])
    bad = replace(result.commit, signature=b"\x00" * 64)
    with pytest.raises(InvalidSignature):
        groups.apply_commit(bob.groups[gid], bad)
    assert groups.apply_commit(bob.groups[gid], result.commit).epoch_message_count == 0
    with pytest.raises(ValueError, match="membership payload"):
        Proposal(gid, bob.groups[gid].epoch, 0, "rotate", target_leaf_index=1)


def test_membership_change_resets_count(chat):
    groups, messages, members, gid = chat
    alice, bob, charlie = members
    send(messages, members, gid, alice, "before removal")
    old_state = charlie.groups[gid]
    result = groups.remove_member(alice, alice.groups[gid], old_state.own_leaf_index)
    bob.groups[gid] = groups.apply_commit(bob.groups[gid], result.commit)
    alice.groups[gid] = result.state
    remaining = [alice, bob]
    assert all(p.groups[gid].epoch_message_count == 0 for p in remaining)
    for i in range(7):
        send(messages, remaining, gid, remaining[i % 2], str(i))
    rotate(groups, remaining, gid)
    packet = send(messages, remaining, gid, alice, "after rotation")
    with pytest.raises(ValueError, match="epoch mismatch"):
        messages.decrypt(old_state, packet)
