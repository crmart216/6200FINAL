from Security.models.key_models.protocols.application_message import ApplicationMessage
from Security.models.key_models.protocols.commit import SignedCommit
from Security.models.user import User
from Security.services.group_services.group_service import GroupService
from Security.services.group_services.key_services.key_package_service import (
    KeyPackageService,
    TrustedIdentity,
)
from Security.services.group_services.key_services.tree_key_service import TreeKeyService
from Security.services.message_services.delivery_service import DeliveryService
from Security.services.message_services.evil_message_service import MessageService
from Security.models.group_models.managed_group_state import ManagedGroupState
from Security.mallory import *

def main() -> None:
    packages = KeyPackageService()
    groups = GroupService(packages, TreeKeyService())
    messages = MessageService()
    delivery = DeliveryService()
    mallory_sniff = MallorySniff()

    alice, bob, charlie, eve = (
        User(name.lower(), name) for name in ("Alice", "Bob", "Charlie", "Eve")
    )
    founder = groups.create_group(alice, "6200 Project Chat")
    group_id = founder.group_id
    members = [alice]

    def identity(user: User) -> TrustedIdentity:
        return TrustedIdentity(
            user.user_id.encode(),
            user.signing_key.public_key().public_bytes_raw(),
        )

    def announce(event: str) -> None:
        names = ", ".join(user.display_name for user in members)
        print(f"\nEpoch {founder.epoch} | {event} | Members: {names}")

    def deliver_commit(commit: SignedCommit, peers: list[User]) -> None:
        delivery.send_message([peer.user_id for peer in peers], commit)
        for peer in peers:
            received, = delivery.receive_messages(peer.user_id)
            if not isinstance(received, SignedCommit):
                raise RuntimeError("Expected a membership Commit.")

            state = peer.groups[group_id]
            if not isinstance(state, ManagedGroupState):
                raise RuntimeError(f"{peer.display_name} has no managed state for this group.")

            peer.groups[group_id] = groups.apply_commit(state, received)
            

    def add(user: User) -> None:
        nonlocal founder
        expected = identity(user)
        package, = packages.generate_packages(user, expected.credential, 1)
        result = groups.add_member(alice, founder, package, expected)

        # Existing members apply the Commit. The new member joins via Welcome.
        deliver_commit(result.commit, [peer for peer in members if peer is not alice])
        groups.accept_welcome(user, result.welcome, expected_inviter=identity(alice))
        founder = alice.groups[group_id] = result.state
        members.append(user)
        announce(f"Alice added {user.display_name}")

    def say(sender: User, text: str) -> ApplicationMessage:
        packet = messages.encrypt(sender, sender.groups[group_id], text)
        peers = [peer for peer in members if peer is not sender]
        delivery.send_message([peer.user_id for peer in peers], packet)

        for peer in peers:
            received, = delivery.receive_messages(peer.user_id)
            if not isinstance(received, ApplicationMessage):
                raise RuntimeError("Expected an application message.")
            if messages.decrypt(peer.groups[group_id], received) != text:
                raise RuntimeError(f"{peer.display_name} received a different message.")

        readers = ", ".join(peer.display_name for peer in peers)
        print(f"{sender.display_name}: {text}  [decrypted by {readers}]")
        return packet

    def add(user: User) -> None:
            nonlocal founder
            expected = identity(user)
            package, = packages.generate_packages(user, expected.credential, 1)
            result = groups.add_member(alice, founder, package, expected)
            
            # Existing members apply the Commit. The new member joins via Welcome.
            deliver_commit(result.commit, [peer for peer in members if peer is not alice])
            groups.accept_welcome(user, result.welcome, expected_inviter=identity(alice))
            founder = alice.groups[group_id] = result.state
            members.append(user)
            announce(f"Alice added {user.display_name}")
    def sniffed_Say(sender: User, text: str) -> ApplicationMessage:
        packet = messages.encrypt(sender, sender.groups[group_id], text)
        peers = [peer for peer in members if peer is not sender]
        delivery.send_message([peer.user_id for peer in peers], packet)
            
        for peer in peers:
            received, = delivery.receive_messages(peer.user_id)
            if not isinstance(received, ApplicationMessage):
                raise RuntimeError("Expected an application message.")
            if messages.decrypt(peer.groups[group_id], received) != text:
                raise RuntimeError(f"{peer.display_name} received a different message.")
            
        readers = ", ".join(peer.display_name for peer in peers)
        print(f"{sender.display_name}: {text}  [decrypted by {readers}]")
        mallory_sniff.loggedTraffic.append(packet)
        return packet
    
    announce("Alice created the group")

    add(bob)
    say(alice, "Bob, can you see the chat?")
    say(bob, "Loud and clear.")
    say(alice, "I'll bring Charlie in.")
    print("Mallory has started to network evesdrop")

    add(charlie)
    sniffed_Say(charlie, "Hey everyone. What are we testing?")
    sniffed_Say(bob, "Whether we all receive each message.")
    sniffed_Say(alice, "Let's try it with four people.")
    sniffed_Say(bob, "I hope no one is watching us.")
    sniffed_Say(alice, "Yea for real.")
    sniffed_Say(charlie, "Yall goofy asf.")
    sniffed_Say(alice, "Nah chief")
    mallory_sniff.attackerDecrypt(messages, charlie.groups[group_id])
    add(eve)
    sniffed_Say(eve, "I'm here for the four-person test.")
    sniffed_Say(charlie, "I got your message, Eve.")
    sniffed_Say(bob, "Same here.")
    sniffed_Say(alice, "Thanks, Eve. That finishes your part.")
    mallory_sniff.attackerDecrypt(messages, charlie.groups[group_id])
    
    # Keep Eve's old state so the demo can check it against a new-epoch message.
    eve_state = eve.groups[group_id]
    result = groups.remove_member(alice, founder, eve_state.own_leaf_index)
    remaining = [peer for peer in members if peer is not eve]
    deliver_commit(result.commit, [peer for peer in remaining if peer is not alice])
    founder = alice.groups[group_id] = result.state
    members = remaining
    del eve.groups[group_id]
    announce("Alice removed Eve")

    packet = say(alice, "Can everyone remaining read this?")
    say(bob, "Yes, I received it.")
    say(charlie, "Me too. Demo complete.")
    try:
        messages.decrypt(eve_state, packet)
    except ValueError as error:
        print(f"Eve's old state rejected the new message: {error}")
    else:
        raise RuntimeError("Eve unexpectedly decrypted a post-removal message.")

if __name__ == "__main__":
    main()