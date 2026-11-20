from collections import deque
from collections.abc import Iterable
from copy import deepcopy
from threading import Lock

from ...models.key_models.key_package import PublicKeyPackage
from ...models.key_models.protocols.application_message import ApplicationMessage
from ...models.key_models.protocols.commit import Commit
from ...models.key_models.protocols.welcome import Welcome


type ProtocolMessage = Commit | Welcome | ApplicationMessage


"""Relay public key packages and protocol messages in memory. Each published package
can be claimed once, while each distinct message recipient gets an independent copy
in a FIFO inbox. A lock protects the queues shared by callers of this service
instance."""
class DeliveryService:
    """Relay public key packages and protocol messages in memory."""

    def __init__(self) -> None:
        """Initialize empty package queues, publication history, inboxes and a lock without arguments and return None."""
        self._public_packages: dict[str, deque[PublicKeyPackage]] = {}
        self._published_package_ids: set[str] = set()
        self._inboxes: dict[str, deque[ProtocolMessage]] = {}
        self._lock: Lock = Lock()

    def publish_key_package(self, user_id: str, package: PublicKeyPackage) -> None:
        """Append the public package to the given user ID’s queue if its package ID is new and return None."""
        with self._lock:
            if package.package_id in self._published_package_ids:
                raise ValueError("This key package has already been published.")

            self._public_packages.setdefault(user_id, deque()).append(package)
            self._published_package_ids.add(package.package_id)

    def fetch_key_package(self, user_id: str) -> PublicKeyPackage | None:
        """Remove and return the oldest available package for the given user ID, or return None if its queue is empty."""
        with self._lock:
            packages = self._public_packages.get(user_id)
            if not packages:
                return None

            package = packages.popleft()
            if not packages:
                del self._public_packages[user_id]
            return package

    def send_message(
        self, recipient_ids: Iterable[str], message: ProtocolMessage
    ) -> None:
        """Queue a separate copy of the protocol message for each distinct recipient ID and return None."""
        deliveries = [
            (recipient_id, deepcopy(message))
            for recipient_id in dict.fromkeys(recipient_ids)
        ]

        with self._lock:
            for recipient_id, queued_message in deliveries:
                self._inboxes.setdefault(recipient_id, deque()).append(queued_message)

    def receive_messages(self, recipient_id: str) -> list[ProtocolMessage]:
        """Drain the inbox for the given recipient ID and return its messages in delivery order, or an empty list."""
        with self._lock:
            inbox = self._inboxes.pop(recipient_id, None)

        return list(inbox) if inbox is not None else []