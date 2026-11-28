from dataclasses import dataclass
from hashlib import sha256
from json import dumps
from secrets import token_bytes
from struct import pack
from threading import Lock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from ...models.group_models.group_state import EpochSecrets, GroupState, SenderRatchet
from ...models.group_models.managed_group_state import ManagedGroupState
from ...models.key_models.protocols.application_message import ApplicationMessage
from ...models.user import User


# Serialize ratchet changes across MessageService instances in this process.
_RATCHET_LOCK = Lock()
_MAX_GENERATION = (1 << 32) - 1
_SIGNATURE_LABEL = b"6200 application signature v1/"


"""Hold the material derived for one sender generation. The message key and base nonce
protect the current payload, while the next ratchet carries the chain secret and
generation counter needed for the following message."""
@dataclass(frozen=True, repr=False)
class RatchetStep:
    """Hold the material derived for one sender generation."""

    message_key: bytes
    nonce: bytes
    next_ratchet: SenderRatchet


"""Protect application messages within a group epoch. Sending signs the text and
encrypts both the signed payload and its sender metadata. Receiving checks the
group, epoch, sender generation and signature before advancing that sender’s ratchet
and returning the decoded text."""
class MessageService:
    """Sign, encrypt, and receive in-order application messages."""

    def advance_ratchet(self, ratchet: SenderRatchet) -> RatchetStep:
        """Derive and return the message key, base nonce and next sender ratchet from the supplied ratchet without advancing it in place."""
        generation = ratchet.next_generation
        if not 0 <= generation <= _MAX_GENERATION:
            raise ValueError("Sender ratchet generation is out of range.")

        material = self._expand(
            ratchet.chain_secret, b"step/" + pack(">I", generation), 60
        )
        return RatchetStep(
            message_key=material[:16],
            nonce=material[16:28],
            next_ratchet=SenderRatchet(
                chain_secret=material[28:], next_generation=generation + 1
            ),
        )

    def encrypt(
        self, sender: User, state: GroupState, plaintext: str
    ) -> ApplicationMessage:
        """Sign and encrypt the sender’s plaintext using its group state, advance its local ratchet, and return an application message."""
        state, secrets = self._require_state(state)
        leaf_index = state.own_leaf_index
        expected_key = self._member_key(state, leaf_index)
        if sender.signing_key.public_key().public_bytes_raw() != expected_key:
            raise ValueError("Sender does not own the group's local leaf.")

        context = self._context(state)
        payload = plaintext.encode("utf-8")

        with _RATCHET_LOCK:
            if state.rotation_due:
                raise ValueError("Epoch rotation required before sending another message.")
            ratchet = self._ratchet(state, secrets, context, leaf_index)
            step = self.advance_ratchet(ratchet)

            guard = token_bytes(12)
            metadata = pack(">II12s", leaf_index, ratchet.next_generation, guard)
            aad = context + metadata
            signature = sender.signing_key.sign(_SIGNATURE_LABEL + aad + payload)

            ciphertext = AESGCM(step.message_key).encrypt(
                self._nonce(step.nonce, guard), signature + payload, aad
            )
            metadata_key, metadata_nonce = self._sender_data(secrets, ciphertext)
            encrypted_metadata = AESGCM(metadata_key).encrypt(
                metadata_nonce, metadata, context
            )

            message = ApplicationMessage(
                group_id=state.group_id,
                epoch=state.epoch,
                encrypted_sender_data=encrypted_metadata,
                ciphertext=ciphertext,
            )
            state.set_sender_ratchet(leaf_index, step.next_ratchet)
            return message

    def decrypt(self, state: GroupState, message: ApplicationMessage) -> str:
        """Use the recipient’s group state to decrypt and verify the application message, advance the sender’s receive ratchet, and return decoded text."""
        state, secrets = self._require_state(state)
        if (message.group_id, message.epoch) != (state.group_id, state.epoch):
            raise ValueError("Application message group or epoch mismatch.")

        context = self._context(state)
        metadata_key, metadata_nonce = self._sender_data(secrets, message.ciphertext)
        metadata = AESGCM(metadata_key).decrypt(
            metadata_nonce, message.encrypted_sender_data, context
        )
        if len(metadata) != 20:
            raise ValueError("Invalid sender metadata length.")

        leaf_index = int.from_bytes(metadata[:4], "big")
        generation = int.from_bytes(metadata[4:8], "big")
        guard = metadata[8:]
        if leaf_index == state.own_leaf_index:
            raise ValueError("Skip delivery to the sender's local group state.")

        signing_key = Ed25519PublicKey.from_public_bytes(
            self._member_key(state, leaf_index)
        )
        aad = context + metadata

        with _RATCHET_LOCK:
            ratchet = self._ratchet(state, secrets, context, leaf_index)
            if generation != ratchet.next_generation:
                raise ValueError("Message is replayed or out of order.")

            step = self.advance_ratchet(ratchet)
            signed_payload = AESGCM(step.message_key).decrypt(
                self._nonce(step.nonce, guard), message.ciphertext, aad
            )
            signature, payload = signed_payload[:64], signed_payload[64:]
            signing_key.verify(signature, _SIGNATURE_LABEL + aad + payload)
            plaintext = payload.decode("utf-8")

            state.set_sender_ratchet(leaf_index, step.next_ratchet)
            return plaintext

    def _ratchet(
        self,
        state: ManagedGroupState,
        secrets: EpochSecrets,
        context: bytes,
        leaf_index: int,
    ) -> SenderRatchet:
        """Return the leaf’s cached sender ratchet from the managed state or derive its initial chain from the epoch secrets, context and leaf index."""
        ratchet = state.get_sender_ratchet(leaf_index)
        if ratchet is not None:
            return ratchet

        chain_secret = self._expand(
            secrets.encryption_secret, b"chain/" + context + pack(">I", leaf_index), 32
        )
        return SenderRatchet(chain_secret=chain_secret)

    def _sender_data(
        self, secrets: EpochSecrets, ciphertext: bytes
    ) -> tuple[bytes, bytes]:
        """Derive and return the sender-metadata encryption key and nonce from the epoch secrets and payload ciphertext."""
        material = self._expand(
            secrets.sender_data_secret, b"sender-data/" + sha256(ciphertext).digest(), 28
        )
        return material[:16], material[16:]

    @staticmethod
    def _require_state(state: GroupState) -> tuple[ManagedGroupState, EpochSecrets]:
        """Return the supplied group state and its epoch secrets if it is an initialized managed state, or raise ValueError."""
        if isinstance(state, ManagedGroupState):
            secrets = state.epoch_secrets
            if secrets is not None:
                return state, secrets

        raise ValueError("Application messages require an initialized managed group.")

    @staticmethod
    def _member_key(state: ManagedGroupState, leaf_index: int) -> bytes:
        """Return the signing public key for the active leaf at the given index in the managed state."""
        return state.require_active_signing_key(leaf_index)

    @staticmethod
    def _context(state: ManagedGroupState) -> bytes:
        """Return encoded context bytes binding the managed state’s group ID, epoch and transcript hash to application messages."""
        return dumps(
            ["6200 application v1", state.group_id, state.epoch, state.transcript_hash.hex()],
            separators=(",", ":"),
        ).encode("utf-8")

    @staticmethod
    def _nonce(base_nonce: bytes, guard: bytes) -> bytes:
        """Return the message nonce obtained by XORing the base nonce with the equal-length guard."""
        return bytes(left ^ right for left, right in zip(base_nonce, guard, strict=True))

    @staticmethod
    def _expand(secret: bytes, label: bytes, length: int) -> bytes:
        """Expand the secret under the application-key label prefix and supplied label and return the requested number of bytes."""
        return HKDFExpand(
            algorithm=hashes.SHA256(),
            length=length,
            info=b"6200 application keys v1/" + label,
        ).derive(secret)