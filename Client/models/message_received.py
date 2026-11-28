from dataclasses import dataclass

from .chat_message import ChatMessage


@dataclass(frozen=True, slots=True)
class MessageReceived:
    message: ChatMessage