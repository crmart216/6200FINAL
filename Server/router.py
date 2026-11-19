import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel


class CreateGroupRequest(BaseModel):
    name: str


class SendMessageRequest(BaseModel):
    text: str
    group_id: str


def create_chat_router(chat_service):
    router = APIRouter(prefix="/api", tags=["chat"])

    @router.post("/groups")
    def create_group(request: CreateGroupRequest):
        group_id = chat_service.createGroup(request.name)
        return {"group_id": group_id}

    @router.post("/groups/{group_id}/messages")
    def send_message(group_id: str, request: SendMessageRequest):
        chat_service.sendMessage(request.text, group_id)
        return {"sent": True}

    @router.get("/users")
    def get_all_users():
        return chat_service.getAllUsers()

    @router.get("/groups/{group_id}/members")
    def get_group_members(group_id: str):
        return chat_service.getGroupChatMembers(group_id)

    @router.post("/groups/{group_id}/members")
    def add_user_to_group(group_id: str):
        # The service chooses which user to add, since addUserToGroup
        # currently takes only the group ID.
        chat_service.addUserToGroup(group_id)
        return {"added": True}

    @router.websocket("/messages/stream")
    async def stream_messages(websocket: WebSocket):
        await websocket.accept()

        try:
            while True:
                message = await asyncio.to_thread(chat_service.waitForMessage)
                await websocket.send_json(message)
        except WebSocketDisconnect:
            pass

    return router