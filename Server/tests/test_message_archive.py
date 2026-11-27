from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from Server.models import ChatGroup, Message
from Server.schemas.archive_receipt import ArchiveReceipt
from .test_user_directory_and_key_packages import (
    alice as alice, auth, bob as bob, client as client, engine as engine, register,
)

GROUP = "/api/groups/demo"
MESSAGES = GROUP + "/messages"
FIRST = UUID("00000000-0000-4000-8000-000000000001")


def packet(epoch: int = 0) -> dict[str, str | int]:
    return {
        "epoch": epoch,
        "encrypted_sender_data": b64encode(b"\x00\xfb\xffsender").decode("ascii"),
        "ciphertext": b64encode(b"cipher\x00\xfe\xff").decode("ascii"),
    }


def setup_group(c: TestClient) -> None:
    register(c, "alice")
    register(c, "bob")
    assert c.put(GROUP, headers=auth("alice"), json={"group_name": "Chat"}).status_code == 200


def publish(c: TestClient, epoch: int, members: list[str]) -> None:
    response = c.put(f"{GROUP}/epochs/{epoch}", headers=auth("alice"),
                     json={"member_user_ids": members})
    assert response.status_code == 200


def test_routes_authentication_and_validation(client: TestClient) -> None:
    schema = client.get("/openapi.json")
    base = "/api/groups/{group_id}/messages"
    assert "get" in schema.json()["paths"][base]
    assert "put" in schema.json()["paths"][base + "/{message_id}"]
    assert "get" in schema.json()["paths"][base + "/{index}"]
    path = f"{MESSAGES}/{FIRST}"
    for headers in ({}, auth("invalid")):
        assert client.put(path, headers=headers, json=packet()).status_code == 401
        assert client.get(MESSAGES, headers=headers).status_code == 401
        assert client.get(MESSAGES + "/1", headers=headers).status_code == 401
    headers = auth("alice")
    for field in ("ciphertext", "encrypted_sender_data"):
        for value in ("", "%%%", "_w=="):
            assert client.put(path, headers=headers, json=packet() | {field: value}).status_code == 422
    assert client.put(path, headers=headers, json=packet(-1)).status_code == 422
    assert client.put(MESSAGES + "/invalid", headers=headers, json=packet()).status_code == 422
    assert client.get(MESSAGES + "/0", headers=headers).status_code == 422
    assert client.put(path, headers=headers, json=packet()).status_code == 404


@pytest.mark.parametrize("engine", ["sqlite", "postgres"], indirect=True)
def test_upload_retries_preserve_bytes_and_counter(client: TestClient, engine: Engine) -> None:
    setup_group(client)
    headers = auth("alice")
    path = f"{MESSAGES}/{FIRST}"
    receipt = {"group_id": "demo", "message_id": str(FIRST), "transcript_index": 1}
    for _ in range(2):
        response = client.put(path, headers=headers, json=packet())
        assert response.status_code == 200
        assert response.json() == receipt
    publish(client, 1, ["alice", "bob"])
    for changed in (packet(1), packet() | {"ciphertext": "YQ=="},
                    packet() | {"encrypted_sender_data": "YQ=="}):
        assert client.put(path, headers=headers, json=changed).status_code == 409
    assert client.put(path, headers=auth("bob"), json=packet()).status_code == 403
    assert client.put(path, headers=headers, json=packet(2)).status_code == 404
    fetched = client.get(MESSAGES + "/1", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json() == receipt | packet()
    with Session(engine) as db:
        row = db.scalars(select(Message)).one()
        assert (row.encrypted_sender_data, row.ciphertext) == (b"\x00\xfb\xffsender", b"cipher\x00\xfe\xff")
        assert db.get_one(ChatGroup, "demo").next_transcript_index == 2


@pytest.mark.parametrize("engine", ["sqlite", "postgres"], indirect=True)
def test_current_and_historical_access_and_group_scope(client: TestClient) -> None:
    setup_group(client)
    alice_headers, bob_headers = auth("alice"), auth("bob")
    second = uuid4()
    assert client.put(f"{MESSAGES}/{FIRST}", headers=alice_headers, json=packet()).status_code == 200
    publish(client, 1, ["alice", "bob"])
    assert client.put(f"{MESSAGES}/{second}", headers=alice_headers, json=packet(1)).status_code == 200
    assert client.get(MESSAGES, headers=bob_headers).json() == [
        {"transcript_index": 2, "message_id": str(second), "epoch": 1}
    ]
    assert client.get(MESSAGES + "/1", headers=bob_headers).status_code == 404
    assert client.get(MESSAGES + "/2", headers=bob_headers).status_code == 200
    assert client.get(MESSAGES, headers=alice_headers).json() == [
        {"transcript_index": 1, "message_id": str(FIRST), "epoch": 0},
        {"transcript_index": 2, "message_id": str(second), "epoch": 1},
    ]

    other = "/api/groups/other"
    assert client.put(other, headers=bob_headers, json={"group_name": "Other"}).status_code == 200
    assert client.get(other + "/messages/1", headers=bob_headers).status_code == 404
    assert client.put(f"{other}/messages/{FIRST}", headers=bob_headers, json=packet(1)).status_code == 404
    publish(client, 2, ["alice"])
    for suffix in ("", "/1", "/2", "/999"):
        assert client.get(MESSAGES + suffix, headers=bob_headers).status_code == 403
    assert client.put(f"{MESSAGES}/{uuid4()}", headers=bob_headers, json=packet(2)).status_code == 403
    # A delayed delivery from Bob's own epoch is still eligible for upload.
    assert client.put(f"{MESSAGES}/{uuid4()}", headers=bob_headers, json=packet(1)).status_code == 200


@pytest.mark.parametrize("engine", ["postgres"], indirect=True)
def test_concurrent_allocations_and_identical_retries(client: TestClient, engine: Engine) -> None:
    setup_group(client)

    def allocate(ids: tuple[UUID, UUID]) -> list[int]:
        gate = Barrier(2)

        def send(message_id: UUID) -> int:
            _ = gate.wait(timeout=5)
            response = client.put(f"{MESSAGES}/{message_id}", headers=auth("alice"), json=packet())
            assert response.status_code == 200
            return ArchiveReceipt.model_validate_json(response.content).transcript_index

        with ThreadPoolExecutor(max_workers=2) as pool:
            return sorted(pool.map(send, ids))

    assert allocate((uuid4(), uuid4())) == [1, 2]
    shared = uuid4()
    assert allocate((shared, shared)) == [3, 3]
    with Session(engine) as db:
        assert list(db.scalars(select(Message.transcript_index).order_by(Message.transcript_index))) == [1, 2, 3]
        assert db.get_one(Message, ("demo", shared)).transcript_index == 3
        assert db.get_one(ChatGroup, "demo").next_transcript_index == 4