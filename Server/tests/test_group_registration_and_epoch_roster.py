from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import Engine, select, update
from sqlalchemy.orm import Session

from Security.models.user import User as ClientUser
from Server.models import ChatGroup, EpochMember, GroupEpoch
from .test_user_directory_and_key_packages import (
    alice as alice,
    auth,
    bob as bob,
    client as client,
    engine as engine,
    register,
)
from .test_group_invitations import claimed_invitation


URL = "/api/groups/demo"


def create(c: TestClient, user: str = "alice", name: str = "Chat") -> Response:
    return c.put(URL, headers=auth(user), json={"group_name": name})


def publish(
    c: TestClient,
    epoch: int,
    members: list[str],
    user: str = "alice",
    invitation_id: UUID | None = None,
) -> Response:
    return c.put(
        f"{URL}/epochs/{epoch}",
        headers=auth(user),
        json={"member_user_ids": members, "invitation_id": str(invitation_id) if invitation_id else None},
    )


def snapshots(engine: Engine) -> dict[int, list[str]]:
    with Session(engine) as db:
        epochs = db.scalars(
            select(GroupEpoch.epoch).where(GroupEpoch.group_id == "demo")
        )
        result: dict[int, list[str]] = {epoch: [] for epoch in epochs}

        rows = db.scalars(
            select(EpochMember)
            .where(EpochMember.group_id == "demo")
            .order_by(EpochMember.user_id)
        )
        for member in rows:
            result[member.epoch].append(member.user_id)
        return result


def test_routes_and_authorization(client: TestClient) -> None:
    schema = client.get("/openapi.json")
    for path in ("/api/groups/{group_id}", "/api/groups/{group_id}/epochs/{epoch}"):
        assert "put" in schema.json()["paths"][path]

    for headers in ({}, auth("unknown")):
        assert client.put(
            URL, headers=headers, json={"group_name": "Chat"}
        ).status_code == 401
        assert client.put(
            URL + "/epochs/1", headers=headers, json={"member_user_ids": ["alice"]}
        ).status_code == 401

    register(client, "alice")
    register(client, "bob")

    assert publish(client, 1, ["alice"]).status_code == 404
    assert create(client, name=" ").status_code == 422
    assert create(client).status_code == 200
    assert create(client, user="bob").status_code == 409
    assert create(client, name="Other").status_code == 409
    assert publish(client, 1, ["alice", "bob"], "bob").status_code == 403


@pytest.mark.parametrize("engine", ["sqlite", "postgres"], indirect=True)
def test_epoch_history_and_retries(client: TestClient, engine: Engine, bob: ClientUser) -> None:
    register(client, "alice")
    register(client, "bob")
    group = {
        "group_id": "demo",
        "founder_user_id": "alice",
        "group_name": "Chat",
        "current_epoch": 0,
    }

    assert create(client).json() == group
    assert snapshots(engine) == {0: ["alice"]}

    with Session(engine) as db, db.begin():
        assert db.get_one(ChatGroup, "demo").next_transcript_index == 1
        _ = db.execute(
            update(ChatGroup)
            .where(ChatGroup.group_id == "demo")
            .values(next_transcript_index=7)
        )

    history = {
        0: ["alice"],
        1: ["alice", "bob"],
        2: ["alice", "bob"],
        3: ["alice"],
    }
    invitation_id = claimed_invitation(client, "demo", bob)
    for epoch, members in history.items():
        response = publish(client, epoch, members, invitation_id=invitation_id if epoch == 1 else None)
        assert response.status_code == 200
        assert response.json() == {
            "group_id": "demo",
            "epoch": epoch,
            "member_user_ids": members,
        }
        assert create(client).json() == group | {"current_epoch": epoch}

    assert publish(client, 1, ["bob", "alice"], invitation_id=invitation_id).json() == {
        "group_id": "demo",
        "epoch": 1,
        "member_user_ids": ["alice", "bob"],
    }
    assert publish(client, 1, ["alice"]).status_code == 409
    assert publish(client, 0, ["alice", "bob"]).status_code == 409
    assert snapshots(engine) == history

    with Session(engine) as db:
        assert db.get_one(ChatGroup, "demo").next_transcript_index == 7


@pytest.mark.parametrize("engine", ["sqlite", "postgres"], indirect=True)
def test_invalid_publications_leave_no_partial_rows(
    client: TestClient, engine: Engine
) -> None:
    register(client, "alice")
    register(client, "bob")
    assert create(client).status_code == 200

    for epoch, members, status in (
        (2, ["alice"], 409),
        (-1, ["alice"], 422),
        (1, ["alice", "alice"], 422),
        (1, ["alice", "missing"], 422),
        (1, ["bob"], 422),
        (1, [], 422),
        (1, [" "], 422),
    ):
        assert publish(client, epoch, members).status_code == status
        assert snapshots(engine) == {0: ["alice"]}


def race(operation: Callable[[int], Response]) -> list[Response]:
    gate = Barrier(2)

    def send(index: int) -> Response:
        _ = gate.wait(timeout=5)
        return operation(index)

    with ThreadPoolExecutor(max_workers=2) as pool:
        return list(pool.map(send, (0, 1)))


@pytest.mark.parametrize("engine", ["postgres"], indirect=True)
@pytest.mark.parametrize("identical", [True, False], ids=["identical", "conflicting"])
def test_competing_writes(
    client: TestClient, engine: Engine, identical: bool, bob: ClientUser
) -> None:
    register(client, "alice")
    register(client, "bob")

    names = ["Chat", "Chat" if identical else "Other"]
    expected = [200, 200] if identical else [200, 409]

    created = race(lambda i: create(client, name=names[i]))
    assert sorted(r.status_code for r in created) == expected
    assert snapshots(engine) == {0: ["alice"]}

    rosters = [["alice", "bob"], ["bob", "alice"] if identical else ["alice"]]
    invitation_id = claimed_invitation(client, "demo", bob)
    published = race(lambda i: publish(
        client, 1, rosters[i], invitation_id=invitation_id if "bob" in rosters[i] else None,
    ))
    assert sorted(r.status_code for r in published) == expected

    winner = next(i for i, response in enumerate(published) if response.status_code == 200)
    assert snapshots(engine) == {0: ["alice"], 1: sorted(rosters[winner])}
