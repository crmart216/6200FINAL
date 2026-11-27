from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from typing import cast
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from httpx2 import Response
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from Security.models.user import User as ClientUser
from Security.services.group_services.key_services.key_package_service import KeyPackageService
from Server.core.config import get_settings
from Server.models import EpochMember, GroupEpoch, GroupInvitation, KeyPackage, PackageClaim
from Server.schemas.invitation_response import InvitationResponse
from Server.schemas.public_key_package import PublicKeyPackagePayload
from Server.services import groups, invitation

from .test_public_registration import SIGNUP, signed_request
from .test_user_directory_and_key_packages import (
    alice as alice, auth, bob as bob, client as client, engine as engine, seed_account,
)

pytestmark = pytest.mark.parametrize("engine", ["postgres"], indirect=True)
INBOX = "/api/invitations"


def new_group(c: TestClient, group: str = "demo") -> None:
    response = c.put(f"/api/groups/{group}", headers=auth("alice"), json={"group_name": group})
    assert response.status_code == 200


def invite(c: TestClient, group: str = "demo", invitee: str = "bob", caller: str = "alice") -> Response:
    return c.post(f"/api/groups/{group}/invitations", headers=auth(caller),
                  json={"invitee_user_id": invitee})


def created(response: Response) -> UUID:
    assert response.status_code == 201
    return InvitationResponse.model_validate_json(response.content).invitation_id


def package_for(account: ClientUser) -> dict[str, object]:
    package, = KeyPackageService().generate_packages(account, account.user_id.encode(), 1)
    return PublicKeyPackagePayload.model_validate(package, from_attributes=True).model_dump(mode="json")


def accept(c: TestClient, target: UUID, package: dict[str, object], caller: str = "bob") -> Response:
    return c.put(f"{INBOX}/{target}/decision", headers=auth(caller),
                 json={"decision": "accept", "key_package": package})


def claim(c: TestClient, target: UUID, caller: str = "alice") -> Response:
    return c.post(f"{INBOX}/{target}/claim", headers=auth(caller))


def claimed_invitation(c: TestClient, group: str, invitee: ClientUser) -> UUID:
    target = created(invite(c, group, invitee.user_id))
    assert accept(c, target, package_for(invitee), invitee.user_id).status_code == 200
    assert claim(c, target).status_code == 200
    return target


def roster(
    c: TestClient, epoch: int, members: list[str], target: UUID | None = None, group: str = "demo",
) -> Response:
    body: dict[str, list[str] | str] = {"member_user_ids": members}
    if target is not None:
        body["invitation_id"] = str(target)
    return c.put(f"/api/groups/{group}/epochs/{epoch}", headers=auth("alice"), json=body)


def race(send: Callable[[], Response]) -> list[Response]:
    gate = Barrier(2)

    def request() -> Response:
        _ = gate.wait(timeout=5)
        return send()

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(request)
        second = pool.submit(request)
        return [first.result(), second.result()]


def test_end_to_end_invitation(client: TestClient, bob: ClientUser, engine: Engine) -> None:
    new_group(client)
    target = created(invite(client))
    pending = client.get(INBOX, headers=auth("bob"), params={"direction": "incoming", "status": "pending"})
    assert pending.status_code == 200
    assert pending.json()[0]["invitation_id"] == str(target)

    package = package_for(bob)
    accepted = accept(client, target, package)
    assert accepted.status_code == 200 and accepted.json()["status"] == "accepted"
    assert "key_package" not in accepted.json() and "joined_epoch" not in accepted.json()
    assert accept(client, target, package).json() == accepted.json()
    assert accept(client, target, package_for(bob)).status_code == 409
    outgoing = client.get(INBOX, headers=auth("alice"), params={"direction": "outgoing", "status": "accepted"})
    assert outgoing.json() == [accepted.json()]

    claimed = claim(client, target)
    assert claimed.status_code == 200
    assert claimed.json() == {"invitation_id": str(target), "key_package": package}
    assert client.get(INBOX, headers=auth("alice"), params={"direction": "outgoing", "status": "claimed"}).json()[0]["status"] == "claimed"
    assert roster(client, 1, ["alice", "bob"], target).status_code == 200
    completed = client.get(f"{INBOX}/{target}", headers=auth("bob"))
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed" and completed.json()["joined_epoch"] == 1
    assert roster(client, 1, ["bob", "alice"], target).status_code == 200
    assert roster(client, 1, ["alice", "bob"]).status_code == 409
    assert claim(client, target).json() == claimed.json()
    assert accept(client, target, package).json() == completed.json()
    with Session(engine) as db:
        assert db.get(EpochMember, ("demo", 1, "bob")) is not None
        assert db.scalar(select(func.count()).select_from(PackageClaim)) == 0


def test_access_validation_and_legacy_claim_cutover(client: TestClient, engine: Engine, bob: ClientUser) -> None:
    with Session(engine) as db, db.begin():
        seed_account(db, "charlie", bytes(32), "test-charlie")
    new_group(client)
    assert invite(client, caller="bob").status_code == 403
    assert invite(client, invitee="missing").status_code == 404
    assert invite(client, invitee="alice").status_code == 409
    target = created(invite(client))
    package = package_for(bob)
    assert client.get(f"{INBOX}/{target}", headers=auth("charlie")).status_code == 404
    assert client.get(INBOX, headers=auth("charlie")).json() == []
    assert client.get(INBOX).status_code == 401
    assert claim(client, target, "charlie").status_code == 404
    assert accept(client, target, package, "alice").status_code == 404
    assert claim(client, target, "bob").status_code == 404
    assert claim(client, target).status_code == 409
    assert client.get(INBOX, headers=auth("bob"), params={"status": "nonsense"}).status_code == 422
    assert accept(client, target, package | {"signature": "AAAA"}).status_code == 422
    assert client.put(f"{INBOX}/{target}/decision", headers=auth("bob"),
                      json={"decision": "decline", "key_package": None}).status_code == 422
    assert client.post("/api/users/bob/key-packages/claims", headers=auth("alice"),
                       json={"request_id": str(uuid4())}).status_code in (404, 405)
    assert accept(client, target, package).status_code == 200
    new_group(client, "second")
    second = created(invite(client, "second"))
    assert accept(client, second, package).status_code == 409
    # A standalone published package cannot be reused for a new approval either.
    unused = package_for(bob)
    assert client.put(f"/api/users/bob/key-packages/{unused['package_id']}",
                      headers=auth("bob"), json=unused).status_code == 200
    assert accept(client, second, unused).status_code == 409
    with Session(engine) as db:
        assert db.get_one(GroupInvitation, second).status == "pending"


def test_concurrent_create_and_claim(client: TestClient, bob: ClientUser, engine: Engine) -> None:
    new_group(client)
    responses = race(lambda: invite(client))
    assert sorted(response.status_code for response in responses) == [200, 201]
    assert responses[0].json() == responses[1].json()
    target = InvitationResponse.model_validate_json(responses[0].content).invitation_id
    package = package_for(bob)
    decisions = race(lambda: accept(client, target, package))
    assert all(response.status_code == 200 for response in decisions)
    responses = race(lambda: claim(client, target))
    assert all(response.status_code == 200 for response in responses)
    assert responses[0].json() == responses[1].json()
    with Session(engine) as db:
        claimed_at = db.get_one(GroupInvitation, target).claimed_at
        assert claimed_at is not None
        assert db.scalar(select(func.count()).select_from(KeyPackage)) == 1
    assert claim(client, target).status_code == 200
    with Session(engine) as db:
        assert db.get_one(GroupInvitation, target).claimed_at == claimed_at


def make_stale(engine: Engine, target: UUID) -> None:
    with Session(engine) as db, db.begin():
        row = db.get_one(GroupInvitation, target)
        row.expires_at = datetime.now(UTC) - timedelta(minutes=5)
        row.created_at = row.expires_at - timedelta(hours=1)


def test_decline_expiry_and_resume(client: TestClient, engine: Engine, bob: ClientUser) -> None:
    new_group(client)
    target = created(invite(client))
    for _ in range(2):
        declined = client.put(f"{INBOX}/{target}/decision", headers=auth("bob"), json={"decision": "decline"})
        assert declined.status_code == 200 and declined.json()["status"] == "declined"
    assert accept(client, target, package_for(bob)).status_code == 409
    assert claim(client, target).status_code == 409

    stale_pending = created(invite(client))
    make_stale(engine, stale_pending)
    assert client.get(INBOX, headers=auth("bob"), params={"status": "pending"}).json() == []
    assert client.get(f"{INBOX}/{stale_pending}", headers=auth("bob")).json()["status"] == "expired"

    stale_accepted = created(invite(client))
    assert accept(client, stale_accepted, package_for(bob)).status_code == 200
    make_stale(engine, stale_accepted)
    assert claim(client, stale_accepted).status_code == 409
    with Session(engine) as db:
        row = db.get_one(GroupInvitation, stale_accepted)
        assert row.status == "expired" and row.package_id is not None and row.claimed_at is None

    expired_on_create = created(invite(client))
    make_stale(engine, expired_on_create)
    resumable = claimed_invitation(client, "demo", bob)
    with Session(engine) as db:
        assert db.get_one(GroupInvitation, expired_on_create).status == "expired"
    make_stale(engine, resumable)
    assert invite(client).json()["invitation_id"] == str(resumable)
    assert claim(client, resumable).status_code == 200
    assert roster(client, 1, ["alice", "bob"], resumable).status_code == 200


def test_epoch_conflicts_preserve_state(client: TestClient, engine: Engine, bob: ClientUser) -> None:
    charlie = ClientUser("charlie", "Charlie")
    with Session(engine) as db, db.begin():
        seed_account(db, charlie.user_id, charlie.signing_key.public_key().public_bytes_raw(), "test-charlie")
    new_group(client)
    new_group(client, "other")
    wrong_group = claimed_invitation(client, "other", bob)
    wrong_invitee = claimed_invitation(client, "demo", charlie)
    target = created(invite(client))
    assert accept(client, target, package_for(bob)).status_code == 200

    for candidate in (None, wrong_group, wrong_invitee, target):
        assert roster(client, 1, ["alice", "bob"], candidate).status_code == 409
    assert roster(client, 1, ["alice", "bob", "charlie"], wrong_invitee).status_code == 409
    assert roster(client, 1, ["alice"], wrong_invitee).status_code == 409
    with Session(engine) as db:
        assert list(db.scalars(select(GroupEpoch.epoch).where(GroupEpoch.group_id == "demo"))) == [0]
        assert db.get_one(GroupInvitation, wrong_group).status == "claimed"
        assert db.get_one(GroupInvitation, wrong_invitee).status == "claimed"
        assert db.get_one(GroupInvitation, target).status == "accepted"

    assert claim(client, target).status_code == 200
    assert roster(client, 1, ["alice", "bob"], target).status_code == 200
    assert roster(client, 2, ["alice", "bob"]).status_code == 200
    assert roster(client, 3, ["alice"]).status_code == 200
    assert roster(client, 1, ["alice", "bob"], wrong_invitee).status_code == 409


def test_failed_epoch_write_rolls_back(
    client: TestClient, engine: Engine, bob: ClientUser, monkeypatch: pytest.MonkeyPatch,
) -> None:
    new_group(client)
    target = claimed_invitation(client, "demo", bob)
    store_epoch = groups.store_epoch

    def fail_after_write(db: Session, group_id: str, epoch: int, members: list[str]) -> None:
        store_epoch(db, group_id, epoch, members)
        raise groups.Conflict("Simulated write failure")

    monkeypatch.setattr(groups, "store_epoch", fail_after_write)
    assert roster(client, 1, ["alice", "bob"], target).status_code == 409
    with Session(engine) as db:
        assert db.get(GroupEpoch, ("demo", 1)) is None
        assert db.get(EpochMember, ("demo", 1, "bob")) is None
        assert db.get_one(GroupInvitation, target).status == "claimed"


def test_creation_quota_allows_equivalent_retry(
    client: TestClient, engine: Engine, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(invitation, "CREATE_LIMIT", 1)
    new_group(client)
    new_group(client, "other")
    target = created(invite(client))
    retry = invite(client)
    assert retry.status_code == 200 and retry.json()["invitation_id"] == str(target)
    assert invite(client, "other").status_code == 429
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(GroupInvitation)) == 1


def test_public_signup_can_participate(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SERVER_DATABASE_URL", "postgresql+psycopg://unused/test")
    monkeypatch.setenv("SERVER_PUBLIC_SIGNUP_ENABLED", "false")
    get_settings.cache_clear()
    try:
        assert client.post(SIGNUP, json={}).status_code == 404
        monkeypatch.setenv("SERVER_PUBLIC_SIGNUP_ENABLED", "true")
        get_settings.cache_clear()
        charlie = ClientUser("charlie", "Charlie")
        payload = signed_request(client, charlie.signing_key, charlie.user_id)
        signup = client.post(SIGNUP, json=payload)
        assert signup.status_code == 201
        headers = {"Authorization": "Bearer " + cast(str, signup.json()["api_token"])}
        new_group(client)
        target = created(invite(client, invitee="charlie"))
        assert client.get(INBOX, headers=headers).json()[0]["invitation_id"] == str(target)
        approved = client.put(f"{INBOX}/{target}/decision", headers=headers,
                              json={"decision": "accept", "key_package": package_for(charlie)})
        assert approved.status_code == 200
        assert claim(client, target).status_code == 200
        assert roster(client, 1, ["alice", "charlie"], target).status_code == 200
    finally:
        get_settings.cache_clear()
