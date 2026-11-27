from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, or_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from ..models import ChatGroup, EpochMember, GroupInvitation, KeyPackage, User
from ..schemas.invitation_claim_response import InvitationClaimResponse
from ..schemas.invitation_decision_request import InvitationDecisionRequest
from ..schemas.invitation_response import InvitationDirection, InvitationResponse, InvitationStatus
from ..schemas.public_key_package import PublicKeyPackagePayload
from .directory import verify_package
from .groups import Conflict, Forbidden, current_epoch

INVITATION_LIFETIME = timedelta(hours=24)
CREATE_LIMIT = 20
CREATE_WINDOW = timedelta(minutes=1)
EXPIRABLE = ("pending", "accepted")
ACTIVE = (*EXPIRABLE, "claimed")


class Unavailable(Exception):
    pass


class CreationLimit(Exception):
    pass


def as_utc(timestamp: datetime) -> datetime:
    # SQLite's offline fixtures return naive UTC timestamps.
    return timestamp.replace(tzinfo=UTC) if timestamp.tzinfo is None else timestamp.astimezone(UTC)


def record(row: GroupInvitation, group_name: str) -> InvitationResponse:
    return InvitationResponse.model_validate({
        "invitation_id": row.invitation_id, "group_id": row.group_id, "group_name": group_name,
        "inviter_user_id": row.inviter_user_id, "invitee_user_id": row.invitee_user_id,
        "status": row.status, "created_at": as_utc(row.created_at),
        "expires_at": as_utc(row.expires_at), "joined_epoch": row.joined_epoch,
    })


def expire_matching(db: Session, scope: ColumnElement[bool], now: datetime) -> None:
    _ = db.execute(
        update(GroupInvitation)
        .where(scope, GroupInvitation.status.in_(EXPIRABLE), GroupInvitation.expires_at <= now)
        .values(status="expired")
    )


def create(
    db: Session, group_id: str, caller: str, invitee: str,
) -> tuple[InvitationResponse, bool]:
    with db.begin():
        group = db.get(ChatGroup, group_id, with_for_update=True)
        if group is None:
            raise Unavailable("Group or invitee unavailable")
        if group.founder_user_id != caller:
            raise Forbidden("Only the founder can create an invitation")
        if db.get(User, invitee) is None:
            raise Unavailable("Group or invitee unavailable")
        if db.get(EpochMember, (group_id, current_epoch(db, group_id), invitee)) is not None:
            raise Conflict("Invitee already belongs to the group")

        # Serialize the inviter-wide limit across groups. NO KEY UPDATE permits FK checks.
        _ = db.get_one(User, caller, with_for_update={"key_share": True})
        scope = (GroupInvitation.group_id == group_id) & (GroupInvitation.invitee_user_id == invitee)
        now = datetime.now(UTC)
        expire_matching(db, scope, now)
        existing = db.scalar(
            select(GroupInvitation).where(scope, GroupInvitation.status.in_(ACTIVE))
        )
        if existing is not None:
            return record(existing, group.group_name), False

        count = db.scalar(select(func.count()).select_from(GroupInvitation).where(
            GroupInvitation.inviter_user_id == caller,
            GroupInvitation.created_at > now - CREATE_WINDOW,
        ))
        if count is not None and count < CREATE_LIMIT:
            row = GroupInvitation(
                invitation_id=uuid4(), group_id=group_id, inviter_user_id=caller,
                invitee_user_id=invitee, status="pending", created_at=now,
                expires_at=now + INVITATION_LIFETIME,
            )
            db.add(row)
            db.flush()
            return record(row, group.group_name), True

    # Commit any expiration before returning the rate-limit error.
    raise CreationLimit


def visible_to(caller: str, direction: InvitationDirection | None = None) -> ColumnElement[bool]:
    incoming = GroupInvitation.invitee_user_id == caller
    outgoing = GroupInvitation.inviter_user_id == caller
    if direction == "incoming":
        return incoming
    if direction == "outgoing":
        return outgoing
    return or_(incoming, outgoing)


def list_for(
    db: Session, caller: str, direction: InvitationDirection | None, status: InvitationStatus | None,
) -> list[InvitationResponse]:
    with db.begin():
        scope = visible_to(caller, direction)
        expire_matching(db, scope, datetime.now(UTC))
        query = select(GroupInvitation).where(scope)
        if status is not None:
            query = query.where(GroupInvitation.status == status)
        rows = db.scalars(query.order_by(GroupInvitation.created_at.desc(), GroupInvitation.invitation_id))
        return [record(row, db.get_one(ChatGroup, row.group_id).group_name) for row in rows]


def find_for_update(db: Session, invitation_id: UUID, scope: ColumnElement[bool]) -> GroupInvitation:
    row = db.scalar(
        select(GroupInvitation)
        .where(GroupInvitation.invitation_id == invitation_id, scope)
        .with_for_update()
    )
    if row is None:
        raise Unavailable("Invitation unavailable")
    return row


def expire_locked(row: GroupInvitation, now: datetime) -> bool:
    if row.status in EXPIRABLE and as_utc(row.expires_at) <= now:
        row.status = "expired"
    return row.status == "expired"


def get(db: Session, invitation_id: UUID, caller: str) -> InvitationResponse:
    with db.begin():
        row = find_for_update(db, invitation_id, visible_to(caller))
        _ = expire_locked(row, datetime.now(UTC))
        return record(row, db.get_one(ChatGroup, row.group_id).group_name)


def package_for(db: Session, package_id: str | None) -> PublicKeyPackagePayload:
    if package_id is None:
        raise Conflict("Invitation has no approved package")
    return PublicKeyPackagePayload.model_validate(db.get_one(KeyPackage, package_id), from_attributes=True)


def accept(db: Session, row: GroupInvitation, package: PublicKeyPackagePayload) -> None:
    if row.status in ("accepted", "claimed", "completed"):
        if package_for(db, row.package_id) == package:
            return
        raise Conflict("Invitation already has a different decision or package")
    if row.status != "pending":
        raise Conflict("Invitation already has a different decision")
    invitee = db.get_one(User, row.invitee_user_id)
    verify_package(invitee.user_id, invitee.signing_public_key, package)
    inserted = db.scalar(insert(KeyPackage).values(
        owner_user_id=invitee.user_id, **package.model_dump(),
    ).on_conflict_do_nothing(index_elements=[KeyPackage.package_id]).returning(KeyPackage.package_id))
    if inserted is None:
        raise Conflict("Acceptance requires a fresh key package")
    row.package_id = inserted
    row.status = "accepted"


def decide(
    db: Session, invitation_id: UUID, caller: str, data: InvitationDecisionRequest,
) -> InvitationResponse:
    with db.begin():
        row = find_for_update(db, invitation_id, visible_to(caller, "incoming"))
        if not expire_locked(row, datetime.now(UTC)):
            if data.key_package is not None:
                accept(db, row, data.key_package)
            elif row.status in ("pending", "declined"):
                row.status = "declined"
            else:
                raise Conflict("Invitation already has a different decision")
            return record(row, db.get_one(ChatGroup, row.group_id).group_name)

    raise Conflict("Invitation expired")


def claim(db: Session, invitation_id: UUID, caller: str) -> InvitationClaimResponse:
    with db.begin():
        row = find_for_update(db, invitation_id, visible_to(caller, "outgoing"))
        now = datetime.now(UTC)
        if not expire_locked(row, now):
            if row.status == "accepted":
                row.status = "claimed"
                row.claimed_at = now
            elif row.status not in ("claimed", "completed"):
                raise Conflict("Invitation has no approved package")
            return InvitationClaimResponse(
                invitation_id=row.invitation_id, key_package=package_for(db, row.package_id),
            )

    raise Conflict("Invitation expired")