from sqlalchemy import insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ..models import ChatGroup, EpochMember, GroupEpoch, User
from ..schemas.epoch_roster_update import EpochRosterResponse
from ..schemas.group_registration import GroupResponse


class Forbidden(Exception):
    pass


class UnknownGroup(Exception):
    pass


class Conflict(Exception):
    pass


class InvalidRoster(Exception):
    pass


def current_epoch(db: Session, group_id: str) -> int:
    query = select(GroupEpoch.epoch).where(GroupEpoch.group_id == group_id)
    return db.scalars(query.order_by(GroupEpoch.epoch.desc()).limit(1)).one()


def roster(db: Session, group_id: str, epoch: int) -> list[str]:
    query = select(EpochMember.user_id).where(
        EpochMember.group_id == group_id,
        EpochMember.epoch == epoch,
    )
    return sorted(db.scalars(query))


def store_epoch(db: Session, group_id: str, epoch: int, members: list[str]) -> None:
    _ = db.execute(insert(GroupEpoch).values(group_id=group_id, epoch=epoch))
    _ = db.execute(
        insert(EpochMember),
        [
            {"group_id": group_id, "epoch": epoch, "user_id": member}
            for member in members
        ],
    )


def register(db: Session, group_id: str, name: str, founder: str) -> GroupResponse:
    with db.begin():
        if db.get(User, founder) is None:
            raise Forbidden("Register your user before creating a group")

        create = (
            pg_insert(ChatGroup)
            .values(group_id=group_id, group_name=name, founder_user_id=founder)
            .on_conflict_do_nothing(index_elements=[ChatGroup.group_id])
            .returning(ChatGroup.group_id)
        )

        if db.scalar(create) is not None:
            store_epoch(db, group_id, 0, [founder])
            epoch = 0
        else:
            group = db.get_one(ChatGroup, group_id)
            if group.founder_user_id != founder or group.group_name != name:
                raise Conflict("Group ID already registered with a different founder or name")
            epoch = current_epoch(db, group_id)

        return GroupResponse(
            group_id=group_id,
            group_name=name,
            founder_user_id=founder,
            current_epoch=epoch,
        )


def publish(
    db: Session,
    group_id: str,
    epoch: int,
    caller: str,
    members: list[str],
) -> EpochRosterResponse:
    ordered = sorted(members)

    with db.begin():
        group = db.get(ChatGroup, group_id, with_for_update=True)
        if group is None:
            raise UnknownGroup("Unknown group")
        if group.founder_user_id != caller:
            raise Forbidden("Only the founder can publish an epoch")

        if db.get(GroupEpoch, (group_id, epoch)) is not None:
            if ordered != roster(db, group_id, epoch):
                raise Conflict("Published epoch has a different roster")
        else:
            if epoch != current_epoch(db, group_id) + 1:
                raise Conflict("Publish the next consecutive epoch")
            if caller not in members:
                raise InvalidRoster("Roster must retain the founder")

            registered = set(
                db.scalars(select(User.user_id).where(User.user_id.in_(members)))
            )
            if registered != set(members):
                raise InvalidRoster("Roster contains an unregistered user")

            store_epoch(db, group_id, epoch, ordered)

        return EpochRosterResponse(
            group_id=group_id,
            epoch=epoch,
            member_user_ids=ordered,
        )