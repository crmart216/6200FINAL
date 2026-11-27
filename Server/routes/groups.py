from collections.abc import Generator
from contextlib import contextmanager
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.orm import Session

from ..dependencies import CurrentIdentity, get_current_identity, get_db
from ..schemas.epoch_roster_update import EpochRosterResponse, EpochRosterUpdate
from ..schemas.group_registration import GroupRegistration, GroupResponse
from ..services import groups


router = APIRouter()
Caller = Annotated[CurrentIdentity, Depends(get_current_identity)]
Database = Annotated[Session, Depends(get_db)]
GroupId = Annotated[str, Path(pattern=r"^[^\x00]+$")]
Epoch = Annotated[int, Path(ge=0, le=2**63 - 1)]


@contextmanager
def group_errors() -> Generator[None, None, None]:
    try:
        yield
    except groups.Forbidden as exc:
        raise HTTPException(403, str(exc)) from exc
    except groups.UnknownGroup as exc:
        raise HTTPException(404, str(exc)) from exc
    except groups.Conflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except groups.InvalidRoster as exc:
        raise HTTPException(422, str(exc)) from exc


@router.put("/{group_id}")
def register(
    group_id: GroupId,
    data: GroupRegistration,
    caller: Caller,
    db: Database,
) -> GroupResponse:
    with group_errors():
        return groups.register(db, group_id, data.group_name, caller.user_id)


@router.put("/{group_id}/epochs/{epoch}")
def publish(
    group_id: GroupId,
    epoch: Epoch,
    data: EpochRosterUpdate,
    caller: Caller,
    db: Database,
) -> EpochRosterResponse:
    with group_errors():
        return groups.publish(db, group_id, epoch, caller.user_id, data.member_user_ids)