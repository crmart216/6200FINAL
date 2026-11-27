from collections.abc import Generator
from contextlib import contextmanager
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.orm import Session

from Server.core.dependencies import CurrentIdentity, get_current_identity, get_db
from ..schemas.epoch_roster_update import EpochRosterResponse, EpochRosterUpdate
from ..schemas.group_registration import GroupRegistration, GroupResponse
from ..services import groups

router = APIRouter(tags=["Groups"], responses={401: {"description": "Missing or invalid bearer token"}})
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


@router.put("/{group_id}", summary="Register a group at epoch zero",
            responses={403: {"description": "Register the caller first"},
                        409: {"description": "Group ID has a different founder or name"}})

def register(
    group_id: GroupId, 
    data: GroupRegistration, 
    caller: Caller,
    db: Database
) -> GroupResponse:
    """The caller becomes the founder. Retrying the same ID and name returns the current epoch."""
    with group_errors():
        return groups.register(db, group_id, data.group_name, caller.user_id)


@router.put("/{group_id}/epochs/{epoch}", summary="Publish a complete epoch roster",
            responses={403: {"description": "Only the founder can publish"},
                        404: {"description": "Unknown group"},
                        409: {"description": "Skipped epoch or conflicting published roster"},
                        422: {"description": "Invalid epoch, unknown or duplicate member, or missing founder"}})

def publish(
    group_id: GroupId, 
    epoch: Epoch, 
    data: EpochRosterUpdate,
    caller: Caller, 
    db: Database
) -> EpochRosterResponse:
    """Publish consecutive epochs with all member IDs, including the founder. An identical
    roster in any order succeeds on retry, including for an earlier epoch.
    """
    with group_errors():
        return groups.publish(db, group_id, epoch, caller.user_id, data.member_user_ids)