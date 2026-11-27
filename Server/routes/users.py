from collections.abc import Generator
from contextlib import contextmanager
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..dependencies import CurrentIdentity, get_current_identity, get_db
from ..schemas.package_claim_request import PackageClaimRequest
from ..schemas.public_key_package import PublicKeyPackagePayload
from ..schemas.user_registration import UserRegistration
from ..schemas.user_response import UserResponse
from ..services import directory


router = APIRouter()
Caller = Annotated[CurrentIdentity, Depends(get_current_identity)]
Database = Annotated[Session, Depends(get_db)]


def require_owner(caller: CurrentIdentity, user_id: str) -> None:
    if caller.user_id != user_id:
        raise HTTPException(403, "Caller does not own this user ID")


@contextmanager
def directory_errors() -> Generator[None, None, None]:
    try:
        yield
    except directory.UnknownUser as exc:
        raise HTTPException(404, str(exc)) from exc
    except directory.Conflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except directory.InvalidPackage as exc:
        raise HTTPException(422, str(exc)) from exc


@router.put("/{user_id}")
def register(
    user_id: str,
    data: UserRegistration,
    caller: Caller,
    db: Database,
) -> UserResponse:
    require_owner(caller, user_id)
    return directory.register(db, caller, data)


@router.get("")
def discover(_caller: Caller, db: Database) -> list[UserResponse]:
    return directory.discover(db)


@router.put("/{user_id}/key-packages/{package_id}")
def publish(
    user_id: str,
    package_id: str,
    data: PublicKeyPackagePayload,
    caller: Caller,
    db: Database,
) -> PublicKeyPackagePayload:
    require_owner(caller, user_id)
    with directory_errors():
        return directory.publish(db, caller, package_id, data)


@router.post("/{user_id}/key-packages/claims")
def claim(
    user_id: str,
    data: PackageClaimRequest,
    caller: Caller,
    db: Database,
) -> PublicKeyPackagePayload:
    with directory_errors():
        return directory.claim(db, caller.user_id, user_id, data.request_id)