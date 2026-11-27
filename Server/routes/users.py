from collections.abc import Generator
from contextlib import contextmanager
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session

from Server.core.dependencies import CurrentIdentity, get_current_identity, get_db
from ..schemas.package_claim_request import PackageClaimRequest
from ..schemas.public_key_package import PublicKeyPackagePayload
from ..schemas.user_registration import UserRegistration
from ..schemas.user_response import UserResponse
from ..services import directory

router = APIRouter(tags=["Users"], responses={401: {"description": "Missing or invalid bearer token"}})
Caller = Annotated[CurrentIdentity, Depends(get_current_identity)]
Database = Annotated[Session, Depends(get_db)]


RegistrationBody = Annotated[UserRegistration, Body(examples=[{
    "display_name": "Alice", "websocket_url": "ws://alice.local:5555"
}])]


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


@router.put("/{user_id}", summary="Register or refresh your directory entry",
            responses={403: {"description": "Caller does not own this user ID"}})

def register(
    user_id: str, 
    data: RegistrationBody, 
    caller: Caller, 
    db: Database
) -> UserResponse:
    """Register your own ID or refresh its name and peer listener address."""
    require_owner(caller, user_id)
    return directory.register(db, caller, data)


@router.get("", summary="List registered peers in user ID order")
def discover(
    _caller: Caller, 
    db: Database
) -> list[UserResponse]:
    return directory.discover(db)


@router.put("/{user_id}/key-packages/{package_id}", summary="Publish a signed public key package",
            responses={403: {"description": "Caller does not own this user ID"},
                        404: {"description": "Publisher has not registered"},
                        409: {"description": "Package ID already used for another owner or content"},
                        422: {"description": "Invalid fields, mismatched ID, identity or signature"}})
def publish(
    user_id: str, 
    package_id: str, 
    data: PublicKeyPackagePayload,
    caller: Caller,
    db: Database
) -> PublicKeyPackagePayload:
    """Use the client-generated package for your pinned identity. Encode the credential,
    three public keys and signature as standard Base64. An identical retry succeeds after claim.
    """
    require_owner(caller, user_id)
    with directory_errors():
        return directory.publish(db, caller, package_id, data)


@router.post("/{user_id}/key-packages/claims", summary="Claim one package from a peer",
            responses={404: {"description": "Inviter or invitee has not registered"},
                        409: {"description": "Pool exhausted or request ID used for another invitee"}})
def claim(
    user_id: str, 
    data: PackageClaimRequest, 
    caller: Caller,
    db: Database
) -> PublicKeyPackagePayload:
    """Reuse the same request UUID for a retry. The same inviter and invitee receive
    the original package even when another package is available.
    """
    with directory_errors():
        return directory.claim(db, caller.user_id, user_id, data.request_id)