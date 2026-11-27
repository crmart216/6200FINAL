from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from Security.models.key_models.key_package import PublicKeyPackage
from Security.services.group_services.key_services.key_package_service import (
    KeyPackageService,
    TrustedIdentity,
)

from Server.core.dependencies import CurrentIdentity
from ..models import KeyPackage, User
from ..schemas.public_key_package import PublicKeyPackagePayload
from ..schemas.user_registration import UserRegistration
from ..schemas.user_response import UserResponse


class UnknownUser(Exception):
    pass


class Conflict(Exception):
    pass


class InvalidPackage(Exception):
    pass


def update_profile(
    db: Session,
    caller: CurrentIdentity,
    data: UserRegistration,
) -> UserResponse:
    with db.begin():
        user = db.get(User, caller.user_id)
        if user is None:
            raise UnknownUser("User is not registered")
        user.display_name = data.display_name
        user.websocket_url = data.websocket_url
        return UserResponse.model_validate(user, from_attributes=True)


def discover(db: Session) -> list[UserResponse]:
    rows = db.scalars(select(User).order_by(User.user_id))
    return [UserResponse.model_validate(row, from_attributes=True) for row in rows]


def verify_package(user_id: str, signing_key: bytes, payload: PublicKeyPackagePayload) -> None:
    package = PublicKeyPackage(
        payload.package_id,
        payload.credential,
        payload.init_public_key,
        payload.leaf_public_key,
        payload.signing_public_key,
        payload.signature,
    )
    expected = TrustedIdentity(user_id.encode("utf-8"), signing_key)

    if not KeyPackageService().verify_package(package, expected):
        raise InvalidPackage("Package failed identity or signature verification")


def publish(
    db: Session,
    caller: CurrentIdentity,
    package_id: str,
    payload: PublicKeyPackagePayload,
) -> PublicKeyPackagePayload:
    if package_id != payload.package_id:
        raise InvalidPackage("Package ID differs from the path")

    with db.begin():
        if db.get(User, caller.user_id) is None:
            raise UnknownUser("Publisher is not registered")

        verify_package(caller.user_id, caller.signing_public_key, payload)

        stmt = insert(KeyPackage).values(
            owner_user_id=caller.user_id,
            **payload.model_dump(),
        )
        _ = db.execute(
            stmt.on_conflict_do_nothing(index_elements=[KeyPackage.package_id])
        )

        stored = db.get_one(KeyPackage, package_id)
        if stored.owner_user_id != caller.user_id or payload != PublicKeyPackagePayload.model_validate(
            stored, from_attributes=True
        ):
            raise Conflict("Package ID is already in use")

    return payload
