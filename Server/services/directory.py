from uuid import UUID

from sqlalchemy import exists, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from Security.models.key_models.key_package import PublicKeyPackage
from Security.services.group_services.key_services.key_package_service import (
    KeyPackageService,
    TrustedIdentity,
)

from ..dependencies import CurrentIdentity
from ..models import KeyPackage, PackageClaim, User
from ..schemas.public_key_package import PublicKeyPackagePayload
from ..schemas.user_registration import UserRegistration
from ..schemas.user_response import UserResponse


class UnknownUser(Exception):
    pass


class Conflict(Exception):
    pass


class InvalidPackage(Exception):
    pass


def register(
    db: Session,
    caller: CurrentIdentity,
    data: UserRegistration,
) -> UserResponse:
    fields = data.model_dump()
    fields["signing_public_key"] = caller.signing_public_key

    with db.begin():
        stmt = insert(User).values(user_id=caller.user_id, **fields)
        _ = db.execute(
            stmt.on_conflict_do_update(index_elements=[User.user_id], set_=fields)
        )

    return UserResponse(
        user_id=caller.user_id,
        display_name=data.display_name,
        websocket_url=data.websocket_url,
    )


def discover(db: Session) -> list[UserResponse]:
    rows = db.scalars(select(User).order_by(User.user_id))
    return [UserResponse.model_validate(row, from_attributes=True) for row in rows]


def publish(
    db: Session,
    caller: CurrentIdentity,
    package_id: str,
    payload: PublicKeyPackagePayload,
) -> PublicKeyPackagePayload:
    if package_id != payload.package_id:
        raise InvalidPackage("Package ID differs from the path")

    package = PublicKeyPackage(
        payload.package_id,
        payload.credential,
        payload.init_public_key,
        payload.leaf_public_key,
        payload.signing_public_key,
        payload.signature,
    )
    expected = TrustedIdentity(caller.user_id.encode("utf-8"), caller.signing_public_key)

    with db.begin():
        if db.get(User, caller.user_id) is None:
            raise UnknownUser("Publisher is not registered")

        if not KeyPackageService().verify_package(package, expected):
            raise InvalidPackage("Package failed identity or signature verification")

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


def prior_claim(
    db: Session,
    inviter: str,
    request_id: UUID,
    invitee: str,
) -> PublicKeyPackagePayload | None:
    row = db.scalar(
        select(KeyPackage)
        .join(PackageClaim)
        .where(
            PackageClaim.inviter_user_id == inviter,
            PackageClaim.request_id == request_id,
        )
    )

    if row is None:
        return None
    if row.owner_user_id != invitee:
        raise Conflict("Request ID already used for another invitee")

    return PublicKeyPackagePayload.model_validate(row, from_attributes=True)


def claim(
    db: Session,
    inviter: str,
    invitee: str,
    request_id: UUID,
) -> PublicKeyPackagePayload:
    with db.begin():
        prior = prior_claim(db, inviter, request_id, invitee)
        if prior is not None:
            return prior

        if db.get(User, inviter) is None:
            raise UnknownUser("Inviter is not registered")

        # On PostgreSQL this emits FOR NO KEY UPDATE. Claimants for the same
        # invitee serialize while foreign-key checks can still reference the user.
        lock = (
            select(User.user_id)
            .where(User.user_id == invitee)
            .with_for_update(key_share=True)
        )
        if db.scalar(lock) is None:
            raise UnknownUser("Invitee is not registered")

        prior = prior_claim(db, inviter, request_id, invitee)
        if prior is not None:
            return prior

        taken = exists().where(PackageClaim.package_id == KeyPackage.package_id)
        row = db.scalar(
            select(KeyPackage)
            .where(KeyPackage.owner_user_id == invitee, ~taken)
            .order_by(KeyPackage.package_id)
            .limit(1)
        )
        if row is None:
            raise Conflict("No available package")

        stmt = (
            insert(PackageClaim)
            .values(
                package_id=row.package_id,
                inviter_user_id=inviter,
                request_id=request_id,
            )
            .on_conflict_do_nothing(
                index_elements=[PackageClaim.inviter_user_id, PackageClaim.request_id]
            )
            .returning(PackageClaim.package_id)
        )

        if db.scalar(stmt) is None:
            # Another transaction committed this inviter/request pair first.
            prior = prior_claim(db, inviter, request_id, invitee)
            if prior is None:
                raise Conflict("Claim could not be resolved")
            return prior

        return PublicKeyPackagePayload.model_validate(row, from_attributes=True)