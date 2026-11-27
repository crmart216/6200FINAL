from collections.abc import Generator
from contextlib import contextmanager
from uuid import UUID

from fastapi import APIRouter, HTTPException, Response

from ..schemas.invitation_claim_response import InvitationClaimResponse
from ..schemas.invitation_create_request import InvitationCreateRequest
from ..schemas.invitation_decision_request import InvitationDecisionRequest
from ..schemas.invitation_response import InvitationDirection, InvitationResponse, InvitationStatus
from ..services import directory, groups, invitation
from .groups import Caller, Database, GroupId

router = APIRouter(tags=["Invitations"], responses={401: {"description": "Missing or invalid bearer token"}})
NOT_FOUND: dict[int | str, dict[str, object]] = {404: {"description": "Invitation unavailable to caller"}}
NOT_APPROVED: dict[int | str, dict[str, object]] = {409: {"description": "Invitation lacks an approved package or has a conflicting state"}}


@contextmanager
def invitation_errors() -> Generator[None, None, None]:
    try:
        yield
    except invitation.Unavailable as exc:
        raise HTTPException(404, str(exc)) from None
    except groups.Forbidden as exc:
        raise HTTPException(403, str(exc)) from None
    except groups.Conflict as exc:
        raise HTTPException(409, str(exc)) from None
    except directory.InvalidPackage as exc:
        raise HTTPException(422, str(exc)) from None
    except invitation.CreationLimit:
        raise HTTPException(429, "Invitation creation limit reached", headers={"Retry-After": "60"}) from None


@router.post(
    "/groups/{group_id}/invitations", status_code=201, summary="Invite a user to your group",
    response_model_exclude_none=True,
    responses={
        200: {"model": InvitationResponse, "description": "Existing active invitation"},
        403: {"description": "Only the founder can invite"},
        404: {"description": "Group or invitee unavailable"},
        409: {"description": "Invitee already belongs to the group"},
        429: {"description": "Invitation creation limit reached"},
    },
)
def create(
    group_id: GroupId, data: InvitationCreateRequest, caller: Caller, db: Database, response: Response,
) -> InvitationResponse:
    with invitation_errors():
        details, created = invitation.create(db, group_id, caller.user_id, data.invitee_user_id)
        if not created:
            response.status_code = 200
        return details


@router.get("/invitations", summary="List your invitations", response_model_exclude_none=True)
def list_for(
    caller: Caller, db: Database, direction: InvitationDirection | None = None,
    status: InvitationStatus | None = None,
) -> list[InvitationResponse]:
    return invitation.list_for(db, caller.user_id, direction, status)


@router.get(
    "/invitations/{invitation_id}", summary="Read an invitation",
    response_model_exclude_none=True, responses=NOT_FOUND,
)
def get(invitation_id: UUID, caller: Caller, db: Database) -> InvitationResponse:
    with invitation_errors():
        return invitation.get(db, invitation_id, caller.user_id)


@router.put(
    "/invitations/{invitation_id}/decision", summary="Accept or decline an invitation",
    response_model_exclude_none=True,
    responses=NOT_FOUND | NOT_APPROVED | {422: {"description": "Invalid decision or signed package"}},
)
def decide(
    invitation_id: UUID, data: InvitationDecisionRequest, caller: Caller, db: Database,
) -> InvitationResponse:
    with invitation_errors():
        return invitation.decide(db, invitation_id, caller.user_id, data)


@router.post(
    "/invitations/{invitation_id}/claim", summary="Claim the approved key package",
    responses=NOT_FOUND | NOT_APPROVED,
)
def claim(invitation_id: UUID, caller: Caller, db: Database) -> InvitationClaimResponse:
    with invitation_errors():
        return invitation.claim(db, invitation_id, caller.user_id)