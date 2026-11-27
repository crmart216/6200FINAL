from fastapi import APIRouter

from . import groups, invitations, messages, registrations, users

router = APIRouter(prefix="/api")
router.include_router(users.router, prefix="/users")
router.include_router(groups.router, prefix="/groups")
router.include_router(messages.router, prefix="/groups")
router.include_router(registrations.router)
router.include_router(invitations.router)