from fastapi import APIRouter

from .routes import groups, messages, users

router = APIRouter(prefix="/api")
router.include_router(users.router, prefix="/users")
router.include_router(groups.router, prefix="/groups")
router.include_router(messages.router, prefix="/groups")