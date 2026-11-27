from fastapi import APIRouter

from .routes import groups, users


router = APIRouter(prefix="/api")
router.include_router(users.router, prefix="/users")
router.include_router(groups.router, prefix="/groups")