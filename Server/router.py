from fastapi import APIRouter
from .routes import users

router = APIRouter(prefix="/api")
router.include_router(users.router, prefix="/users", tags=["users"])