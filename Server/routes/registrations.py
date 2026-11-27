from collections import OrderedDict
from collections.abc import Callable, Coroutine
from threading import Lock
from time import monotonic
from typing import Annotated, final, override

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.routing import APIRoute
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from Server.core.config import get_settings
from Server.core.dependencies import get_db
from ..schemas.registration_challenge_request import RegistrationChallengeRequest
from ..schemas.registration_challenge_response import RegistrationChallengeResponse
from ..schemas.registration_request import RegistrationRequest
from ..schemas.registration_response import RegistrationResponse
from ..services import registration

Database = Annotated[Session, Depends(get_db)]


@final
class PeerRateLimit:
    """A bounded fixed-window limiter for one process and one endpoint."""

    def __init__(self, attempts: int, capacity: int = 4096, window_seconds: int = 60) -> None:
        self.attempts = attempts
        self.capacity = capacity
        self.window_seconds = window_seconds
        self.windows: OrderedDict[str, tuple[float, int]] = OrderedDict()
        self.lock = Lock()

    def allow(self, peer: str) -> bool:
        with self.lock:
            now = monotonic()
            while self.windows and next(iter(self.windows.values()))[0] <= now:
                _ = self.windows.popitem(last=False)

            entry = self.windows.get(peer)
            if entry is None:
                if len(self.windows) >= self.capacity:
                    return False
                self.windows[peer] = (now + self.window_seconds, 1)
                return True

            deadline, used = entry
            if used >= self.attempts:
                return False
            self.windows[peer] = (deadline, used + 1)
            return True


challenge_limit = PeerRateLimit(attempts=20)
registration_limit = PeerRateLimit(attempts=10)


class SignupRoute(APIRoute):
    @override
    def get_route_handler(self) -> Callable[[Request], Coroutine[object, object, Response]]:
        handler = super().get_route_handler()

        async def guarded(request: Request) -> Response:
            if not get_settings().public_signup_enabled:
                raise HTTPException(404, "Public signup is disabled")

            limiter = challenge_limit if self.path.endswith("/registration-challenges") else registration_limit
            peer = request.client.host if request.client is not None else "unknown"
            if not limiter.allow(peer):
                raise HTTPException(429, "Too many signup requests", headers={"Retry-After": "60"})
            return await handler(request)

        return guarded


router = APIRouter(tags=["Registration"], route_class=SignupRoute)


@router.post(
    "/registration-challenges", status_code=201,
    summary="Request a registration challenge",
    responses={404: {"description": "Public signup is disabled"}, 429: {"description": "Rate limit reached"}},
)
def issue(data: RegistrationChallengeRequest, db: Database) -> RegistrationChallengeResponse:
    try:
        return registration.issue(db, data)
    except SQLAlchemyError:
        raise HTTPException(503, "Registration temporarily unavailable") from None


@router.post(
    "/registrations", status_code=201,
    summary="Register an account and issue its first bearer token",
    responses={
        404: {"description": "Public signup is disabled"},
        409: {"description": "User ID already taken"},
        422: {"description": "Invalid request, proof, or challenge"},
        429: {"description": "Rate limit reached"},
    },
)
def register(data: RegistrationRequest, db: Database, response: Response) -> RegistrationResponse:
    try:
        result = registration.register(db, data)
    except registration.InvalidChallenge:
        raise HTTPException(422, "Invalid registration proof or challenge") from None
    except registration.UserIdTaken:
        raise HTTPException(409, "User ID already taken") from None
    except (registration.TokenCollision, SQLAlchemyError):
        raise HTTPException(503, "Registration temporarily unavailable") from None
    response.headers["Cache-Control"] = "no-store"
    return result
