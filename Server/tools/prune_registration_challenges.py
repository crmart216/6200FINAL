from sqlalchemy.exc import SQLAlchemyError

from Server.core.database import get_session_factory
from Server.services.registration import prune_expired


def main() -> None:
    try:
        with get_session_factory()() as db:
            count = prune_expired(db)
    except (ValueError, SQLAlchemyError):
        raise SystemExit("Could not prune challenges. Check database settings and migration status.") from None
    print(f"Pruned {count} expired registration challenges")


if __name__ == "__main__":
    main()