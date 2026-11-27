from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from Server.core.config import DemoIdentity, get_settings
from Server.core.database import get_session_factory
from Server.models import ApiCredential, User
from Server.models.api_credential import digest_api_token


class BackfillConflict(Exception):
    """The configured identity conflicts with a registered account or credential."""


@dataclass(frozen=True)
class BackfillCounts:
    inserted: int
    unchanged: int
    skipped_user_ids: tuple[str, ...] = ()

    @property
    def skipped(self) -> int:
        return len(self.skipped_user_ids)


def backfill(db: Session, identities: Iterable[DemoIdentity]) -> BackfillCounts:
    inserted = unchanged = 0
    skipped: list[str] = []
    with db.begin():
        for identity in sorted(identities, key=lambda item: item.user_id):
            user_id = identity.user_id
            user = db.get(User, user_id, with_for_update=True)
            if user is None:
                skipped.append(user_id)
                continue
            if user.signing_public_key != identity.signing_public_key:
                raise BackfillConflict(f"Signing key mismatch for user {user_id!r}")

            digest = digest_api_token(identity.api_token.get_secret_value())
            statement = (
                insert(ApiCredential)
                .values(user_id=user_id, token_digest=digest)
                .on_conflict_do_nothing()
                .returning(ApiCredential.user_id)
            )
            if db.scalar(statement) is not None:
                inserted += 1
                continue

            stored = db.get(ApiCredential, user_id, populate_existing=True)
            if stored is None:
                raise BackfillConflict(f"Credential for user {user_id!r} is assigned to another user")
            if stored.token_digest != digest:
                raise BackfillConflict(f"Existing credential differs for user {user_id!r}")
            unchanged += 1

    return BackfillCounts(inserted, unchanged, tuple(skipped))


def main() -> None:
    try:
        identities = get_settings().demo_identities
        with get_session_factory()() as db:
            counts = backfill(db, identities)
    except BackfillConflict as exc:
        raise SystemExit(f"Backfill rolled back. {exc}") from None
    except ValueError:
        raise SystemExit("Backfill failed. Check server settings.") from None
    except SQLAlchemyError:
        raise SystemExit("Backfill failed. Check database connectivity and migration status.") from None

    print(f"Inserted {counts.inserted}, unchanged {counts.unchanged}, skipped {counts.skipped}")
    for user_id in counts.skipped_user_ids:
        print(f"Skipped user {user_id!r}: no existing account")


if __name__ == "__main__":
    main()