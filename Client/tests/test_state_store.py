import sqlite3
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import pytest

from Client.models.local_identity import LocalIdentity
from Client.models.user_profile import UserProfile
from Client.state_store import ClientStateStore


@pytest.fixture
def identity() -> LocalIdentity:
    return LocalIdentity(UserProfile("user-1", "Ryan O'Connor"), b"\x00\xffprivate-key\x00")


def test_creates_database_and_schema_in_new_directory(tmp_path: Path) -> None:
    state_dir = tmp_path / "client-state"
    with closing(ClientStateStore(state_dir)) as store:
        assert store.load_identity() is None

    database = state_dir / "client.sqlite"
    assert database.is_file()
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)


def test_pending_identity_survives_reopen(tmp_path: Path, identity: LocalIdentity) -> None:
    with closing(ClientStateStore(tmp_path)) as store:
        store.save_pending_identity(identity)
        store.save_pending_identity(identity)

    with closing(ClientStateStore(tmp_path)) as reopened:
        saved = reopened.load_identity()
        assert saved is not None
        assert saved.profile == identity.profile
        assert saved.signing_private_key == identity.signing_private_key
        assert saved.api_token is None


def test_registered_identity_survives_reopen_and_retries(tmp_path: Path, identity: LocalIdentity) -> None:
    token = "issued-token"
    expected = replace(identity, api_token=token)
    with closing(ClientStateStore(tmp_path)) as store:
        store.save_pending_identity(identity)
        store.save_registered_identity(identity.profile.id, token)

    with closing(ClientStateStore(tmp_path)) as reopened:
        assert reopened.load_identity() == expected
        reopened.save_pending_identity(identity)
        reopened.save_registered_identity(identity.profile.id, token)
        assert reopened.load_identity() == expected

    with closing(ClientStateStore(tmp_path)) as reopened:
        assert reopened.load_identity() == expected


def test_conflicting_writes_preserve_saved_identity(tmp_path: Path, identity: LocalIdentity) -> None:
    token = "issued-token"
    expected = replace(identity, api_token=token)
    with closing(ClientStateStore(tmp_path)) as store:
        store.save_pending_identity(identity)
        store.save_registered_identity(identity.profile.id, token)

        for different in (
            replace(identity, profile=UserProfile("other-user", identity.profile.display_name)),
            replace(identity, profile=UserProfile(identity.profile.id, "Different name")),
            replace(identity, signing_private_key=b"different-key"),
        ):
            with pytest.raises(ValueError, match="different identity"):
                store.save_pending_identity(different)
            assert store.load_identity() == expected

        with pytest.raises(ValueError, match="user ID does not match"):
            store.save_registered_identity("other-user", token)
        assert store.load_identity() == expected
        with pytest.raises(ValueError, match="different API token"):
            store.save_registered_identity(identity.profile.id, "replacement-token")
        assert store.load_identity() == expected

    with closing(ClientStateStore(tmp_path)) as reopened:
        assert reopened.load_identity() == expected


def test_registration_and_pending_save_require_valid_state(tmp_path: Path, identity: LocalIdentity) -> None:
    with closing(ClientStateStore(tmp_path)) as store:
        with pytest.raises(ValueError, match="Save a pending identity"):
            store.save_registered_identity(identity.profile.id, "issued-token")
        with pytest.raises(ValueError, match="must have no API token"):
            store.save_pending_identity(replace(identity, api_token="issued-token"))
        assert store.load_identity() is None

        store.save_pending_identity(identity)
        with pytest.raises(ValueError, match="nonblank"):
            store.save_registered_identity(identity.profile.id, " \t")
        assert store.load_identity() == identity


def test_failed_sqlite_write_rolls_back(tmp_path: Path, identity: LocalIdentity) -> None:
    with closing(ClientStateStore(tmp_path)) as store:
        store.save_pending_identity(identity)
        with closing(sqlite3.connect(tmp_path / "client.sqlite")) as connection, connection:
            _ = connection.execute("""
                CREATE TRIGGER fail_registration AFTER UPDATE ON local_identity
                BEGIN
                    SELECT RAISE(FAIL, 'simulated write failure');
                END
                """)

        with pytest.raises(sqlite3.IntegrityError, match="simulated write failure"):
            store.save_registered_identity(identity.profile.id, "issued-token")
        assert store.load_identity() == identity

    with closing(ClientStateStore(tmp_path)) as reopened:
        assert reopened.load_identity() == identity


def test_unsupported_schema_version_is_rejected(tmp_path: Path, identity: LocalIdentity) -> None:
    with closing(ClientStateStore(tmp_path)) as store:
        store.save_pending_identity(identity)

    database = tmp_path / "client.sqlite"
    with closing(sqlite3.connect(database)) as connection, connection:
        _ = connection.execute("PRAGMA user_version = 2")

    with pytest.raises(RuntimeError, match="Unsupported client database schema version: 2"):
        with closing(ClientStateStore(tmp_path)):
            pytest.fail("An unsupported database opened successfully.")

    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (2,)
        assert connection.execute("SELECT user_id FROM local_identity").fetchone() == (identity.profile.id,)


def test_local_identity_repr_excludes_credentials(identity: LocalIdentity) -> None:
    registered = replace(identity, api_token="issued-token")
    assert "private-key" not in repr(registered)
    assert "issued-token" not in repr(registered)