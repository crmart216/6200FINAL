"""SQLite persistence for the client's local identity."""

import sqlite3
from pathlib import Path
from typing import cast

from .models.local_identity import LocalIdentity
from .models.user_profile import UserProfile


class ClientStateStore:
    """Own the SQLite connection for one client state directory."""

    def __init__(self, state_dir: Path) -> None:
        state_dir.mkdir(parents=True, exist_ok=True)
        self._connection: sqlite3.Connection = sqlite3.connect(state_dir / "client.sqlite")
        try:
            self._initialize_schema()
        except BaseException:
            self.close()
            raise

    def _initialize_schema(self) -> None:
        with self._connection:
            _ = self._connection.execute("BEGIN IMMEDIATE")
            row = cast(tuple[int], self._connection.execute("PRAGMA user_version").fetchone())
            version = row[0]
            if version == 1:
                return
            if version != 0:
                raise RuntimeError(f"Unsupported client database schema version: {version}")

            _ = self._connection.execute("""
                CREATE TABLE local_identity (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    user_id TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    signing_private_key BLOB NOT NULL,
                    api_token TEXT
                )
                """)
            _ = self._connection.execute("PRAGMA user_version = 1")

    def load_identity(self) -> LocalIdentity | None:
        cursor = self._connection.execute("""
            SELECT user_id, display_name, signing_private_key, api_token
            FROM local_identity
            WHERE id = 1
            """)
        row = cast(tuple[object, object, object, object] | None, cursor.fetchone())
        if row is None:
            return None

        user_id, display_name, signing_private_key, api_token = row
        if (
            not isinstance(user_id, str)
            or not isinstance(display_name, str)
            or not isinstance(signing_private_key, bytes)
            or (api_token is not None and not isinstance(api_token, str))
        ):
            raise RuntimeError("Invalid local identity stored in the client database.")
        return LocalIdentity(UserProfile(user_id, display_name), signing_private_key, api_token)

    def save_pending_identity(self, identity: LocalIdentity) -> None:
        if identity.api_token is not None:
            raise ValueError("A pending identity must have no API token.")

        with self._connection:
            _ = self._connection.execute("BEGIN IMMEDIATE")
            saved = self.load_identity()
            if saved is not None:
                if saved.profile != identity.profile or saved.signing_private_key != identity.signing_private_key:
                    raise ValueError("This client database already contains a different identity.")
                return

            _ = self._connection.execute(
                """
                INSERT INTO local_identity (id, user_id, display_name, signing_private_key)
                VALUES (1, ?, ?, ?)
                """,
                (identity.profile.id, identity.profile.display_name, identity.signing_private_key),
            )

    def save_registered_identity(self, user_id: str, api_token: str) -> None:
        if not api_token.strip():
            raise ValueError("The API token must be nonblank.")

        with self._connection:
            _ = self._connection.execute("BEGIN IMMEDIATE")
            saved = self.load_identity()
            if saved is None:
                raise ValueError("Save a pending identity before registration.")
            if saved.profile.id != user_id:
                raise ValueError("The user ID does not match the saved identity.")
            if saved.api_token is not None:
                if saved.api_token != api_token:
                    raise ValueError("The saved identity already has a different API token.")
                return

            _ = self._connection.execute(
                "UPDATE local_identity SET api_token = ? WHERE id = 1",
                (api_token,),
            )

    def close(self) -> None:
        self._connection.close()