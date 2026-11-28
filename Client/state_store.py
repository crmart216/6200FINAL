"""SQLite persistence for the local account and founder groups."""

import sqlite3
from pathlib import Path
from typing import cast

from .models.group_summary import GroupSummary
from .models.local_group import GroupStatus, LocalGroup
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
            if version == 2:
                return
            if version not in (0, 1):
                raise RuntimeError(f"Unsupported client database schema version: {version}")
            if version == 0:
                _ = self._connection.execute("""
                    CREATE TABLE local_identity (
                        id INTEGER PRIMARY KEY CHECK (id = 1),
                        user_id TEXT NOT NULL,
                        display_name TEXT NOT NULL,
                        signing_private_key BLOB NOT NULL,
                        api_token TEXT
                    )
                    """)
            _ = self._connection.execute("""
                CREATE TABLE local_group (
                    group_id TEXT PRIMARY KEY NOT NULL,
                    title TEXT NOT NULL,
                    founder_id TEXT NOT NULL,
                    snapshot BLOB NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('pending', 'confirmed'))
                )
                """)
            _ = self._connection.execute("PRAGMA user_version = 2")

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

    def save_pending_group(self, group: LocalGroup) -> None:
        if group.status != "pending":
            raise ValueError("A new local group must be pending.")
        with self._connection:
            _ = self._connection.execute(
                """
                INSERT INTO local_group (group_id, title, founder_id, snapshot, status)
                VALUES (?, ?, ?, ?, 'pending')
                """,
                (group.summary.id, group.summary.name, group.summary.founder_id, group.snapshot),
            )

    def load_group(self, group_id: str) -> LocalGroup | None:
        cursor = self._connection.execute(
            "SELECT group_id, title, founder_id, snapshot, status FROM local_group WHERE group_id = ?",
            (group_id,),
        )
        row = cast(tuple[object, object, object, object, object] | None, cursor.fetchone())
        if row is None:
            return None
        saved_id, title, founder_id, snapshot, status = row
        if (
            not isinstance(saved_id, str) or not isinstance(title, str)
            or not isinstance(founder_id, str) or not isinstance(snapshot, bytes)
            or status not in ("pending", "confirmed")
        ):
            raise RuntimeError("Invalid group record in the client database.")
        return LocalGroup(GroupSummary(saved_id, title, founder_id), snapshot, status)

    def list_groups(self, founder_id: str, *, status: GroupStatus = "confirmed") -> list[GroupSummary]:
        cursor = self._connection.execute(
            """
            SELECT group_id, title, founder_id FROM local_group
            WHERE founder_id = ? AND status = ?
            ORDER BY title, group_id
            """,
            (founder_id, status),
        )
        rows = cast(list[tuple[str, str, str]], cursor.fetchall())
        return [GroupSummary(group_id, title, owner) for group_id, title, owner in rows]

    def confirm_group(self, group_id: str, founder_id: str) -> None:
        with self._connection:
            cursor = self._connection.execute(
                "UPDATE local_group SET status = 'confirmed' WHERE group_id = ? AND founder_id = ?",
                (group_id, founder_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("The local group was not found for this account.")

    def close(self) -> None:
        self._connection.close()
