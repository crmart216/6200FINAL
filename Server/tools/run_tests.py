import os
import subprocess
import sys
from pathlib import Path

from psycopg import Error
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import DBAPIError

from Server.core.config import get_settings


TEST_DATABASE = "chat_demo_migration_test"


def test_database_url() -> URL:
    configured = os.getenv("SERVER_MIGRATION_TEST_URL")
    demo = make_url(get_settings().database_url.get_secret_value())
    target = make_url(configured) if configured else demo.set(database=TEST_DATABASE)

    if target.drivername != "postgresql+psycopg" or target.database != TEST_DATABASE:
        raise SystemExit(f"Expected a PostgreSQL test URL for {TEST_DATABASE}.")

    maintenance = target.set(database="postgres")
    engine = create_engine(maintenance)
    try:
        with engine.connect() as conn:
            exists = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"),
                {"name": TEST_DATABASE},
            ).first() is not None

        if exists:
            return target
    finally:
        engine.dispose()

    password = os.getenv("POSTGRES_PASSWORD")
    if not password or target.username != "chat_demo_app":
        raise SystemExit(
            "To create the test database, use the chat_demo_app login and "
            + "set POSTGRES_PASSWORD to the project's postgres administrator password."
        )

    admin = create_engine(
        maintenance.set(username="postgres", password=password),
        isolation_level="AUTOCOMMIT",
    )
    try:
        with admin.connect() as conn:
            try:
                _ = conn.exec_driver_sql(
                    "CREATE DATABASE chat_demo_migration_test OWNER chat_demo_app TEMPLATE template0"
                )
            except DBAPIError as exc:
                # A second runner may have created the database at the same time.
                if not isinstance(exc.orig, Error) or exc.orig.sqlstate not in {"42P04", "23505"}:
                    raise
                if not conn.scalar(
                    text("SELECT 1 FROM pg_database WHERE datname = :name"),
                    {"name": TEST_DATABASE},
                ):
                    raise
    finally:
        admin.dispose()

    return target


def main() -> int:
    target = test_database_url()
    env = os.environ.copy()
    env["SERVER_MIGRATION_TEST_URL"] = target.render_as_string(hide_password=False)
    env["RUN_POSTGRES_TESTS"] = "1"
    _ = env.pop("POSTGRES_PASSWORD", None)

    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-ra", "Server/tests"],
        cwd=Path(__file__).resolve().parent.parent,
        env=env,
        check=False,
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())