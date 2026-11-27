import argparse
import os
import subprocess
import sys
from pathlib import Path

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.engine import URL


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_DATABASE = "chat_demo_migration_test"


def test_database_url() -> "URL":
    from psycopg import Error
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import DBAPIError

    from Server.core.config import get_settings

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


def run_pytest() -> int:
    target = test_database_url()
    env = os.environ.copy()
    env["SERVER_MIGRATION_TEST_URL"] = target.render_as_string(hide_password=False)
    env["RUN_POSTGRES_TESTS"] = "1"
    _ = env.pop("POSTGRES_PASSWORD", None)

    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-vv", "-ra", "--capture=tee-sys", "Server/tests"],
        cwd=PROJECT_ROOT,
        env=env,
        check=False,
    )
    return result.returncode


def run_in_compose(use_sudo: bool) -> int:
    compose = ["sudo", "docker", "compose"] if use_sudo else ["docker", "compose"]

    try:
        _ = subprocess.run(
            [*compose, "up", "-d", "--wait", "db"], cwd=PROJECT_ROOT, check=True,
        )
        password = subprocess.run(
            [*compose, "exec", "-T", "db", "sh", "-ec", 'printf "%s\n" "$POSTGRES_PASSWORD"'],
            cwd=PROJECT_ROOT,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        result = subprocess.run(
            [
                *compose, "run", "--build", "--rm", "--no-deps", "-T",
                "--user", f"{os.getuid()}:{os.getgid()}",
                "--volume", f"{PROJECT_ROOT}:/workspace:ro",
                "--workdir", "/workspace",
                "api", "sh", "-ec",
                """IFS= read -r POSTGRES_PASSWORD
export POSTGRES_PASSWORD PYTHONDONTWRITEBYTECODE=1
python -m venv /tmp/server-test-venv
/tmp/server-test-venv/bin/python -m pip install --no-cache-dir -r Server/requirements-dev.txt
exec /tmp/server-test-venv/bin/python -m Server.tools.run_tests --inside-container
""",
            ],
            cwd=PROJECT_ROOT,
            input=password,
            check=False,
        )
        return result.returncode
    except FileNotFoundError:
        print("Unable to launch Docker Compose. Check that Docker is installed.", file=sys.stderr)
        return 127
    except subprocess.CalledProcessError as exc:
        return exc.returncode


class TestOptions(argparse.Namespace):
    sudo: bool = False
    inside_container: bool = False


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the server tests using Docker Compose.")
    _ = parser.add_argument("--sudo", action="store_true", help="Run Docker Compose with sudo.")
    _ = parser.add_argument("--inside-container", action="store_true", help=argparse.SUPPRESS)
    args = TestOptions()
    _ = parser.parse_args(namespace=args)

    if args.inside_container:
        return run_pytest()
    return run_in_compose(args.sudo)


if __name__ == "__main__":
    raise SystemExit(main())
