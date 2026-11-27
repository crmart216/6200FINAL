import os

import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url

from .config import get_settings


def main() -> None:
    url = make_url(get_settings().database_url.get_secret_value())
    if url.username != "chat_demo_app" or url.database != "chat_demo" or not url.password:
        raise SystemExit("Expected chat_demo_app, chat_demo, and an application password.")

    def admin(database: str) -> psycopg.Connection:
        return psycopg.connect(
            host=url.host,
            port=url.port,
            dbname=database,
            user="postgres",
            password=os.environ["POSTGRES_PASSWORD"],
            autocommit=True,
        )

    with admin("postgres") as conn:
        owner = conn.execute(
            "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = 'chat_demo'"
        ).fetchone()
        if owner and owner[0] != "chat_demo_app":
            raise SystemExit(
                f"Existing chat_demo owner is {owner[0]}. Review before proceeding."
            )

        role = conn.execute("""
            SELECT rolcanlogin AND NOT (
                rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls
                OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member = r.oid)
            )
            FROM pg_roles AS r
            WHERE rolname = 'chat_demo_app'
        """).fetchone()
        if role and not role[0]:
            raise SystemExit("Existing application role has incompatible privileges or memberships.")

        if role is None:
            verifier = conn.pgconn.encrypt_password(
                url.password.encode(), b"chat_demo_app", b"scram-sha-256"
            ).decode()
            _ = conn.execute(
                sql.SQL(
                    "CREATE ROLE chat_demo_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD {}"
                ).format(sql.Literal(verifier))
            )

        if owner is None:
            _ = conn.execute("CREATE DATABASE chat_demo OWNER chat_demo_app")

    with admin("chat_demo") as conn:
        tables = conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename"
        ).fetchall()
        if tables:
            raise SystemExit(f"Existing public tables: {[row[0] for row in tables]}. Stopping.")

        grants = conn.execute("""
            SELECT has_schema_privilege('chat_demo_app', 'public', 'USAGE'),
                   has_schema_privilege('chat_demo_app', 'public', 'CREATE')
        """).fetchone()
        if grants != (True, True):
            _ = conn.execute("GRANT USAGE, CREATE ON SCHEMA public TO chat_demo_app")


if __name__ == "__main__":
    main()