import os

import pytest
from sqlalchemy import text

from Server.core.database import get_engine


if os.getenv("RUN_POSTGRES_TESTS") != "1":
    pytest.skip(
        "Set RUN_POSTGRES_TESTS=1 to check the demo database.",
        allow_module_level=True,
    )


def test_application_login_can_execute_select_one() -> None:
    with get_engine().connect() as conn:
        assert conn.scalar(text("SELECT 1")) == 1


def test_connection_uses_demo_database_role_and_schema() -> None:
    with get_engine().connect() as conn:
        row = conn.execute(
            text("SELECT current_database(), current_user, current_schema()")
        ).one()
        assert tuple(row) == ("chat_demo", "chat_demo_app", "public")


@pytest.mark.parametrize("privilege", ["USAGE", "CREATE"])
def test_application_login_has_public_schema_privilege(privilege: str) -> None:
    with get_engine().connect() as conn:
        query = text("SELECT has_schema_privilege(current_user, 'public', :privilege)")
        assert conn.scalar(query, {"privilege": privilege}) is True