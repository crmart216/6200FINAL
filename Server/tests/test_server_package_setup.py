from importlib import import_module
from pathlib import Path


def test_server_packages_resolve_to_expected_directories() -> None:
    root = Path(__file__).resolve().parents[2]
    for name in ("Server", "Server.models", "Server.schemas", "Server.routes", "Server.services"):
        filename = import_module(name).__file__
        assert filename is not None
        assert Path(filename).resolve() == root.joinpath(*name.split("."), "__init__.py")


def test_server_runtime_dependencies_import() -> None:
    for name in (
        "fastapi", "uvicorn", "pydantic", "pydantic_settings",
        "sqlalchemy", "alembic", "psycopg", "cryptography",
    ):
        assert import_module(name).__name__ == name