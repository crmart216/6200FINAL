from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


def test_initial_revision_is_discoverable() -> None:
    ini = Path(__file__).resolve().parents[1] / "alembic.ini"
    scripts = ScriptDirectory.from_config(Config(str(ini)))
    assert scripts.get_bases() == ["0001_initial_schema"]