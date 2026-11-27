import os
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient
from starlette.routing import Match
from starlette.types import Scope

from Server.main import app
from Server.routes.router import router


def test_app_starts_without_server_settings() -> None:
    env = os.environ.copy()
    for name in ("SERVER_DATABASE_URL", "SERVER_DEMO_IDENTITIES"):
        _ = env.pop(name, None)

    code = """
            from fastapi.testclient import TestClient
            from Server.main import app

            with TestClient(app) as client:
                assert client.get("/openapi.json").status_code == 200
            """
    _ = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        check=True,
    )


def test_aggregate_router_uses_api_prefix() -> None:
    assert router.prefix == "/api"


def test_docs_returns_html() -> None:
    with TestClient(app) as client:
        response = client.get("/docs")

    assert response.status_code == 200
    assert response.headers["content-type"].split(";")[0] == "text/html"


def test_openapi_exposes_title_and_paths() -> None:
    with TestClient(app) as client:
        response = client.get("/openapi.json")

    assert response.status_code == 200
    assert response.json()["info"]["title"] == "6200 Group Chat API"
    assert isinstance(response.json()["paths"], dict)


def test_legacy_websocket_stream_is_absent() -> None:
    scope: Scope = {
        "type": "websocket",
        "path": "/api/messages/stream",
        "root_path": "",
        "headers": [],
        "app": app,
    }
    assert all(route.matches(scope)[0] != Match.FULL for route in app.routes)