"""Run the client test suite with the active Python environment's pytest.

test_prototype_backend.py exercises the in-memory chat backend, including
signup, invitations, delayed joins, messaging, and member removal.
test_state_store.py uses pytest's tmp_path to exercise SQLite initialization,
identity persistence, registration retries, rejected writes, and rollback.
test_identity_service.py covers Ed25519 key generation, signup proof encoding
and verification, and signing with a pending identity restored from SQLite.
test_api_client.py checks public signup, authenticated directory requests,
typed responses, and errors using HTTPX MockTransport.
test_client_backend.py checks signup orchestration with SQLite, a real Ed25519
proof, and mocked HTTP, plus directory authentication and self-filtering.
test_signup_frontend.py checks signup and manual directory refresh, including
retry, duplicate clicks, and worker shutdown without a graphical display.

Group coverage includes v1-to-v2 migration, authenticated PUT registration,
retry after a lost response, local founder snapshot restoration, and Tkinter
group-list coordination with the backend worker.

The current suite runs offline and requires neither a display nor a server.
"""

import subprocess
import sys
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-v", "-ra", "Client/tests"],
        cwd=project_root,
        check=False,
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
