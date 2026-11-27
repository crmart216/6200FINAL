import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-ra", "Server/tests"],
        cwd=project_root,
        env={**os.environ, "RUN_POSTGRES_TESTS": "1"},
        check=False,
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())