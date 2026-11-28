"""Launch the chat prototype or the real signup client."""

import tkinter as tk
from argparse import ArgumentParser, Namespace
from collections.abc import Generator, Sequence
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Literal

from .api_client import ApiClient
from .client_backend import ClientBackend
from .client_frontend import ClientFrontend
from .identity import IdentityService
from .prototype_backend import PrototypeBackend
from .signup_frontend import SignupFrontend, SignupWorker
from .state_store import ClientStateStore


class _Arguments(Namespace):
    mode: Literal["prototype", "real"] = "prototype"
    server_url: str | None = None
    websocket_url: str | None = None
    data_dir: Path | None = None


@contextmanager
def _open_backend(
    server_url: str, websocket_url: str, data_dir: Path
) -> Generator[ClientBackend, None, None]:
    with closing(ClientStateStore(data_dir)) as store, closing(ApiClient(server_url)) as api:
        yield ClientBackend(store, IdentityService(), api, websocket_url)


def _run_real(root: tk.Tk, server_url: str, websocket_url: str, data_dir: Path) -> None:
    worker = SignupWorker(lambda: _open_backend(server_url, websocket_url, data_dir))
    try:
        _ = SignupFrontend(root, worker)
        root.mainloop()
    finally:
        worker.close()
        worker.join()


def main(argv: Sequence[str] | None = None) -> None:
    parser = ArgumentParser(description=__doc__)
    _ = parser.add_argument("--mode", choices=("prototype", "real"), default="prototype")
    _ = parser.add_argument("--server-url", help="HTTP(S) server origin without /api")
    _ = parser.add_argument("--websocket-url", help="Advertised WebSocket address for signup")
    _ = parser.add_argument("--data-dir", type=Path, help="Directory for this client's SQLite database")
    args = parser.parse_args(argv, namespace=_Arguments())
    if args.mode == "prototype":
        root = tk.Tk()
        _ = ClientFrontend(root, PrototypeBackend(root.after))
        root.mainloop()
        return

    if not args.server_url or not args.websocket_url or args.data_dir is None:
        parser.error("--mode real requires --server-url, --websocket-url, and --data-dir")
    _run_real(tk.Tk(), args.server_url, args.websocket_url, args.data_dir)


if __name__ == "__main__":
    main()