import tkinter as tk

from .client_frontend import ClientFrontend
from .prototype_backend import PrototypeBackend


def main() -> None:
    root = tk.Tk()
    _ = ClientFrontend(root, PrototypeBackend(root.after))
    root.mainloop()


if __name__ == "__main__":
    main()
