"""Tkinter signup and directory views with a single backend worker."""

import sqlite3
import tkinter as tk
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
from enum import Enum, auto
from queue import Empty, Queue
from threading import Event, Thread
from tkinter import ttk
from typing import Literal, Protocol

from .api_client import ApiHttpError, ApiMalformedResponseError, ApiTransportError
from .client_backend import GroupStateMismatch
from .models.group_summary import GroupSummary
from .models.user_profile import UserProfile


class SignupBackend(Protocol):
    def get_registered_profile(self) -> UserProfile | None: ...

    def register(self, display_name: str) -> UserProfile: ...

    def list_users(self) -> list[UserProfile]: ...

    def list_groups(self) -> list[GroupSummary]: ...

    def list_pending_groups(self) -> list[GroupSummary]: ...

    def create_group(self, name: str) -> GroupSummary: ...

    def retry_group_creation(self, group_id: str) -> GroupSummary: ...


@dataclass(frozen=True, slots=True)
class GroupLists:
    confirmed: tuple[GroupSummary, ...] = ()
    pending: tuple[GroupSummary, ...] = ()


@dataclass(frozen=True, slots=True)
class GroupRequest:
    value: str
    retry: bool = False


@dataclass(frozen=True, slots=True)
class GroupResult:
    lists: GroupLists | None
    status: str = ""


@dataclass(frozen=True, slots=True)
class SignupResult:
    profile: UserProfile | None = None
    error: str | None = None
    groups: GroupResult | None = None


class _Command(Enum):
    REFRESH_DIRECTORY = auto()


@dataclass(frozen=True, slots=True)
class DirectoryResult:
    users: tuple[UserProfile, ...] = ()
    error: str | None = None


def _signup_error(error: Exception) -> str:
    match error:
        case ApiTransportError(timed_out=True):
            return "Signup timed out. Try again."
        case ApiTransportError():
            return "Could not connect to the signup server."
        case ApiHttpError(status_code=404):
            return "Public signup is unavailable."
        case ApiHttpError(status_code=409):
            return "This account already exists on the server."
        case ApiHttpError(status_code=422):
            return "The server rejected signup. Check the name and try again."
        case ApiHttpError(status_code=429):
            return "Too many signup attempts. Wait before trying again."
        case ApiHttpError(status_code=503):
            return "Signup is temporarily unavailable. Try again later."
        case ApiMalformedResponseError():
            return "The server returned an invalid signup response."
        case sqlite3.Error():
            return "Could not save this account on this device."
        case ValueError():
            return "Check the display name. To resume signup, use the same name as before."
        case _:
            return "Could not complete signup."


def _directory_error(error: Exception) -> str:
    match error:
        case ApiTransportError():
            return "Could not reach the server. Try Refresh again."
        case ApiHttpError(status_code=401):
            return "The server rejected this client's saved credentials."
        case ApiHttpError(status_code=429):
            return "Too many directory requests. Wait before refreshing again."
        case _:
            return "Could not refresh available users. Try again."


def _group_error(error: Exception) -> str:
    match error:
        case GroupStateMismatch():
            return str(error)
        case ApiTransportError():
            return "Could not reach the server. Retry the pending group."
        case ApiHttpError(status_code=409):
            return "The server reported a group conflict."
        case ApiHttpError(status_code=401):
            return "The server rejected this client's saved credentials."
        case ApiMalformedResponseError():
            return "The server returned an invalid group registration."
        case sqlite3.Error():
            return "Could not save the group on this device."
        case ValueError():
            return "Enter a nonblank group name without NUL, or select a pending group."
        case _:
            return "Could not register the group. Retry it if it is pending."


class SignupWorker:
    """Open, use, and close a backend on one thread. Results contain only UI data."""

    def __init__(self, open_backend: Callable[[], AbstractContextManager[SignupBackend]]) -> None:
        self.results: Queue[SignupResult | DirectoryResult | GroupResult] = Queue()
        self._requests: Queue[str | _Command | GroupRequest | None] = Queue()
        self._stopping: Event = Event()
        self._thread: Thread = Thread(target=self._run, args=(open_backend,), name="signup", daemon=False)
        self._thread.start()

    def submit(self, display_name: str) -> None:
        self._requests.put(display_name)

    def refresh_directory(self) -> None:
        self._requests.put(_Command.REFRESH_DIRECTORY)

    def submit_group(self, request: GroupRequest) -> None:
        self._requests.put(request)

    def close(self) -> None:
        if not self._stopping.is_set():
            self._stopping.set()
            self._requests.put(None)

    def join(self) -> None:
        self._thread.join()

    def _run(self, open_backend: Callable[[], AbstractContextManager[SignupBackend]]) -> None:
        try:
            with open_backend() as backend:
                if self._stopping.is_set():
                    return
                profile = backend.get_registered_profile()
                groups = self._load_groups(backend) if profile is not None else None
                self.results.put(SignupResult(profile=profile, groups=groups))
                while (request := self._requests.get()) is not None:
                    if self._stopping.is_set():
                        return
                    if isinstance(request, str):
                        try:
                            profile = backend.register(request)
                            self.results.put(SignupResult(profile=profile, groups=self._load_groups(backend)))
                        except Exception as error:
                            self.results.put(SignupResult(error=_signup_error(error)))
                    elif isinstance(request, GroupRequest):
                        self.results.put(self._register_group(backend, request))
                    else:
                        try:
                            self.results.put(DirectoryResult(users=tuple(backend.list_users())))
                        except Exception as error:
                            self.results.put(DirectoryResult(error=_directory_error(error)))
        except Exception:
            self.results.put(SignupResult(error="Could not open local account data. Check the client settings."))


    @staticmethod
    def _load_groups(backend: SignupBackend, status: str = "") -> GroupResult:
        try:
            groups = GroupLists(tuple(backend.list_groups()), tuple(backend.list_pending_groups()))
        except Exception:
            return GroupResult(None, f"{status} Could not load local groups.".strip())
        return GroupResult(groups, status)

    def _register_group(self, backend: SignupBackend, request: GroupRequest) -> GroupResult:
        try:
            if request.retry:
                _ = backend.retry_group_creation(request.value)
            else:
                _ = backend.create_group(request.value)
        except Exception as error:
            return self._load_groups(backend, _group_error(error))
        return self._load_groups(backend, "Group registered.")


@dataclass(frozen=True, slots=True)
class SignupState:
    status: str = ""
    show_form: bool = False
    can_submit: bool = False
    profile: UserProfile | None = None
    users: tuple[UserProfile, ...] = ()
    directory_status: str = ""
    refreshing: bool = False
    groups: GroupLists = GroupLists()
    group_status: str = ""
    group_busy: bool = False


class SignupController:
    """Coordinate submission and results on the UI thread."""

    def __init__(self, worker: SignupWorker, render: Callable[[SignupState], None]) -> None:
        self._worker: SignupWorker = worker
        self._render: Callable[[SignupState], None] = render
        self._state: SignupState = SignupState(status="Checking local account…")
        self._closed: bool = False
        self._render(self._state)

    def submit(self, display_name: str) -> None:
        if self._closed or not self._state.can_submit:
            return
        self._show(SignupState(status="Creating account…", show_form=True))
        self._worker.submit(display_name)

    def refresh_directory(self) -> None:
        if self._closed or self._state.profile is None or self._state.refreshing:
            return
        self._show(replace(self._state, directory_status="Loading available users…", refreshing=True))
        self._worker.refresh_directory()

    def create_group(self, name: str) -> None:
        self._submit_group(GroupRequest(name))

    def retry_group_creation(self, group_id: str) -> None:
        if any(group.id == group_id for group in self._state.groups.pending):
            self._submit_group(GroupRequest(group_id, retry=True))

    def _submit_group(self, request: GroupRequest) -> None:
        if self._closed or self._state.profile is None or self._state.group_busy:
            return
        self._show(replace(self._state, group_status="Registering group…", group_busy=True))
        self._worker.submit_group(request)

    def poll(self) -> None:
        if self._closed:
            return
        try:
            result = self._worker.results.get_nowait()
        except Empty:
            return
        if isinstance(result, DirectoryResult):
            if result.error is not None:
                self._show(replace(self._state, directory_status=result.error, refreshing=False))
            else:
                status = "" if result.users else "No other users are registered."
                self._show(replace(self._state, users=result.users, directory_status=status, refreshing=False))
        elif isinstance(result, GroupResult):
            self._show(replace(
                self._state, groups=result.lists or self._state.groups,
                group_status=result.status, group_busy=False,
            ))
        elif result.profile is not None:
            groups = result.groups or GroupResult(None)
            self._show(SignupState(
                profile=result.profile, directory_status="Click Refresh to load available users.",
                groups=groups.lists or GroupLists(), group_status=groups.status,
            ))
        elif result.error is None or self._state.show_form:
            self._show(SignupState(status=result.error or "", show_form=True, can_submit=True))
        else:
            self._show(SignupState(status=result.error))

    def close(self) -> None:
        self._closed = True
        self._worker.close()

    def _show(self, state: SignupState) -> None:
        self._state = state
        self._render(state)


class SignupFrontend:
    """Show signup or the restored account on the Tkinter thread."""

    def __init__(self, root: tk.Tk, worker: SignupWorker) -> None:
        self._root: tk.Tk = root
        root.title("6200 Group Chat")
        root.geometry("700x540")
        root.minsize(560, 460)
        ttk.Style(root).configure("Title.TLabel", font=("TkDefaultFont", 17, "bold"))

        card = ttk.Frame(root, padding=24)
        card.place(relx=0.5, rely=0.45, anchor="center", relwidth=0.88)
        ttk.Label(card, text="6200 Group Chat", style="Title.TLabel").pack(anchor="w")
        self._form: ttk.Frame = ttk.Frame(card)
        ttk.Label(self._form, text="Display name").pack(anchor="w", pady=(22, 4))
        self._name: ttk.Entry = ttk.Entry(self._form, width=36)
        self._name.pack(fill="x")
        self._button: ttk.Button = ttk.Button(self._form, text="Register", command=self._submit)
        self._button.pack(anchor="w", pady=(10, 4))
        _ = self._name.bind("<Return>", lambda _event: self._submit())
        self._status: tk.StringVar = tk.StringVar(master=root)
        self._status_label: ttk.Label = ttk.Label(card, textvariable=self._status, wraplength=370)
        self._status_label.pack(anchor="w", pady=(10, 0))

        self._tabs: ttk.Notebook = ttk.Notebook(card)
        groups = ttk.Frame(self._tabs, padding=8)
        self._directory: ttk.Frame = ttk.Frame(self._tabs, padding=8)
        self._tabs.add(groups, text="Your groups")
        self._tabs.add(self._directory, text="Available users")
        ttk.Label(groups, text="Group name").pack(anchor="w")
        self._group_name: ttk.Entry = ttk.Entry(groups)
        self._group_name.pack(fill="x")
        self._create_button: ttk.Button = ttk.Button(groups, text="Create group", command=self._create_group)
        self._create_button.pack(anchor="w", pady=(4, 6))
        self._confirmed: tk.Listbox = tk.Listbox(groups, height=4, exportselection=False)
        self._confirmed.pack(fill="x")
        ttk.Label(groups, text="Pending registration").pack(anchor="w", pady=(6, 0))
        self._pending: ttk.Treeview = ttk.Treeview(
            groups, columns=("name", "id"), show="headings", height=3, selectmode="browse"
        )
        self._pending.heading("name", text="Group name")
        self._pending.heading("id", text="Group ID")
        self._pending.pack(fill="x")
        self._retry_button: ttk.Button = ttk.Button(groups, text="Retry", command=self._retry_group)
        self._retry_button.pack(anchor="w", pady=(4, 0))
        _ = self._pending.bind("<<TreeviewSelect>>", lambda _event: self._update_retry())
        self._group_status: tk.StringVar = tk.StringVar(master=root)
        ttk.Label(groups, textvariable=self._group_status, wraplength=430).pack(anchor="w")
        self._shown_groups: GroupLists = GroupLists()
        self._group_busy: bool = False
        ttk.Label(self._directory, text="Available users").pack(anchor="w")
        table = ttk.Frame(self._directory)
        table.pack(fill="x", pady=(4, 0))
        self._users: ttk.Treeview = ttk.Treeview(table, columns=("name", "id"), show="headings", height=5)
        self._users.heading("name", text="Display name")
        self._users.heading("id", text="User ID")
        _ = self._users.column("name", width=145)
        _ = self._users.column("id", width=280)
        def scroll(action: str, amount: str, units: Literal["units", "pages"] = "units") -> None:
            if action == "moveto":
                self._users.yview_moveto(float(amount))
            else:
                self._users.yview_scroll(int(amount), units)

        scrollbar = ttk.Scrollbar(table, orient="vertical", command=scroll)
        _ = self._users.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self._users.pack(side="left", fill="x", expand=True)
        self._refresh_button: ttk.Button = ttk.Button(self._directory, text="Refresh", command=self._refresh)
        self._refresh_button.pack(anchor="w", pady=(6, 0))
        self._directory_status: tk.StringVar = tk.StringVar(master=root)
        ttk.Label(self._directory, textvariable=self._directory_status, wraplength=370).pack(anchor="w")
        self._rendered_users: tuple[UserProfile, ...] = ()

        self._controller: SignupController = SignupController(worker, self._render)
        self._poll_id: str = root.after(50, self._poll)
        _ = root.protocol("WM_DELETE_WINDOW", self.close)

    def _submit(self) -> None:
        self._controller.submit(self._name.get())

    def _refresh(self) -> None:
        self._controller.refresh_directory()

    def _create_group(self) -> None:
        self._controller.create_group(self._group_name.get())

    def _retry_group(self) -> None:
        selection = self._pending.selection()
        if selection:
            self._controller.retry_group_creation(selection[0])

    def _update_retry(self) -> None:
        enabled = bool(self._pending.selection()) and not self._group_busy
        _ = self._retry_button.configure(state="normal" if enabled else "disabled")

    def _poll(self) -> None:
        self._controller.poll()
        self._poll_id = self._root.after(50, self._poll)

    def _render(self, state: SignupState) -> None:
        status = state.status if state.profile is None else f"Signed in as {state.profile.display_name}"
        self._status.set(status)
        if not state.show_form:
            self._form.pack_forget()
            if state.profile is not None:
                self._tabs.pack(fill="x", pady=(12, 0))
                self._render_groups(state)
                self._render_directory(state)
            return
        was_hidden = not self._form.winfo_manager()
        self._form.pack(fill="x", before=self._status_label)
        widget_state = "normal" if state.can_submit else "disabled"
        _ = self._name.configure(state=widget_state)
        _ = self._button.configure(state=widget_state)
        if was_hidden:
            self._name.focus_set()

    def _render_groups(self, state: SignupState) -> None:
        self._group_status.set(state.group_status)
        self._group_busy = state.group_busy
        _ = self._create_button.configure(state="disabled" if state.group_busy else "normal")
        if state.groups != self._shown_groups:
            self._confirmed.delete(0, "end")
            for group in state.groups.confirmed:
                self._confirmed.insert("end", group.name)
            self._pending.delete(*self._pending.get_children())
            for group in state.groups.pending:
                _ = self._pending.insert("", "end", iid=group.id, values=(group.name, group.id))
            self._shown_groups = state.groups
        self._update_retry()

    def _render_directory(self, state: SignupState) -> None:
        self._directory_status.set(state.directory_status)
        _ = self._refresh_button.configure(state="disabled" if state.refreshing else "normal")
        if state.users == self._rendered_users:
            return
        self._users.delete(*self._users.get_children())
        for user in state.users:
            _ = self._users.insert("", "end", values=(user.display_name, user.id))
        self._rendered_users = state.users

    def close(self) -> None:
        self._controller.close()
        self._root.after_cancel(self._poll_id)
        self._root.destroy()
