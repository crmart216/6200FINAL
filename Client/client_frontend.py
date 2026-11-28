"""Tkinter views for the injected client translation layer."""

from __future__ import annotations

import tkinter as tk
from collections import defaultdict
from collections.abc import Callable, Iterable
from queue import Empty
from tkinter import messagebox, simpledialog, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Literal, ParamSpec, TypeVar

from .prototype_backend import Group, Invitation, Message, PrototypeBackend, User

P = ParamSpec("P")
T = TypeVar("T")


class ClientFrontend:
    def __init__(self, root: tk.Tk, backend: PrototypeBackend) -> None:
        self.root: tk.Tk = root
        self.backend: PrototypeBackend = backend
        self.user: User | None = backend.load_session()
        self.active_group: str | None = None
        self.groups: dict[str, Group] = {}
        self.invitations: dict[str, Invitation] = {}
        self.members: dict[str, User] = {}
        self.messages: defaultdict[str, dict[str, Message]] = defaultdict(dict)
        self.drafts: dict[str, str] = {}
        self.status: tk.StringVar = tk.StringVar(master=root)
        self.draft: tk.StringVar = tk.StringVar(master=root)
        root.title("6200 Group Chat")
        root.geometry("1100x640")
        root.minsize(920, 500)
        ttk.Style(root).configure("Title.TLabel", font=("TkDefaultFont", 17, "bold"))
        self.page: ttk.Frame = ttk.Frame(root, padding=18)
        self.page.pack(fill="both", expand=True)
        self.signup: ttk.Frame = ttk.Frame(self.page, padding=24)
        ttk.Label(self.signup, text="6200 Group Chat", style="Title.TLabel").pack(anchor="w")
        ttk.Label(self.signup, text="Display name").pack(anchor="w", pady=(22, 4))
        self.name: ttk.Entry = ttk.Entry(self.signup, width=36)
        self.name.pack(fill="x")
        _ = self.name.bind("<Return>", lambda _event: self._register())
        ttk.Button(self.signup, text="Register", command=self._register).pack(anchor="w", pady=(10, 4))
        ttk.Label(self.signup, textvariable=self.status).pack(anchor="w")

        self.chat: ttk.Frame = ttk.Frame(self.page)
        header = ttk.Frame(self.chat)
        header.pack(fill="x", pady=(0, 16))
        ttk.Label(header, text="6200 Group Chat", style="Title.TLabel").pack(side="left")
        self.signin_label: ttk.Label = ttk.Label(header)
        self.signin_label.pack(side="right")

        body = ttk.Frame(self.chat)
        body.pack(fill="both", expand=True)
        _ = body.columnconfigure(1, weight=1)
        _ = body.rowconfigure(0, weight=1)
        sidebar = ttk.Frame(body)
        sidebar.grid(row=0, column=0, sticky="ns", padx=(0, 14))
        self.conversations: ttk.Treeview = self._table(sidebar, ("Conversations", 160))
        _ = self.conversations.bind("<<TreeviewSelect>>", self._select_group)
        ttk.Button(sidebar, text="Create group", command=self._create_group).pack(fill="x")

        chat = ttk.Frame(body)
        chat.grid(row=0, column=1, sticky="nsew")
        self.heading: ttk.Label = ttk.Label(chat, style="Title.TLabel")
        self.heading.pack(anchor="w", pady=(0, 8))
        self.transcript: ScrolledText = ScrolledText(chat, wrap="word", state="disabled", height=12, width=30, padx=12, pady=10)
        _ = self.transcript.tag_configure("sender", font=("TkDefaultFont", 10, "bold"))
        self.transcript.pack(fill="both", expand=True)
        composer = ttk.Frame(chat)
        composer.pack(fill="x", pady=(8, 0))
        self.entry: ttk.Entry = ttk.Entry(composer, textvariable=self.draft)
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        _ = self.entry.bind("<Return>", lambda _event: self._send())
        self.send_button: ttk.Button = ttk.Button(composer, text="Send", command=self._send)
        self.send_button.pack(side="right")

        tabs = ttk.Notebook(body)
        tabs.grid(row=0, column=2, sticky="ns", padx=(14, 0))
        directory, inbox, roster = [ttk.Frame(tabs, padding=8) for _ in range(3)]
        for frame, label in ((directory, "Directory"), (inbox, "Invitations"), (roster, "Members")):
            tabs.add(frame, text=label)

        self.directory: ttk.Treeview = self._table(directory, ("Display name", 110), ("User ID", 105))
        ttk.Button(directory, text="Refresh directory", command=self._refresh_directory).pack(fill="x")
        self.invite_button: ttk.Button = ttk.Button(directory, text="Invite selected user", command=self._invite)
        self.invite_button.pack(fill="x", pady=(4, 0))
        _ = self.directory.bind("<<TreeviewSelect>>", self._update_actions)

        self.inbox: ttk.Treeview = self._table(inbox, ("Group", 110), ("From / To", 105), ("Status", 80))
        self.accept_button: ttk.Button = ttk.Button(inbox, text="Accept", command=lambda: self._respond("accept"))
        self.decline_button: ttk.Button = ttk.Button(inbox, text="Decline", command=lambda: self._respond("decline"))
        self.accept_button.pack(side="left")
        self.decline_button.pack(side="left", padx=(4, 0))
        _ = self.inbox.bind("<<TreeviewSelect>>", self._update_actions)

        self.roster: ttk.Treeview = self._table(roster, ("Display name", 120), ("Role", 90))
        self.remove_button: ttk.Button = ttk.Button(roster, text="Remove selected member", command=self._remove)
        self.remove_button.pack(fill="x")
        _ = self.roster.bind("<<TreeviewSelect>>", self._update_actions)

        demo = ttk.Frame(self.chat)
        demo.pack(fill="x", pady=(10, 0))
        ttk.Label(demo, text="Demo controls").pack(side="left", padx=(0, 8))
        self.receive_button: ttk.Button = ttk.Button(demo, text="Simulate incoming message", command=self._simulate_incoming)
        self.receive_button.pack(side="left", padx=(0, 6))
        ttk.Button(demo, text="Fail next send", command=self._simulate_failure).pack(side="left")
        ttk.Label(self.chat, textvariable=self.status, wraplength=850).pack(fill="x", pady=(8, 0))

        if self.user is None:
            self.signup.place(relx=0.5, rely=0.45, anchor="center")
            self.name.focus_set()
        else:
            self._show_chat()

    def _register(self) -> None:
        name = self.name.get().strip()
        if not name:
            self.status.set("Enter a display name.")
            return
        user = self._call(self.backend.register, name)
        if user is not None:
            self.user = user
            self.status.set("")
            self._show_chat()

    def _show_chat(self) -> None:
        assert self.user is not None
        self.signup.destroy()
        _ = self.signin_label.configure(text=f"Signed in as {self.user.display_name}")
        self.chat.pack(fill="both", expand=True)
        self._refresh_directory()
        self._refresh_invitations()
        self._refresh_groups()
        _ = self.root.after(50, self._poll_events)

    @staticmethod
    def _table(parent: ttk.Frame, *columns: tuple[str, int]) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, pady=(0, 8))
        keys = list(range(len(columns)))
        tree = ttk.Treeview(frame, columns=keys, show="headings", selectmode="browse")

        def scroll(action: str, amount: str, units: Literal["units", "pages"] = "units") -> None:
            if action == "moveto":
                tree.yview_moveto(float(amount))
            else:
                tree.yview_scroll(int(amount), units)

        scrollbar = ttk.Scrollbar(frame, command=scroll)
        _ = tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        for key, (label, width) in zip(keys, columns):
            tree.heading(key, text=label)
            _ = tree.column(key, width=width, stretch=False)
        return tree

    @staticmethod
    def _selection(tree: ttk.Treeview) -> str | None:
        return next(iter(tree.selection()), None)

    def _fill(self, tree: ttk.Treeview, rows: Iterable[tuple[str, tuple[str, ...]]]) -> None:
        selected = self._selection(tree)
        tree.delete(*tree.get_children())
        for key, values in rows:
            _ = tree.insert("", "end", iid=key, values=values)
        if selected is not None and tree.exists(selected):
            tree.selection_set(selected)

    def _call(self, action: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T | None:
        try:
            return action(*args, **kwargs)
        except ValueError as error:
            self.status.set(str(error))
            return None

    def _refresh_directory(self) -> None:
        users = self.backend.list_users()
        self._fill(self.directory, ((user.id, (user.display_name, user.id)) for user in users))

    def _refresh_groups(self, select: str | None = None) -> None:
        self.groups = {group.id: group for group in self.backend.list_groups()}
        self._fill(self.conversations, ((group.id, (group.name,)) for group in self.groups.values()))
        selected = select or self._selection(self.conversations) or next(iter(self.groups), None)
        if selected is not None:
            self.conversations.selection_set(selected)
            self.conversations.see(selected)
        self._select_group()

    def _select_group(self, _event: tk.Event[ttk.Treeview] | None = None) -> None:
        selected = self._selection(self.conversations)
        if self.active_group != selected:
            if self.active_group is not None:
                self.drafts[self.active_group] = self.draft.get()
            self.active_group = selected
            self.draft.set(self.drafts.get(selected, "") if selected is not None else "")
        group = self.groups.get(selected) if selected is not None else None
        _ = self.heading.configure(text=group.name if group else "Select a conversation")
        self._render_messages()
        self._refresh_members()

    def _refresh_invitations(self) -> None:
        assert self.user is not None
        self.invitations = {item.id: item for item in self.backend.list_invitations()}
        rows: list[tuple[str, tuple[str, ...]]] = []
        for item in self.invitations.values():
            other = item.inviter if item.invitee.id == self.user.id else item.invitee
            status = "Joining…" if item.status == "joining" else item.status.capitalize()
            rows.append((item.id, (item.group.name, other.display_name, status)))
        self._fill(self.inbox, rows)
        self._update_actions()

    def _refresh_members(self) -> None:
        group_id = self.active_group
        group = self.groups.get(group_id) if group_id is not None else None
        members = self.backend.list_group_members(group.id) if group is not None else []
        founder_id = group.founder_id if group is not None else None
        self.members = {member.id: member for member in members}
        self._fill(self.roster, (
            (member.id, (member.display_name, "Founder" if member.id == founder_id else "Member"))
            for member in members
        ))
        self._update_actions()

    def _update_actions(self, _event: tk.Event[ttk.Treeview] | None = None) -> None:
        assert self.user is not None
        group_id = self.active_group
        group = self.groups.get(group_id) if group_id is not None else None
        owns_group = group is not None and group.founder_id == self.user.id
        peer_id = self._selection(self.directory)
        member_id = self._selection(self.roster)
        invitation_id = self._selection(self.inbox)
        invitation = self.invitations.get(invitation_id) if invitation_id is not None else None
        can_respond = invitation and invitation.invitee.id == self.user.id and invitation.status == "pending"
        for widget, enabled in (
            (self.entry, group),
            (self.send_button, group),
            (self.receive_button, len(self.members) > 1),
            (self.invite_button, owns_group and peer_id and peer_id not in self.members),
            (self.remove_button, owns_group and member_id and member_id != self.user.id),
            (self.accept_button, can_respond),
            (self.decline_button, can_respond),
        ):
            _ = widget.configure(state="normal" if enabled else "disabled")

    def _create_group(self) -> None:
        name = simpledialog.askstring("Create group", "Group name", parent=self.root)
        if name is None:
            return
        if not name.strip():
            self.status.set("Enter a group name.")
            return
        group = self._call(self.backend.create_group, name)
        if group is not None:
            self._refresh_groups(select=group.id)
            self.status.set(f"Created {group.name}.")

    def _invite(self) -> None:
        group_id = self.active_group
        user_id = self._selection(self.directory)
        if group_id is None or user_id is None:
            return
        item = self._call(self.backend.invite_user, group_id, user_id)
        if item is not None:
            self._refresh_invitations()
            self.status.set(f"Invitation to {item.invitee.display_name} ({item.invitee.id}) is pending.")

    def _respond(self, decision: str) -> None:
        invitation_id = self._selection(self.inbox)
        if invitation_id is None:
            return
        item = self._call(self.backend.respond_to_invitation, invitation_id, decision)
        if item is not None:
            self._refresh_invitations()
            self.status.set(f"Joining {item.group.name}…" if item.status == "joining" else "Invitation declined.")

    def _remove(self) -> None:
        group_id = self.active_group
        member_id = self._selection(self.roster)
        if group_id is None or member_id is None:
            return
        member = self.members.get(member_id)
        if member and messagebox.askyesno(
            "Remove member", f"Remove {member.display_name} ({member.id}) from this group?", parent=self.root
        ):
            self._call(self.backend.remove_member, group_id, member.id)

    def _send(self) -> None:
        if self.active_group is None:
            return
        if not self.draft.get().strip():
            self.status.set("Write a message first.")
            return
        message = self._call(self.backend.send_message, self.active_group, self.draft.get())
        if message is not None:
            self._record_message(message)
            self.draft.set("")
            self.status.set("Message sent.")

    def _simulate_failure(self) -> None:
        self.backend.simulate_send_failure()
        self.status.set("The next send will fail once.")

    def _simulate_incoming(self) -> None:
        if self.active_group is not None:
            self._call(self.backend.simulate_incoming, self.active_group)

    def _record_message(self, message: Message) -> None:
        self.messages[message.group_id][message.id] = message
        if message.group_id == self.active_group:
            self._render_messages()
        else:
            self.status.set(f"New message in {self.groups[message.group_id].name}.")

    def _render_messages(self) -> None:
        assert self.user is not None
        _ = self.transcript.configure(state="normal")
        self.transcript.delete("1.0", "end")
        group_id = self.active_group
        messages = self.messages.get(group_id, {}) if group_id is not None else {}
        for message in messages.values():
            author = "You" if message.sender.id == self.user.id else message.sender.display_name
            self.transcript.insert("end", f"{author}\n", "sender")
            self.transcript.insert("end", f"{message.text}\n\n")
        _ = self.transcript.configure(state="disabled")
        self.transcript.see("end")

    def _poll_events(self) -> None:
        while True:
            try:
                event = self.backend.events.get_nowait()
            except Empty:
                break
            if event.kind == "group_joined":
                self._refresh_groups(select=event.group_id)
                self._refresh_invitations()
                self.status.set(f"Joined {self.groups[event.group_id].name}.")
            elif event.kind == "message_received" and event.message is not None:
                self._record_message(event.message)
            elif event.kind == "group_members_updated":
                if event.group_id == self.active_group:
                    self._refresh_members()
                self.status.set(f"Member roster updated for {self.groups[event.group_id].name}.")
        _ = self.root.after(50, self._poll_events)
