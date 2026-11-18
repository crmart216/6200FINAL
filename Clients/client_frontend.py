"""Simple Tkinter group chat. Pass an object/module implementing the six hooks.

UI message contract: {"group_id": str, "sender": str, "text": str}.
This is an adapter contract, not a network message format.
"""
import queue
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from tkinter.scrolledtext import ScrolledText


class ChatFrontend:
    def __init__(self, root, backend):
        self.root = root
        self.backend = backend
        self.groups = {}  # group ID -> display name
        self.history = {}  # group ID -> message dictionaries
        self.active_group = None
        self._events = queue.Queue()
        self._jobs = queue.Queue()
        self._closed = threading.Event()
        self._sending = False
        root.title("Group Chat — Demo" if getattr(backend, "is_demo", False) else "Group Chat")
        root.geometry("900x560")
        root.minsize(650, 400)
        root.protocol("WM_DELETE_WINDOW", self.close)
        self._build()
        threading.Thread(target=self._work, daemon=True).start()
        threading.Thread(target=self._receive, daemon=True).start()
        self._poll_id = root.after(75, self._poll)
        self.refresh_users()

    def _build(self):
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)
        left = ttk.Frame(self.root, padding=10)
        left.grid(row=0, column=0, sticky="ns")
        ttk.Label(left, text="Groups").pack(anchor="w")
        self.group_list = tk.Listbox(left, width=24, exportselection=False)
        self.group_list.pack(fill="both", expand=True, pady=6)
        self.group_list.bind("<<ListboxSelect>>", self._select)
        ttk.Button(left, text="Create group", command=self.create_group).pack(fill="x")

        center = ttk.Frame(self.root, padding=10)
        center.grid(row=0, column=1, sticky="nsew")
        center.columnconfigure(0, weight=1)
        center.rowconfigure(1, weight=1)
        self.title = ttk.Label(center, text="Create a group to start chatting")
        self.title.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        self.chat = ScrolledText(center, wrap="word", state="disabled", width=40)
        self.chat.grid(row=1, column=0, columnspan=2, sticky="nsew")
        self.draft = tk.StringVar()
        self.entry = ttk.Entry(center, textvariable=self.draft, state="disabled")
        self.entry.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        self.entry.bind("<Return>", lambda event: self.send_message())
        self.send_button = ttk.Button(center, text="Send", command=self.send_message, state="disabled")
        self.send_button.grid(row=2, column=1, padx=(8, 0), pady=(8, 0))

        right = ttk.Frame(self.root, padding=10)
        right.grid(row=0, column=2, sticky="ns")
        ttk.Label(right, text="Group members").pack(anchor="w")
        self.members = tk.Listbox(right, width=20, height=10, exportselection=False)
        self.members.pack(fill="both", expand=True, pady=6)
        self.add_button = ttk.Button(right, text="Add user to group", command=self.add_user, state="disabled")
        self.add_button.pack(fill="x")
        ttk.Button(right, text="Refresh members", command=self.refresh_members).pack(fill="x", pady=(4, 10))
        ttk.Label(right, text="All users").pack(anchor="w")
        self.users = tk.Listbox(right, width=20, height=8, exportselection=False)
        self.users.pack(fill="both", expand=True, pady=6)
        ttk.Button(right, text="Refresh users", command=self.refresh_users).pack(fill="x")
        self.status = tk.StringVar(value=getattr(self.backend, "description", "Ready"))
        ttk.Label(self.root, textvariable=self.status, padding=8).grid(row=1, column=0, columnspan=3, sticky="ew")

    def _submit(self, function, done, *args):
        self._jobs.put((function, args, done))

    def _work(self):
        """Backend calls run off the Tk thread, in submission order."""
        while not self._closed.is_set():
            job = self._jobs.get()
            if job is None:
                return
            function, args, done = job
            try:
                self._events.put(("result", (done, function(*args))))
            except Exception as exc:
                self._events.put(("error", (done, str(exc))))

    def _receive(self):
        try:
            for message in self.backend.waitForMessage():
                if self._closed.is_set():
                    return
                self._events.put(("message", message))
            if not self._closed.is_set():
                self._events.put(("stream_error", "Incoming message stream ended."))
        except Exception as exc:
            if not self._closed.is_set():
                self._events.put(("stream_error", str(exc)))

    def _poll(self):
        # Every widget access, including callbacks and errors, stays on Tk's thread.
        for _ in range(100):
            try:
                kind, value = self._events.get_nowait()
            except queue.Empty:
                break
            try:
                if kind == "message":
                    self._incoming(value)
                elif kind == "result":
                    callback, result = value
                    callback(result, None)
                elif kind == "error":
                    callback, error = value
                    callback(None, error)
                else:
                    self.status.set("Receive error: " + value)
            except Exception as exc:
                self.status.set("Could not process update: " + str(exc))
        if not self._closed.is_set():
            self._poll_id = self.root.after(75, self._poll)

    def _error(self, error):
        if error is None:
            return False
        self.status.set("Error: " + error)
        messagebox.showerror("Group chat", error, parent=self.root)
        return True

    def _ensure_group(self, group_id, name=None):
        group_id = str(group_id)
        if group_id not in self.groups:
            self.groups[group_id] = name or group_id
            self.history[group_id] = []
            self.group_list.insert(tk.END, self.groups[group_id])
        return group_id

    def create_group(self):
        name = simpledialog.askstring("Create group", "Group name:", parent=self.root)
        if not name or not name.strip():
            return
        name = name.strip()
        def done(group_id, error):
            if self._error(error):
                return
            if group_id is None:
                self._error("createGroup() must return a group ID.")
                return
            group_id = self._ensure_group(group_id, name)
            index = list(self.groups).index(group_id)
            self.group_list.selection_clear(0, tk.END)
            self.group_list.selection_set(index)
            self._select()
            self.status.set("Created " + name)
        self._submit(self.backend.createGroup, done, name)

    def _select(self, event=None):
        selected = self.group_list.curselection()
        if not selected:
            return
        self.active_group = list(self.groups)[selected[0]]
        self.title.config(text=self.groups[self.active_group])
        self.entry.config(state="normal")
        self.send_button.config(state="disabled" if self._sending else "normal")
        self.add_button.config(state="normal")
        self._render()
        self.refresh_members()

    def _render(self):
        self.chat.config(state="normal")
        self.chat.delete("1.0", tk.END)
        for message in self.history.get(self.active_group, []):
            self.chat.insert(tk.END, f"{message['sender']}: {message['text']}\n")
        self.chat.config(state="disabled")
        self.chat.see(tk.END)

    def _incoming(self, message):
        if not isinstance(message, dict) or not all(key in message for key in ("group_id", "sender", "text")):
            raise ValueError("Expected group_id, sender, and text in incoming message")
        if not isinstance(message["text"], str):
            raise ValueError("Incoming text must be a string")
        group_id = self._ensure_group(message["group_id"], message.get("group_name"))
        self.history[group_id].append(dict(message))
        if group_id == self.active_group:
            self._render()
        else:
            self.status.set("New message in " + self.groups[group_id])

    def send_message(self):
        text = self.draft.get()
        if self.active_group is None or not text.strip() or self._sending:
            return
        group_id = self.active_group
        self._sending = True
        self.send_button.config(state="disabled")
        def done(result, error):
            self._sending = False
            self.send_button.config(state="normal" if self.active_group else "disabled")
            if self._error(error):
                return  # Preserve the draft so the user can retry.
            if self.active_group == group_id and self.draft.get() == text:
                self.draft.set("")
            self.status.set("Sent to " + self.groups[group_id])
        # Sent messages are displayed by waitForMessage(), avoiding duplicate echoes.
        self._submit(self.backend.sendMessage, done, text, group_id)

    @staticmethod
    def _fill(widget, users):
        widget.delete(0, tk.END)
        for user in users:
            widget.insert(tk.END, user["name"] if isinstance(user, dict) else str(user))

    def refresh_users(self):
        def done(users, error):
            if not self._error(error):
                self._fill(self.users, users)
        self._submit(self.backend.getAllUsers, done)

    def refresh_members(self):
        group_id = self.active_group
        if group_id is None:
            return
        self.members.delete(0, tk.END)
        def done(members, error):
            if group_id == self.active_group and not self._error(error):
                self._fill(self.members, members)
        self._submit(self.backend.getGroupChatMembers, done, group_id)

    def add_user(self):
        group_id = self.active_group
        if group_id is None:
            return
        def done(result, error):
            if not self._error(error):
                self.status.set("Membership updated for " + self.groups[group_id])
                if group_id == self.active_group:
                    self.refresh_members()
        self._submit(self.backend.addUserToGroup, done, group_id)

    def close(self):
        self._closed.set()
        self.root.after_cancel(self._poll_id)
        self._jobs.put(None)
        # An optional close hook should unblock waitForMessage(). Never block Tk.
        close = getattr(self.backend, "close", None)
        if close:
            threading.Thread(target=close, daemon=True).start()
        self.root.destroy()


def main(backend=None):
    if backend is None:
        if __package__:
            from .client_demo import DemoBackend
        else:
            from client_demo import DemoBackend
        backend = DemoBackend()
    root = tk.Tk()
    ChatFrontend(root, backend)
    root.mainloop()


if __name__ == "__main__":
    main()
