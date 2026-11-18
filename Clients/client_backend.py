from queue import Queue
from threading import Lock, Thread

from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect
from websockets.sync.server import serve


class SocketService:
    """Send text to a peer and listen for text on local IPv4 interfaces.

    ip is the destination host, not the local bind address. Call listen()
    once to start receiving; read strings from messages with Queue.get().
    Call listen() and stop() from the same controlling thread.
    """

    def __init__(self, ip, port=5555):
        self.ip = ip
        self.port = port
        self.messages = Queue()
        self._server = None
        self._thread = None
        self._connections = set()
        self._lock = Lock()
        self._stopping = False

    def sendMessage(self, message):
        """Send one text message to ip:port. Connection errors propagate.

        This opens a connection per send; no application acknowledgment,
        message format, encryption, or automatic retry is added.
        """
        if not isinstance(message, str):
            raise TypeError("message must be a string")
        host = f"[{self.ip}]" if ":" in self.ip else self.ip
        with connect(
            f"ws://{host}:{self.port}", proxy=None,
            open_timeout=5, close_timeout=5,
        ) as websocket:
            websocket.send(message)

    def listen(self):
        """Start a background listener on 0.0.0.0:port and return immediately.

        Repeated calls while running do nothing. Bind errors propagate.
        Incoming text is queued unchanged, up to 1 MiB per message.
        """
        if self._server is not None:
            return
        self._stopping = False
        self._server = serve(
            self._receive, "0.0.0.0", self.port,
            max_size=1024 * 1024, close_timeout=5,
        )
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def _receive(self, websocket):
        with self._lock:
            stopping = self._stopping
            if not stopping:
                self._connections.add(websocket)
        if stopping:
            websocket.close()
            return
        try:
            for message in websocket:
                if not isinstance(message, str):
                    websocket.close(code=1003, reason="Text messages only")
                    return
                self.messages.put(message)
        except ConnectionClosed:
            pass
        finally:
            with self._lock:
                self._connections.discard(websocket)

    def stop(self):
        """Stop listening and close active incoming connections."""
        if self._server is None:
            return
        with self._lock:
            self._stopping = True
            connections = list(self._connections)
        self._server.shutdown()
        self._thread.join()
        for websocket in connections:
            websocket.close(code=1001, reason="Listener stopped")
        self._server = None
        self._thread = None


class Client:
    def __init__(self):
        self.users = ["You", "Alice", "Bob", "Charlie"]
        self.groups = {}
        self.messages = Queue()

    def createGroup(self, name):
        group_id = str(uuid4())
        self.groups[group_id] = {"name": name, "members": ["You"]}
        return group_id

    def sendMessage(self, text, group_id):
        group = self.groups[group_id]
        self.messages.put({"group_id": group_id, "group_name": group["name"],"sender": "You", "text": text})

    def getAllUsers(self):
        return list(self.users)

    def getGroupChatMembers(self, groupId):
        return list(self.groups[groupId]["members"])

    def addUserToGroup(self, groupId):
        members = self.groups[groupId]["members"]
        for user in self.users:
            if user not in members:
                members.append(user)
                return
        raise ValueError("All sample users are already in this group.")

    def waitForMessage(self):
        while True:
            message = self.messages.get()
            if message is None:
                return
            yield message

    def close(self):
        self.messages.put(None)


