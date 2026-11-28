from collections.abc import Generator
from contextlib import contextmanager
from queue import Queue
from threading import get_ident
from time import monotonic, sleep

import pytest

from Client.api_client import ApiHttpError, ApiTransportError
from Client.models.user_profile import UserProfile
from Client.signup_frontend import SignupController, SignupState, SignupWorker

_PROFILE = UserProfile("user-1", "Ryan Martin")
_FIRST_PEER = UserProfile("user-2", "Ryan Martin")
_NEXT_PEER = UserProfile("user-3", "Alice Chen")
_DIRECTORY_PROMPT = "Click Refresh to load available users."


class FakeBackend:
    def __init__(self, profile: UserProfile | None) -> None:
        self.profile: UserProfile | None = profile
        self.requests: Queue[str] = Queue()
        self.results: Queue[UserProfile | Exception] = Queue()
        self.refreshes: Queue[None] = Queue()
        self.directory_results: Queue[list[UserProfile] | Exception] = Queue()
        self.lifecycle: list[tuple[str, int]] = []

    @contextmanager
    def open(self) -> Generator["FakeBackend", None, None]:
        self.lifecycle.append(("open", get_ident()))
        try:
            yield self
        finally:
            self.lifecycle.append(("close", get_ident()))

    def get_registered_profile(self) -> UserProfile | None:
        self.lifecycle.append(("restore", get_ident()))
        return self.profile

    def register(self, display_name: str) -> UserProfile:
        self.lifecycle.append(("register", get_ident()))
        self.requests.put(display_name)
        result = self.results.get(timeout=3)
        if isinstance(result, Exception):
            raise result
        return result

    def list_users(self) -> list[UserProfile]:
        self.lifecycle.append(("refresh", get_ident()))
        self.refreshes.put(None)
        result = self.directory_results.get(timeout=3)
        if isinstance(result, Exception):
            raise result
        return result


@contextmanager
def _start(
    backend: FakeBackend,
) -> Generator[tuple[SignupController, SignupWorker, list[SignupState]], None, None]:
    states: list[SignupState] = []
    worker = SignupWorker(backend.open)
    controller = SignupController(worker, states.append)
    try:
        yield controller, worker, states
    finally:
        controller.close()
        worker.join()


def _poll_next(controller: SignupController, states: list[SignupState]) -> SignupState:
    count = len(states)
    deadline = monotonic() + 3
    while monotonic() < deadline:
        controller.poll()
        if len(states) > count:
            return states[-1]
        sleep(0.005)
    pytest.fail("The worker did not deliver a UI state.")


@pytest.mark.parametrize("profile", [None, _PROFILE])
def test_startup_shows_signup_or_the_restored_account(profile: UserProfile | None) -> None:
    backend = FakeBackend(profile)
    with _start(backend) as (controller, _, states):
        assert states[-1] == SignupState(status="Checking local account…")
        state = _poll_next(controller, states)
        if profile is None:
            assert state == SignupState(show_form=True, can_submit=True)
        else:
            assert state == SignupState(profile=profile, directory_status=_DIRECTORY_PROMPT)
    assert backend.requests.empty()
    assert backend.refreshes.empty()


def test_one_submission_switches_to_signed_in_and_worker_owns_lifecycle() -> None:
    backend = FakeBackend(None)
    ui_thread = get_ident()
    with _start(backend) as (controller, _, states):
        _ = _poll_next(controller, states)
        controller.submit("Ryan Martin")
        assert backend.requests.get(timeout=3) == "Ryan Martin"
        controller.submit("Second submission")
        assert states[-1] == SignupState(status="Creating account…", show_form=True)
        backend.results.put(_PROFILE)
        assert _poll_next(controller, states) == SignupState(profile=_PROFILE, directory_status=_DIRECTORY_PROMPT)

    assert backend.requests.empty()
    assert [event for event, _thread in backend.lifecycle] == ["open", "restore", "register", "close"]
    worker_threads = {thread for _event, thread in backend.lifecycle}
    assert len(worker_threads) == 1
    assert ui_thread not in worker_threads


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (ApiTransportError(timed_out=False), "Could not connect to the signup server."),
        (ApiHttpError(404, None), "Public signup is unavailable."),
        (ApiHttpError(409, None), "This account already exists on the server."),
        (ApiHttpError(429, "untrusted response content"), "Too many signup attempts. Wait before trying again."),
        (RuntimeError("private response"), "Could not complete signup."),
    ],
)
def test_failure_keeps_form_usable_and_allows_retry(error: Exception, message: str) -> None:
    backend = FakeBackend(None)
    entered_name = "  Ryan Martin  "
    with _start(backend) as (controller, _, states):
        _ = _poll_next(controller, states)
        controller.submit(entered_name)
        assert backend.requests.get(timeout=3) == entered_name
        backend.results.put(error)
        assert _poll_next(controller, states) == SignupState(status=message, show_form=True, can_submit=True)
        controller.submit(entered_name)
        assert backend.requests.get(timeout=3) == entered_name
        backend.results.put(_PROFILE)
        assert _poll_next(controller, states) == SignupState(profile=_PROFILE, directory_status=_DIRECTORY_PROMPT)


def test_close_ignores_an_in_flight_result_and_closes_the_worker() -> None:
    backend = FakeBackend(None)
    with _start(backend) as (controller, worker, states):
        _ = _poll_next(controller, states)
        controller.submit("Ryan Martin")
        assert backend.requests.get(timeout=3) == "Ryan Martin"
        controller.close()
        backend.results.put(_PROFILE)
        worker.join()
        before = list(states)
        controller.poll()
        assert states == before
        assert backend.lifecycle[-1][0] == "close"


def test_refresh_is_manual_ignores_duplicates_and_replaces_users() -> None:
    backend = FakeBackend(_PROFILE)
    with _start(backend) as (controller, _, states):
        assert _poll_next(controller, states).directory_status == _DIRECTORY_PROMPT
        assert backend.refreshes.empty()
        controller.refresh_directory()
        backend.refreshes.get(timeout=3)
        controller.refresh_directory()
        assert states[-1].refreshing
        backend.directory_results.put([_FIRST_PEER])
        state = _poll_next(controller, states)
        assert state.users == (_FIRST_PEER,)
        assert not state.refreshing

        controller.refresh_directory()
        backend.refreshes.get(timeout=3)
        assert states[-1].users == (_FIRST_PEER,)
        backend.directory_results.put([_NEXT_PEER])
        assert _poll_next(controller, states).users == (_NEXT_PEER,)

        controller.refresh_directory()
        backend.refreshes.get(timeout=3)
        backend.directory_results.put([])
        state = _poll_next(controller, states)
        assert state.users == ()
        assert state.directory_status == "No other users are registered."
    assert [event for event, _ in backend.lifecycle].count("refresh") == 3


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (ApiHttpError(401, None), "The server rejected this client's saved credentials."),
        (ApiTransportError(timed_out=False), "Could not reach the server. Try Refresh again."),
    ],
)
def test_failed_refresh_preserves_users_and_allows_retry(error: Exception, message: str) -> None:
    backend = FakeBackend(_PROFILE)
    with _start(backend) as (controller, _, states):
        _ = _poll_next(controller, states)
        controller.refresh_directory()
        backend.refreshes.get(timeout=3)
        backend.directory_results.put([_FIRST_PEER])
        _ = _poll_next(controller, states)

        controller.refresh_directory()
        backend.refreshes.get(timeout=3)
        backend.directory_results.put(error)
        state = _poll_next(controller, states)
        assert state.profile == _PROFILE
        assert state.users == (_FIRST_PEER,)
        assert state.directory_status == message
        assert not state.refreshing

        controller.refresh_directory()
        backend.refreshes.get(timeout=3)
        backend.directory_results.put([_NEXT_PEER])
        assert _poll_next(controller, states).users == (_NEXT_PEER,)


def test_close_ignores_late_refresh_result() -> None:
    backend = FakeBackend(_PROFILE)
    with _start(backend) as (controller, worker, states):
        _ = _poll_next(controller, states)
        controller.refresh_directory()
        backend.refreshes.get(timeout=3)
        controller.close()
        backend.directory_results.put([_FIRST_PEER])
        worker.join()
        before = list(states)
        controller.poll()
        assert states == before
        assert backend.lifecycle[-1][0] == "close"