"""Operation lifecycle events reach the owning client, and only that client.

Host information (and any other client-started operation) learns that its work
finished from ``OPERATION_STATE_CHANGED``. Before this was forwarded the daemon
completed the operation silently and the client waited forever, so the coverage
here is both a delivery check and a scoping check: an operation summary names
its owner and may carry a result, so it must not be fanned out to every peer.
"""

from datetime import datetime, timezone

from sshpilot.api import EventType
from sshpilot.api.events import CoreEvent
from sshpilot.api.models.common import ClientId
from sshpilot.api.models.operations import (
    OperationId,
    OperationKind,
    OperationState,
    OperationSummary,
)
from sshpilot.daemon.server import DaemonServer, _ClientConnection

from tests.daemon.test_event_backpressure import _FakeSocket

OWNER = ClientId("client-owner")
OTHER = ClientId("client-other")


def _operation_event(state=OperationState.SUCCEEDED, owner=OWNER, sequence=0):
    summary = OperationSummary(
        OperationId("operation-1"),
        OperationKind.BROADCAST_COMMAND,
        state,
        "probe finished",
        datetime.now(timezone.utc),
        owner_client_id=owner,
    )
    return CoreEvent(
        type=EventType.OPERATION_STATE_CHANGED, payload=summary, sequence=sequence
    )


def _client(file_descriptor, client_id):
    state = _ClientConnection(_FakeSocket(file_descriptor))
    state.protocol.handshake_completed = True
    state.protocol.client_id = client_id
    return state


def _server(tmp_path):
    server = DaemonServer(lambda: None, socket_path=tmp_path / "sshpilotd.sock")
    owner = _client(10, OWNER)
    other = _client(11, OTHER)
    server._clients = {10: owner, 11: other}
    server._accepting_core_events = True
    return server, owner, other


def test_the_owning_client_is_told_its_operation_finished(tmp_path):
    server, owner, other = _server(tmp_path)

    server._on_core_event(_operation_event())

    assert owner.output, "the owning client must receive the completion event"
    assert not other.output


def test_other_clients_never_see_someone_elses_operation(tmp_path):
    server, owner, other = _server(tmp_path)

    server._on_core_event(_operation_event(owner=OTHER))

    assert other.output
    assert not owner.output


def test_a_client_without_an_identity_receives_nothing(tmp_path):
    server, owner, _other = _server(tmp_path)
    owner.protocol.client_id = None

    server._on_core_event(_operation_event())

    assert not owner.output


def test_running_states_are_forwarded_too(tmp_path):
    """Progress is observable, not only completion."""

    server, owner, _other = _server(tmp_path)

    server._on_core_event(_operation_event(state=OperationState.RUNNING))

    assert owner.output
