"""End-to-end host information against a real sshd on a non-standard port.

This is the only coverage that exercises the whole chain at once: daemon
dispatch -> broadcast execution -> a real SSH login -> the probe script -> the
parser -> the completion event -> the client read. It exists because each half
passed its own unit tests while the seam between them was broken twice: the
daemon never forwarded ``OPERATION_STATE_CHANGED``, so the frontend waited for
a completion event that could not arrive, and the event payload names its
operation ``operation_id`` rather than ``id``.

The sshd runs on an ephemeral port, never 22, so a host that moved its SSH port
is the normal case here rather than an afterthought.
"""

import os
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

from sshpilot.api.daemon_client import DaemonClient
from sshpilot.api.events import EventType
from sshpilot.api.models.common import ConnectionId
from sshpilot.api.models.host_info import HostInfoProbe, HostInfoRequest
from sshpilot.api.models.operations import OperationState
from sshpilot.core.connection_application_service import ConnectionApplicationService
from sshpilot.daemon import DaemonServer
from tests.daemon.conftest import (
    TestConnection as _Connection,
    TestConnectionManager as _ConnectionManager,
)

pytestmark = pytest.mark.integration

_SSHD = next(
    (path for path in ("/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd")
     if os.path.exists(path)),
    None,
)

_TERMINAL = {OperationState.SUCCEEDED, OperationState.FAILED, OperationState.CANCELLED}


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class _Sshd:
    """A running throwaway sshd plus the means to trust another key."""

    def __init__(self, port, identity, authorized_keys):
        self.port = port
        self.identity = identity
        self._authorized_keys = authorized_keys

    def authorize(self, identity: Path) -> None:
        with self._authorized_keys.open("a") as handle:
            handle.write(identity.with_suffix(".pub").read_text())


@pytest.fixture
def local_sshd(tmp_path):
    """A throwaway sshd on a random high port, keyed to a throwaway identity."""

    if _SSHD is None or shutil.which("ssh-keygen") is None:
        pytest.skip("no local sshd available")
    root = tmp_path / "sshd"
    root.mkdir()
    identity = root / "id"
    host_key = root / "hostkey"
    for target in (identity, host_key):
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(target)],
            check=True,
        )
    authorized = root / "authorized_keys"
    authorized.write_text(identity.with_suffix(".pub").read_text())
    authorized.chmod(0o600)
    host_key.chmod(0o600)

    port = _free_port()
    config = root / "sshd_config"
    config.write_text(
        f"Port {port}\n"
        "ListenAddress 127.0.0.1\n"
        f"HostKey {host_key}\n"
        f"PidFile {root / 'sshd.pid'}\n"
        f"AuthorizedKeysFile {authorized}\n"
        "StrictModes no\n"
        "UsePAM no\n"
        "PasswordAuthentication no\n"
    )
    started = subprocess.run(
        [_SSHD, "-f", str(config), "-E", str(root / "sshd.log")],
        capture_output=True,
        text=True,
    )
    if started.returncode != 0:
        pytest.skip(f"sshd would not start: {started.stderr.strip()}")

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.1)
    else:
        pytest.skip("sshd did not begin listening")

    yield _Sshd(port, identity, authorized)

    pid_file = root / "sshd.pid"
    if pid_file.exists():
        try:
            os.kill(int(pid_file.read_text().strip()), 15)
        except (OSError, ValueError):
            pass


def _connection(port: int, identity: Path) -> _Connection:
    connection = _Connection(
        nickname="loopback", hostname="127.0.0.1", username=os.environ.get("USER", "")
    )
    connection.port = port
    connection.keyfile = str(identity)
    connection.data.update({"hostname": "127.0.0.1", "port": port})
    return connection


class _LoopbackLaunchProvider:
    """Resolve a saved connection to a real ``ssh`` invocation.

    Stands in for the daemon's config-resolving provider only; everything past
    this point — the SSH child, sshd, the probe, the parser — is real.
    """

    def __init__(self, port: int, identity: Path) -> None:
        self._port = port
        self._identity = identity

    def remote_identity(self, connection_id):
        """What the daemon asks for so prompts name the right account."""

        return "127.0.0.1", os.environ.get("USER", ""), self._port

    def prepare_remote_command_launch(
        self, connection_id, remote_command, *, interaction_policy="broker"
    ):
        # No BatchMode: the daemon's askpass transport must be able to raise
        # a prompt, which BatchMode would suppress. The real provider does not
        # set it either.
        argv = (
            "ssh", "-T",
            "-F", "/dev/null",
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-i", str(self._identity),
            "-p", str(self._port),
            "127.0.0.1",
            remote_command,
        )
        return argv, dict(os.environ)


def _daemon(tmp_path, port, identity, name):
    manager = _ConnectionManager()
    manager.connections = [_connection(port, identity)]
    provider = _LoopbackLaunchProvider(port, identity)
    socket_path = tmp_path / name / "sshpilotd.sock"
    socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    server = DaemonServer(
        lambda: ConnectionApplicationService(
            manager,
            launch_provider=provider,
            secret_provider=manager,
            client_name="sshpilotd",
        ),
        socket_path=socket_path,
    )
    server.start_in_thread()
    return server


def test_host_info_completes_over_a_real_ssh_session(tmp_path, local_sshd):
    port, identity = local_sshd.port, local_sshd.identity
    server = _daemon(tmp_path, port, identity, "full")

    client = DaemonClient(socket_path=server.socket_path, client_id="client:hostinfo")
    finished = threading.Event()
    seen = []

    def _on_event(event):
        if event.type is not EventType.OPERATION_STATE_CHANGED:
            return
        # The frontend keys off this exact attribute name.
        seen.append(event.payload.operation_id)
        if event.payload.state in _TERMINAL:
            finished.set()

    try:
        subscription = client.subscribe_events(_on_event)
        connection_id = ConnectionId(client.list_connections()[0].id)
        started = client.start_host_info(
            HostInfoRequest(connection_id, HostInfoProbe.FULL)
        )

        assert finished.wait(90), "no completion event arrived for the probe"
        assert seen, "the completion event carried no operation id"

        summary = client.get_host_info(started.operation.operation_id)
        assert summary.failure is None, summary.failure
        snapshot = summary.snapshot
        assert snapshot is not None

        # The host reports its own identity and the port we actually arrived on.
        assert snapshot.hostname
        assert snapshot.ssh_port == port
        assert snapshot.ssh_port != 22
        assert snapshot.memory.total_bytes > 0
        assert summary.counters, "a full probe also returns byte counters"
    finally:
        subscription.close()
        client.close()
        server.shutdown()
        server.wait_stopped()


def test_bandwidth_sampling_returns_counters_without_a_snapshot(tmp_path, local_sshd):
    port, identity = local_sshd.port, local_sshd.identity
    server = _daemon(tmp_path, port, identity, "counters")

    client = DaemonClient(socket_path=server.socket_path, client_id="client:counters")
    finished = threading.Event()

    def _on_event(event):
        if (
            event.type is EventType.OPERATION_STATE_CHANGED
            and event.payload.state in _TERMINAL
        ):
            finished.set()

    try:
        subscription = client.subscribe_events(_on_event)
        connection_id = ConnectionId(client.list_connections()[0].id)
        started = client.start_host_info(
            HostInfoRequest(connection_id, HostInfoProbe.NETWORK_COUNTERS)
        )
        assert finished.wait(60)

        summary = client.get_host_info(started.operation.operation_id)
        assert summary.failure is None, summary.failure
        assert summary.snapshot is None
        assert summary.counters
        assert all(item.rx_bytes >= 0 for item in summary.counters)
    finally:
        subscription.close()
        client.close()
        server.shutdown()
        server.wait_stopped()


def test_a_passphrase_prompt_is_raised_under_the_probe_operation_scope(
    tmp_path, local_sshd
):
    """The dialog binds its interaction presenter to the operation id.

    If the daemon scoped a probe's prompts to anything else, the presenter
    would stay unbound and the user would watch a spinner instead of being
    asked for a passphrase, so the scope is asserted rather than assumed.
    """

    locked = tmp_path / "locked_key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "hunter2", "-f", str(locked)],
        check=True,
    )
    # The server must accept the locked key, or it is rejected before ssh ever
    # needs to decrypt it and no passphrase is asked for.
    local_sshd.authorize(locked)
    server = _daemon(tmp_path, local_sshd.port, locked, "passphrase")

    client = DaemonClient(socket_path=server.socket_path, client_id="client:prompt")
    try:
        connection_id = ConnectionId(client.list_connections()[0].id)
        started = client.start_host_info(
            HostInfoRequest(connection_id, HostInfoProbe.FULL)
        )
        operation_id = started.operation.operation_id

        deadline = time.monotonic() + 45
        scopes = []
        while time.monotonic() < deadline:
            scopes = [str(item.session_id) for item in client.list_interactions()]
            if scopes:
                break
            time.sleep(0.2)

        assert scopes, "the locked key raised no interaction at all"
        assert str(operation_id) in scopes, (
            f"prompt scoped to {scopes}, not the probe operation {operation_id}"
        )
    finally:
        try:
            client.cancel_host_info(operation_id)
        except Exception:
            pass
        client.close()
        server.shutdown()
        server.wait_stopped()
