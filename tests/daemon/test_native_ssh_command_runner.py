"""Native one-shot SSH runner pipe-drain behavior."""

from __future__ import annotations

import os
import signal
import sys
import threading
import time
from pathlib import Path

from sshpilot.api.models.broadcast import BroadcastExecutionPolicy
from sshpilot.daemon.broadcast_service import NativeSshCommandRunner


def _policy(**kwargs) -> BroadcastExecutionPolicy:
    return BroadcastExecutionPolicy(**kwargs)


def test_runner_returns_after_child_exit_when_pipe_write_end_stays_open(tmp_path: Path):
    """ControlPersist mux can hold capture pipes after the command child exits.

    Reproduce that with a fork that inherits stderr: parent exits, child keeps
    the write end open. The runner must return on exit (with buffered output),
    not wait for EOF until timeout.
    """

    orphan_pid_path = tmp_path / "orphan.pid"
    script = r"""
import os
import sys
import time

sys.stdout.write("probe-ok\n")
sys.stdout.flush()
sys.stderr.write("verbose-line\n")
sys.stderr.flush()
child = os.fork()
if child == 0:
    time.sleep(120)
    os._exit(0)
with open(os.environ["SSHPILOT_TEST_ORPHAN_PID"], "w", encoding="utf-8") as handle:
    handle.write(str(child))
os._exit(0)
"""
    env = {**os.environ, "SSHPILOT_TEST_ORPHAN_PID": str(orphan_pid_path)}
    runner = NativeSshCommandRunner()
    cancel_event = threading.Event()
    started = time.monotonic()
    try:
        code, stdout, stderr, truncated, timed_out = runner.run(
            (sys.executable, "-c", script),
            env,
            _policy(timeout_seconds=5.0),
            cancel_event=cancel_event,
        )
        elapsed = time.monotonic() - started
        assert code == 0
        assert timed_out is False
        assert truncated is False
        assert "probe-ok" in stdout
        assert "verbose-line" in stderr
        assert elapsed < 2.0, f"runner hung waiting for pipe EOF ({elapsed:.2f}s)"
    finally:
        if orphan_pid_path.exists():
            orphan_pid = int(orphan_pid_path.read_text(encoding="utf-8").strip())
            try:
                os.kill(orphan_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_runner_drains_normal_child_output_to_eof():
    runner = NativeSshCommandRunner()
    code, stdout, stderr, truncated, timed_out = runner.run(
        (sys.executable, "-c", "import sys; print('ok'); print('e', file=sys.stderr)"),
        dict(os.environ),
        _policy(timeout_seconds=5.0),
        cancel_event=threading.Event(),
    )
    assert code == 0
    assert timed_out is False
    assert truncated is False
    assert stdout.strip() == "ok"
    assert stderr.strip() == "e"
