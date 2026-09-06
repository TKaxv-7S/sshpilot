"""GTK-free controller for daemon-owned host-information probes.

The dialog renders DTOs; this controller is the only thing that talks to the
daemon.  It never carries probe text and never parses remote output — both
belong to the daemon — and it never polls: completion arrives as an
``OPERATION_STATE_CHANGED`` event, so a probe occupies a client worker only
for the two short RPCs that start it and read its result.

Threading: the controller owns a single worker thread and every daemon call
runs on it.  ``start`` returns immediately, and callbacks arrive on that worker
— never on the client's event-dispatch thread, which must not be blocked by an
RPC or the whole application's event stream stalls behind it.  Callers are
responsible for marshalling callbacks onto the UI main loop.

One probe of each kind may be in flight at a time; a second request of the same
kind while one is outstanding is refused rather than queued, which is what
keeps repeated bandwidth sampling from piling up behind a slow link.
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

from sshpilot.api.client import SshPilotClient
from sshpilot.api.events import EventType
from sshpilot.api.models.common import ConnectionId
from sshpilot.api.models.host_info import (
    HostInfoProbe,
    HostInfoRequest,
    HostInfoSummary,
)
from sshpilot.api.models.operations import OperationState

logger = logging.getLogger(__name__)

_TERMINAL_STATES = frozenset(
    {OperationState.SUCCEEDED, OperationState.FAILED, OperationState.CANCELLED}
)


class HostInfoProbeBusy(RuntimeError):
    """Raised when a probe of the same kind is already running."""


class HostInfoController:
    """Start host-information probes and deliver their typed results."""

    def __init__(self, client: SshPilotClient) -> None:
        if client is None:
            raise ValueError("a daemon client is required")
        self._client = client
        self._lock = threading.RLock()
        self._inflight: dict = {}
        self._subscription = None
        self._closed = False
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="sshpilot-host-info"
        )

    # -- lifecycle ------------------------------------------------------

    def close(self) -> None:
        """Stop listening and forget in-flight probes; safe to call twice."""

        with self._lock:
            if self._closed:
                return
            self._closed = True
            subscription = self._subscription
            self._subscription = None
            self._inflight.clear()
        if subscription is not None:
            try:
                subscription.close()
            except Exception:
                logger.debug("Host info event subscription close failed", exc_info=True)
        self._executor.shutdown(wait=False)

    def is_running(self, probe: HostInfoProbe) -> bool:
        with self._lock:
            return probe in self._inflight

    # -- probing --------------------------------------------------------

    def start(
        self,
        connection_id: ConnectionId,
        probe: HostInfoProbe,
        on_result: Callable[[HostInfoSummary], None],
        on_error: Callable[[BaseException], None],
        on_started: Optional[Callable[[object], None]] = None,
    ) -> None:
        """Run one probe and deliver its finished summary exactly once.

        Returns immediately.  ``on_result`` is invoked with the terminal
        summary (which may carry a ``failure``); ``on_error`` is invoked when
        the probe could not be started or read at all.  Raises
        :class:`HostInfoProbeBusy` when a probe of this kind is outstanding.

        ``on_started`` receives the operation id as soon as the daemon accepts
        the probe.  A frontend uses it to bind an interaction presenter to the
        operation scope, which is how a passphrase, password, host-key or MFA
        prompt raised by the probe reaches the user.
        """

        with self._lock:
            if self._closed:
                raise HostInfoProbeBusy("the host information controller is closed")
            if probe in self._inflight:
                raise HostInfoProbeBusy(f"a {probe.value} probe is already running")
            self._inflight[probe] = None
            self._ensure_subscribed_locked()
        self._submit(
            lambda: self._start_blocking(
                connection_id, probe, on_result, on_error, on_started
            )
        )

    def _start_blocking(
        self,
        connection_id: ConnectionId,
        probe: HostInfoProbe,
        on_result: Callable[[HostInfoSummary], None],
        on_error: Callable[[BaseException], None],
        on_started: Optional[Callable[[object], None]] = None,
    ) -> None:
        try:
            summary = self._client.start_host_info(
                HostInfoRequest(connection_id, probe)
            )
        except BaseException as error:
            self._finish(probe)
            on_error(error)
            return

        operation_id = summary.operation.operation_id
        with self._lock:
            if self._closed or probe not in self._inflight:
                return
            self._inflight[probe] = _Pending(operation_id, on_result, on_error)

        # Bind before waiting: the probe may already be blocked on a prompt.
        if on_started is not None:
            on_started(operation_id)

        # The probe can finish before its completion event is dispatched, so
        # settle from the summary already in hand rather than waiting forever.
        if summary.operation.state in _TERMINAL_STATES:
            self._settle(operation_id, summary)

    def cancel(self, probe: HostInfoProbe) -> None:
        """Cancel an in-flight probe; a probe that already finished is a no-op."""

        with self._lock:
            pending = self._inflight.get(probe)
            operation_id = pending.operation_id if pending is not None else None
            self._inflight.pop(probe, None)
        if operation_id is None:
            return
        try:
            self._client.cancel_host_info(operation_id)
        except Exception:
            logger.debug("Host info cancellation failed", exc_info=True)

    # -- internals ------------------------------------------------------

    def _ensure_subscribed_locked(self) -> None:
        if self._subscription is not None:
            return
        try:
            self._subscription = self._client.subscribe_events(self._on_event)
        except Exception as error:
            self._inflight.clear()
            raise RuntimeError("host information events are unavailable") from error

    def _submit(self, operation: Callable[[], None]) -> None:
        try:
            self._executor.submit(operation)
        except RuntimeError:
            logger.debug("Host info worker is shut down", exc_info=True)

    def _on_event(self, event) -> None:
        """Runs on the client's event thread: never block it with an RPC."""

        if event.type is not EventType.OPERATION_STATE_CHANGED:
            return
        summary = event.payload
        if getattr(summary, "state", None) not in _TERMINAL_STATES:
            return
        operation_id = getattr(summary, "operation_id", None)
        if operation_id is None:
            return
        with self._lock:
            if self._closed or not self._waiting_for_locked(operation_id):
                return
        self._submit(lambda: self._settle(operation_id, None))

    def _waiting_for_locked(self, operation_id) -> bool:
        return any(
            pending is not None and str(pending.operation_id) == str(operation_id)
            for pending in self._inflight.values()
        )

    def _settle(self, operation_id, summary: Optional[HostInfoSummary]) -> None:
        """Read the finished probe once and hand it to its waiter."""

        with self._lock:
            probe = next(
                (
                    key
                    for key, pending in self._inflight.items()
                    if pending is not None and str(pending.operation_id) == str(operation_id)
                ),
                None,
            )
            if probe is None:
                return
            pending = self._inflight.pop(probe)

        try:
            result = summary if summary is not None else self._client.get_host_info(
                pending.operation_id
            )
        except BaseException as error:
            pending.on_error(error)
            return
        pending.on_result(result)

    def _finish(self, probe: HostInfoProbe) -> None:
        with self._lock:
            self._inflight.pop(probe, None)


class _Pending:
    __slots__ = ("operation_id", "on_result", "on_error")

    def __init__(self, operation_id, on_result, on_error) -> None:
        self.operation_id = operation_id
        self.on_result = on_result
        self.on_error = on_error
