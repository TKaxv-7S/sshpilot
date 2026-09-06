"""GUI coverage for the Host Info dialog rendering daemon-supplied DTOs.

The dialog is presentation only: it must build every tab from a
``HostInfoSnapshot`` without reaching for a shell, and must degrade to "N/A"
rather than to zero for readings the host did not publish.
"""

import pytest

from gi.repository import Gtk

from sshpilot.api.models.host_info import (
    CpuInfo,
    FailedUnit,
    FilesystemUsage,
    HostInfoSnapshot,
    HostKeyFingerprint,
    InterfaceCounters,
    ListeningPort,
    LoadAverage,
    LoginSession,
    MemoryInfo,
    NetworkInterface,
    NetworkInterfaceKind,
    NetworkInterfaceState,
    PressureStall,
    ProcessUsage,
    SocketConnection,
    SocketDirection,
    TemperatureReading,
)
from tests._gui_harness import requires_gui

requires_gui()

pytestmark = pytest.mark.gui


def _walk(widget):
    yield widget
    child = widget.get_first_child()
    while child is not None:
        yield from _walk(child)
        child = child.get_next_sibling()


def _texts(widget):
    return [w.get_text() for w in _walk(widget) if isinstance(w, Gtk.Label)]


def _snapshot(**overrides):
    base = dict(
        hostname="router",
        os_pretty_name="OpenWrt 23.05",
        kernel="Linux 5.15 mips",
        uptime_seconds=90061.0,
        boot_time="2026-09-01 18:00",
        cpu=CpuInfo(
            model="Atheros AR9344",
            cores_per_socket=2,
            threads_per_core=2,
            sockets=1,
            logical_processors=4,
            frequency_mhz=1200.0,
        ),
        memory=MemoryInfo(
            total_bytes=1024 * 1024 * 512,
            free_bytes=1024 * 1024 * 64,
            available_bytes=1024 * 1024 * 128,
            cached_bytes=1024 * 1024 * 32,
            swap_total_bytes=1024 * 1024 * 256,
            swap_free_bytes=1024 * 1024 * 200,
        ),
        load_average=LoadAverage(1.0, 0.5, 0.25),
        filesystems=(
            FilesystemUsage(
                device="/dev/mtdblock6",
                mount_point="/overlay",
                fstype="jffs2",
                size_bytes=2_000_000,
                used_bytes=1_900_000,
                available_bytes=100_000,
                use_percent=95,
            ),
        ),
        interfaces=(
            NetworkInterface(
                name="wlan0",
                kind=NetworkInterfaceKind.WIRELESS,
                state=NetworkInterfaceState.UP,
                mac_address="11:22:33:44:55:66",
                mtu=1500,
                ipv4_addresses=("192.168.1.1/24",),
            ),
        ),
        temperatures=(TemperatureReading("cpu-thermal", 85.0),),
        sessions=(
            LoginSession(user="root", tty="pts/0", origin="10.0.0.9", since="09:15", remote=True),
            LoginSession(user="local", tty="tty1", since="08:00"),
        ),
        sockets=(
            SocketConnection(
                protocol="tcp",
                local_address="10.0.0.5",
                local_port=2222,
                peer_address="10.0.0.9",
                peer_port=51234,
                process="sshd",
                direction=SocketDirection.INCOMING,
            ),
        ),
        default_gateway="192.168.1.254",
        default_gateway_interface="wlan0",
        dns_servers=("1.1.1.1",),
        ssh_port=2222,
        ssh_process="sshd",
    )
    base.update(overrides)
    return HostInfoSnapshot(**base)


def _dialog(snapshot, counters=()):
    """Build a dialog shell without a daemon and hand it a snapshot."""

    from sshpilot.machine_info_dialog import MachineInfoDialog

    dialog = object.__new__(MachineInfoDialog)
    dialog._snapshot = snapshot
    dialog._rate_labels = {}
    dialog._previous_counters = counters
    return dialog


def test_every_tab_builds_from_a_snapshot():
    dialog = _dialog(_snapshot(), counters=(InterfaceCounters("wlan0", 100, 200),))
    for build in (
        dialog._build_overview,
        dialog._build_resources,
        dialog._build_storage,
        dialog._build_network,
        dialog._build_traffic,
        dialog._build_system,
    ):
        assert isinstance(build(), Gtk.Box)


def test_the_discovered_ssh_port_is_shown_not_a_hardcoded_22():
    texts = _texts(_dialog(_snapshot())._build_network())
    assert any("2222/tcp" in text for text in texts)
    assert not any(text.startswith("22/tcp") for text in texts)


def test_an_unreported_memory_availability_reads_as_na_everywhere():
    snapshot = _snapshot(
        memory=MemoryInfo(total_bytes=1024 * 1024 * 512, free_bytes=1024 * 1024 * 64)
    )
    dialog = _dialog(snapshot)
    overview = _texts(dialog._build_overview())
    resources = _texts(dialog._build_resources())
    # Neither "0%" (nothing used) nor "100%" (everything used) may be invented.
    assert "—" in overview
    assert any("N/A" in text for text in overview)
    assert any("N/A" in text for text in resources)


def test_a_missing_cpu_count_does_not_break_the_load_gauges():
    snapshot = _snapshot(cpu=CpuInfo(model="Unknown"))
    dialog = _dialog(snapshot)
    assert isinstance(dialog._build_overview(), Gtk.Box)
    texts = _texts(dialog._build_resources())
    assert any("CPU count unavailable" in text for text in texts)


def test_memory_and_temperatures_are_stacked_not_side_by_side():
    """Both sections need the full width; a half-width column wraps badly."""

    page = _dialog(_snapshot())._build_resources()
    headings = {}
    for widget in _walk(page):
        if isinstance(widget, Gtk.Label) and widget.get_text() in ("Memory", "Temperatures"):
            headings[widget.get_text()] = widget
    assert set(headings) == {"Memory", "Temperatures"}

    def _ancestors(widget):
        found = []
        parent = widget.get_parent()
        while parent is not None:
            found.append(parent)
            parent = parent.get_parent()
        return found

    shared = set(map(id, _ancestors(headings["Memory"]))) & set(
        map(id, _ancestors(headings["Temperatures"]))
    )
    horizontal = [
        widget for widget in _walk(page)
        if id(widget) in shared
        and isinstance(widget, Gtk.Box)
        and widget.get_orientation() is Gtk.Orientation.HORIZONTAL
    ]
    assert not horizontal, "the two sections still share a horizontal container"


def test_a_nearly_full_filesystem_is_marked_critical_not_healthy():
    from sshpilot.machine_info_dialog import _SEVERITY_CRITICAL

    page = _dialog(_snapshot())._build_storage()
    bars = [w for w in _walk(page) if isinstance(w, Gtk.LevelBar)]
    assert bars
    assert _SEVERITY_CRITICAL in bars[0].get_css_classes()


def test_severity_runs_green_amber_red_as_a_value_fills_up():
    from sshpilot.machine_info_dialog import (
        _SEVERITY_CRITICAL,
        _SEVERITY_OK,
        _SEVERITY_UNKNOWN,
        _SEVERITY_WARN,
        _temperature_severity,
        _usage_severity,
    )

    assert _usage_severity(0.0) is _SEVERITY_OK
    assert _usage_severity(0.74) is _SEVERITY_OK
    assert _usage_severity(0.75) is _SEVERITY_WARN
    assert _usage_severity(0.89) is _SEVERITY_WARN
    assert _usage_severity(0.90) is _SEVERITY_CRITICAL
    assert _usage_severity(1.0) is _SEVERITY_CRITICAL
    assert _temperature_severity(59.9) is _SEVERITY_OK
    assert _temperature_severity(60.0) is _SEVERITY_WARN
    assert _temperature_severity(80.0) is _SEVERITY_CRITICAL

    # An unknown reading is neither healthy nor alarming.
    assert _usage_severity(None) is _SEVERITY_UNKNOWN


def test_an_unknown_reading_is_not_painted_as_healthy():
    """Green means "there is headroom", so it must not mean "no idea"."""

    from sshpilot.machine_info_dialog import _SEVERITY_OK, _SEVERITY_UNKNOWN
    from sshpilot.api.models.host_info import MemoryInfo

    snapshot = _snapshot(
        memory=MemoryInfo(total_bytes=1024 * 1024 * 512, free_bytes=1024)
    )
    page = _dialog(snapshot)._build_resources()
    memory_bars = [
        w for w in _walk(page)
        if isinstance(w, Gtk.LevelBar) and _SEVERITY_UNKNOWN in w.get_css_classes()
    ]
    assert memory_bars, "a memory bar with no MemAvailable must read as unknown"
    assert all(
        _SEVERITY_OK not in bar.get_css_classes() for bar in memory_bars
    )


def test_a_hot_sensor_is_marked_critical():
    from sshpilot.machine_info_dialog import _SEVERITY_CRITICAL

    page = _dialog(_snapshot())._build_resources()
    bars = [
        w for w in _walk(page)
        if isinstance(w, Gtk.LevelBar) and _SEVERITY_CRITICAL in w.get_css_classes()
    ]
    assert bars, "an 85 °C sensor must render as critical"


def test_remote_sessions_and_all_users_are_listed_separately():
    dialog = _dialog(_snapshot())
    remote = _texts(dialog._build_traffic())
    everyone = _texts(dialog._build_system())
    assert "root" in remote and "local" not in remote
    assert "root" in everyone and "local" in everyone


def test_an_empty_snapshot_still_renders():
    dialog = _dialog(HostInfoSnapshot())
    for build in (
        dialog._build_overview,
        dialog._build_resources,
        dialog._build_storage,
        dialog._build_network,
        dialog._build_traffic,
        dialog._build_system,
    ):
        assert isinstance(build(), Gtk.Box)


# ---------------------------------------------------------------------------
# Authentication prompts
# ---------------------------------------------------------------------------

class _FakePresenter:
    """Stands in for DaemonInteractionDialogs."""

    def __init__(self):
        self.sessions = []
        self.closed = False

    def set_session(self, session_id):
        self.sessions.append(str(session_id))

    def close(self):
        self.closed = True


class _FakeController:
    def __init__(self):
        self.calls = []

    def start(self, connection_id, probe, on_result, on_error, on_started=None):
        self.calls.append((probe, on_started))

    def is_running(self, probe):
        return False


class _Connection:
    nickname = "demo"
    username = "alice"
    host = "example.test"


def _wired_dialog():
    """A dialog shell with a fake controller and presenter, no daemon."""

    from sshpilot.machine_info_dialog import MachineInfoDialog

    dialog = object.__new__(MachineInfoDialog)
    dialog._closed = False
    dialog._connection = _Connection()
    dialog._controller = _FakeController()
    dialog._interaction_dialogs = _FakePresenter()
    dialog._window = None
    return dialog


def test_a_password_prompt_reaches_the_user_by_binding_the_operation_scope():
    """The presenter ignores every interaction until it is bound to a scope."""

    from sshpilot.api.models.host_info import HostInfoProbe

    dialog = _wired_dialog()
    assert dialog._submit(HostInfoProbe.FULL, lambda s: None, lambda e: None)

    probe, on_started = dialog._controller.calls[0]
    assert probe is HostInfoProbe.FULL
    assert on_started is not None, "a full gather must bind the presenter"

    dialog._bind_interactions("operation-7")
    assert dialog._interaction_dialogs.sessions == ["operation-7"]


def test_bandwidth_sampling_never_rebinds_the_presenter():
    """Counter probes are autofill-only and must not steal the scope."""

    from sshpilot.api.models.host_info import HostInfoProbe

    dialog = _wired_dialog()
    dialog._submit(HostInfoProbe.NETWORK_COUNTERS, lambda s: None, lambda e: None)

    probe, on_started = dialog._controller.calls[0]
    assert probe is HostInfoProbe.NETWORK_COUNTERS
    assert on_started is None


def test_binding_after_the_dialog_closed_is_ignored():
    dialog = _wired_dialog()
    dialog._closed = True

    dialog._bind_interactions("operation-7")

    assert dialog._interaction_dialogs.sessions == []


def test_every_reported_address_is_shown_not_just_the_first_ipv4():
    """An interface that answers only over IPv6 must not read as address-less."""

    snapshot = _snapshot(
        interfaces=(
            NetworkInterface(
                name="eth0",
                kind=NetworkInterfaceKind.ETHERNET,
                state=NetworkInterfaceState.UP,
                ipv4_addresses=("10.0.0.5/24", "10.0.0.6/24"),
                ipv6_addresses=("2001:db8::1/64",),
            ),
        )
    )
    texts = _texts(_dialog(snapshot)._build_network())
    for address in ("10.0.0.5/24", "10.0.0.6/24", "2001:db8::1/64"):
        assert address in texts


def test_interface_state_is_readable_without_hovering():
    """State used to live in an icon tooltip, which touch users cannot reach."""

    snapshot = _snapshot(
        interfaces=(
            NetworkInterface(
                name="eth0",
                kind=NetworkInterfaceKind.ETHERNET,
                state=NetworkInterfaceState.NO_CARRIER,
                mtu=1500,
            ),
        )
    )
    page = _dialog(snapshot)._build_network()
    assert any("No carrier" in text for text in _texts(page))
    assert not [
        widget for widget in _walk(page)
        if isinstance(widget, Gtk.Image) and widget.get_tooltip_text()
    ]


def test_the_filesystem_table_reports_what_the_host_says_is_left():
    """Reserved blocks mean size - used overstates what is actually free."""

    from sshpilot.machine_info_dialog import _format_bytes_si

    snapshot = _snapshot(
        filesystems=(
            FilesystemUsage(
                device="/dev/sda1",
                mount_point="/",
                fstype="ext4",
                size_bytes=2_000_000,
                used_bytes=1_900_000,
                available_bytes=50_000,
            ),
        )
    )
    texts = _texts(_dialog(snapshot)._build_storage())
    assert "Available" in texts
    assert _format_bytes_si(50_000) in texts
    assert _format_bytes_si(100_000) not in texts, "available must not be derived"


def test_buffers_is_reported_with_the_other_meminfo_fields():
    snapshot = _snapshot(
        memory=MemoryInfo(
            total_bytes=1024 * 1024 * 512,
            free_bytes=1024 * 1024 * 64,
            available_bytes=1024 * 1024 * 128,
            buffers_bytes=1024 * 1024 * 16,
        )
    )
    texts = _texts(_dialog(snapshot)._build_resources())
    assert "Buffers" in texts
    assert "16.0 MiB" in texts


def test_a_capped_socket_list_names_the_protocol_and_says_what_it_hid():
    sockets = tuple(
        SocketConnection(
            protocol="udp" if index % 2 else "tcp",
            local_address="10.0.0.5",
            local_port=2222 + index,
            peer_address="10.0.0.9",
            peer_port=51000 + index,
            process="sshd",
            direction=SocketDirection.INCOMING,
        )
        for index in range(11)
    )
    texts = _texts(_dialog(_snapshot(sockets=sockets))._build_traffic())
    assert "tcp" in texts and "udp" in texts
    assert "3 more" in texts


def test_the_system_tab_reports_what_the_host_exposes():
    snapshot = _snapshot(
        os_id="openwrt",
        os_version_id="23.05.5",
        architecture="mips",
        listening_ports=(
            ListeningPort(port=22, process="sshd"),
            ListeningPort(port=8080, process="uhttpd"),
        ),
        failed_units=(FailedUnit(name="logrotate.service", description="Rotate logs"),),
        host_keys=(
            HostKeyFingerprint(algorithm="ED25519", fingerprint="SHA256:abc", bits=256),
        ),
    )
    texts = _texts(_dialog(snapshot)._build_system())
    assert "openwrt 23.05.5" in texts and "mips" in texts
    assert "8080/tcp" in texts and "uhttpd" in texts
    assert "logrotate.service" in texts
    assert "SHA256:abc" in texts and "ED25519" in texts


def test_a_host_with_nothing_to_report_says_so_rather_than_showing_blanks():
    texts = _texts(_dialog(_snapshot())._build_system())
    for message in (
        "No listening services reported",
        "No failed units",
        "No host keys reported",
    ):
        assert message in texts


def test_a_multi_threaded_process_may_exceed_one_hundred_percent():
    """A share of one CPU, so 457% is a reading and not an overflow."""

    snapshot = _snapshot(
        processes=(ProcessUsage(command="ffmpeg", cpu_percent=457.0, memory_percent=5.1),)
    )
    texts = _texts(_dialog(snapshot)._build_resources())
    assert "457.0%" in texts


def test_a_process_without_a_memory_reading_shows_na_not_zero():
    snapshot = _snapshot(processes=(ProcessUsage(command="procd", cpu_percent=0.5),))
    texts = _texts(_dialog(snapshot)._build_resources())
    assert "0.5%" in texts
    assert any("N/A" in text for text in texts)


def test_io_pressure_is_shown_when_the_kernel_publishes_it():
    snapshot = _snapshot(
        io_pressure_some=PressureStall(1.1, 0.73, 0.38),
        io_pressure_full=PressureStall(0.33, 0.46, 0.29),
    )
    texts = _texts(_dialog(snapshot)._build_storage())
    assert "1.1%" in texts and "0.4%" in texts
    assert "Some tasks stalled" in texts and "All tasks stalled" in texts


def test_a_kernel_without_psi_says_so_rather_than_showing_zeroes():
    texts = _texts(_dialog(_snapshot())._build_storage())
    assert "This host does not report I/O pressure" in texts
    assert "0.0%" not in texts
