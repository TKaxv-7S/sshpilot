"""Turn raw host-probe output into typed host-information DTOs (GTK-free).

Everything here is a pure text transformation: no I/O, no gettext, no
presentation.  Each helper accepts both the coreutils/iproute2 form and the
BusyBox form of its input, because OpenWrt and other embedded hosts answer
with ``netstat``, six-column ``df`` and ``w`` where a desktop answers with
``ss``, seven-column ``df`` and ``who``.

Two decisions are worth calling out because guessing them wrongly produced
visibly contradictory output before:

* an absent reading stays ``None`` rather than becoming ``0`` or the total, so
  a frontend renders "unknown" instead of "0% used" on one screen and "100%
  used" on another;
* socket direction is decided from the host's own listening ports rather than
  from a privileged-port guess, so a service on 8443 is still "incoming" and
  an outgoing connection to 443 is not misfiled.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence, Tuple

from ...api.models.host_info import (
    CpuInfo,
    FilesystemUsage,
    HostInfoSnapshot,
    InterfaceCounters,
    LoadAverage,
    LoginSession,
    MemoryInfo,
    NetworkInterface,
    NetworkInterfaceKind,
    NetworkInterfaceState,
    SocketConnection,
    SocketDirection,
    TemperatureReading,
)
from .probe import SECTION_PATTERN

_SECTION_RE = re.compile(SECTION_PATTERN)

# Filesystems backed by kernel memory rather than storage.  ``overlayfs``
# appears as the *device* of OpenWrt's merged ``/``; its real backing store is
# reported separately as ``/overlay`` and is kept.
_PSEUDO_FILESYSTEMS = frozenset(
    {
        "binfmt_misc", "cgroup", "cgroup2", "configfs", "debugfs", "devpts",
        "devtmpfs", "efivarfs", "fusectl", "hugetlbfs", "mqueue", "none",
        "nsfs", "overlay", "overlayfs", "proc", "pstore", "ramfs",
        "rpc_pipefs", "securityfs", "sysfs", "tmpfs", "tracefs", "udev",
    }
)

_PSEUDO_MOUNT_PREFIXES = ("/snap/", "/run/", "/sys/", "/proc/", "/dev/")

# ``who``/``w`` render a local X or console login as these origins.
_LOCAL_ORIGINS = frozenset({"", ":0", ":1", ":0.0", "-", "console"})


def split_sections(raw: str) -> Dict[str, str]:
    """Split probe output into ``{marker: body}`` with surrounding blanks cut."""

    sections: Dict[str, str] = {}
    key: Optional[str] = None
    lines: List[str] = []
    for line in raw.splitlines():
        match = _SECTION_RE.match(line)
        if match:
            if key is not None:
                sections[key] = "\n".join(lines).strip()
            key = match.group(1)
            lines = []
        elif key is not None:
            lines.append(line)
    if key is not None:
        sections[key] = "\n".join(lines).strip()
    return sections


# ---------------------------------------------------------------------------
# Scalar helpers
# ---------------------------------------------------------------------------

def _int_or_none(value: object) -> Optional[int]:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _positive_int_or_none(value: object) -> Optional[int]:
    """``0`` means "the host could not tell us", never "zero CPUs"."""

    parsed = _int_or_none(value)
    return parsed if parsed else None


def _float_or_none(value: object) -> Optional[float]:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _port_or_none(endpoint: str) -> Optional[int]:
    match = re.search(r":(\d+)$", endpoint or "")
    if not match:
        return None
    port = int(match.group(1))
    return port if 0 <= port <= 65535 else None


def _strip_port(endpoint: str) -> str:
    return re.sub(r":\d+$", "", endpoint or "")


# ---------------------------------------------------------------------------
# Identity, CPU, memory
# ---------------------------------------------------------------------------

def parse_os_release(text: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip().strip('"')
    return values


def parse_key_value_block(text: str) -> Dict[str, str]:
    """Parse ``lscpu``-style ``key: value`` output."""

    values: Dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            values[key.strip()] = value.strip()
    return values


def parse_cpuinfo(text: str) -> Dict[str, str]:
    """Extract lscpu-equivalent fields from ``/proc/cpuinfo``.

    ARM, MIPS and other architectures name the model differently and omit
    topology entirely, so only the first occurrence of each field is kept and
    the logical processor count is derived by counting ``processor`` lines.
    """

    values: Dict[str, str] = {}
    processors = 0
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if key == "processor":
            processors += 1
        elif key in ("model name", "cpu model", "system type", "machine", "Hardware"):
            values.setdefault("model", value)
        elif key == "cpu MHz":
            values.setdefault("mhz", value)
        elif key == "BogoMIPS":
            values.setdefault("bogomips", value)
    if processors:
        values["processors"] = str(processors)
    return values


def parse_cpu(lscpu_text: str, cpuinfo_text: str, nproc_text: str) -> CpuInfo:
    lscpu = parse_key_value_block(lscpu_text)
    cpuinfo = parse_cpuinfo(cpuinfo_text)
    logical = (
        _positive_int_or_none(nproc_text)
        or _positive_int_or_none(cpuinfo.get("processors"))
        or _positive_int_or_none(lscpu.get("CPU(s)"))
    )
    frequency = _float_or_none(lscpu.get("CPU MHz")) or _float_or_none(cpuinfo.get("mhz"))
    return CpuInfo(
        model=lscpu.get("Model name", "") or cpuinfo.get("model", ""),
        cores_per_socket=_positive_int_or_none(lscpu.get("Core(s) per socket")),
        threads_per_core=_positive_int_or_none(lscpu.get("Thread(s) per core")),
        sockets=_positive_int_or_none(lscpu.get("Socket(s)")),
        logical_processors=logical,
        frequency_mhz=frequency,
        bogomips=_float_or_none(cpuinfo.get("bogomips")),
    )


def parse_meminfo(text: str) -> MemoryInfo:
    """Parse ``/proc/meminfo``; ``MemAvailable`` stays ``None`` when absent."""

    values: Dict[str, int] = {}
    for line in text.splitlines():
        match = re.match(r"^(\w+):\s+(\d+)", line)
        if match:
            values[match.group(1)] = int(match.group(2)) * 1024
    return MemoryInfo(
        total_bytes=values.get("MemTotal", 0),
        free_bytes=values.get("MemFree", 0),
        available_bytes=values.get("MemAvailable"),
        cached_bytes=values.get("Cached", 0),
        buffers_bytes=values.get("Buffers", 0),
        swap_total_bytes=values.get("SwapTotal", 0),
        swap_free_bytes=values.get("SwapFree", 0),
    )


def parse_load_average(text: str) -> Optional[LoadAverage]:
    parts = text.split()
    if len(parts) < 3:
        return None
    values = [_float_or_none(part) for part in parts[:3]]
    if any(value is None or value < 0 for value in values):
        return None
    return LoadAverage(values[0], values[1], values[2])


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def parse_filesystems(text: str) -> Tuple[FilesystemUsage, ...]:
    """Parse ``df`` output, normalising every size to bytes.

    coreutils ``df -T -B1`` reports bytes in seven columns; BusyBox ``df``
    reports 1K blocks in six.  The header decides which, so the multiplier is
    never guessed from the magnitude of the numbers.
    """

    lines = text.strip().splitlines()
    if not lines:
        return ()
    header = lines[0].lower()
    has_type = "type" in header
    multiplier = 1024 if ("1k-block" in header or "1024-block" in header) else 1
    rows: List[FilesystemUsage] = []
    for line in lines[1:]:
        parts = line.split()
        offset = 1 if has_type else 0
        if len(parts) < 6 + offset:
            continue
        device = parts[0]
        fstype = parts[1] if has_type else ""
        mount_point = " ".join(parts[5 + offset:])
        if device.lower() in _PSEUDO_FILESYSTEMS or fstype.lower() in _PSEUDO_FILESYSTEMS:
            continue
        if mount_point.startswith(_PSEUDO_MOUNT_PREFIXES):
            continue
        sizes = []
        for raw in parts[1 + offset:4 + offset]:
            value = _int_or_none(raw)
            sizes.append(None if value is None else value * multiplier)
        percent = _int_or_none(parts[4 + offset].rstrip("%"))
        rows.append(
            FilesystemUsage(
                device=device,
                mount_point=mount_point,
                fstype=fstype,
                size_bytes=sizes[0],
                used_bytes=sizes[1],
                available_bytes=sizes[2],
                use_percent=None if percent is None or percent > 100 else percent,
            )
        )
    return tuple(rows)


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

def parse_network_counters(text: str) -> Tuple[InterfaceCounters, ...]:
    """Parse ``/proc/net/dev`` cumulative byte counters.

    The kernel prints eight receive fields then eight transmit fields, so
    bytes are the first and ninth numeric columns.
    """

    counters: List[InterfaceCounters] = []
    for line in text.splitlines():
        match = re.match(
            r"\s*(\S+):\s*(\d+)(?:\s+\d+){7}\s+(\d+)",
            line,
        )
        if match:
            counters.append(
                InterfaceCounters(match.group(1), int(match.group(2)), int(match.group(3)))
            )
    return tuple(counters)


def parse_wireless_interfaces(text: str) -> set:
    """Names that have a ``wireless``/``phy80211`` node in sysfs.

    This is what actually makes an interface wireless. Interface names are not
    evidence: ``wlx…``, ``ath0``, ``ra0`` and plain ``eth1`` are all possible
    names for a radio, and ``wl…`` can equally be a bridge someone named that
    way.
    """

    names = set()
    for line in text.splitlines():
        match = re.match(r"^/sys/class/net/([^/]+)/(?:wireless|phy80211)", line.strip())
        if match:
            names.add(match.group(1))
    return names


def _interface_kind(name: str, flags: str, wireless: set) -> NetworkInterfaceKind:
    if "LOOPBACK" in flags:
        return NetworkInterfaceKind.LOOPBACK
    if name in wireless:
        return NetworkInterfaceKind.WIRELESS
    return NetworkInterfaceKind.ETHERNET


def _interface_state(flags: str) -> NetworkInterfaceState:
    if "NO-CARRIER" in flags:
        return NetworkInterfaceState.NO_CARRIER
    if "state UP" in flags:
        return NetworkInterfaceState.UP
    if "state DOWN" in flags:
        return NetworkInterfaceState.DOWN
    if "LOOPBACK" in flags and "UP" in flags:
        return NetworkInterfaceState.UP
    return NetworkInterfaceState.UNKNOWN


def parse_interfaces(
    link_text: str, addr_text: str, wireless_text: str = ""
) -> Tuple[NetworkInterface, ...]:
    addresses: Dict[str, Tuple[List[str], List[str]]] = {}
    for line in addr_text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] in ("inet", "inet6"):
            name = parts[1].split("@", 1)[0]
            ipv4, ipv6 = addresses.setdefault(name, ([], []))
            (ipv4 if parts[2] == "inet" else ipv6).append(parts[3])

    wireless = parse_wireless_interfaces(wireless_text)
    interfaces: List[NetworkInterface] = []
    for line in link_text.splitlines():
        match = re.match(r"^\d+:\s+(\S+?)(?:@\S+)?:\s*(.*)$", line)
        if not match:
            continue
        name, rest = match.group(1), match.group(2)
        mac_match = re.search(r"link/\S+\s+([0-9a-f:]{17})", rest)
        mtu_match = re.search(r"mtu\s+(\d+)", rest)
        ipv4, ipv6 = addresses.get(name, ([], []))
        interfaces.append(
            NetworkInterface(
                name=name,
                kind=_interface_kind(name, rest, wireless),
                state=_interface_state(rest),
                mac_address=mac_match.group(1) if mac_match else "",
                mtu=_int_or_none(mtu_match.group(1)) if mtu_match else None,
                ipv4_addresses=tuple(ipv4),
                ipv6_addresses=tuple(ipv6),
            )
        )
    return tuple(interfaces)


def parse_default_route(text: str) -> Tuple[str, str]:
    """Return ``(gateway, interface)`` from ``ip route show default``."""

    parts = text.split()
    gateway = ""
    interface = ""
    for index, token in enumerate(parts):
        if token == "via" and index + 1 < len(parts):
            gateway = parts[index + 1]
        elif token == "dev" and index + 1 < len(parts):
            interface = parts[index + 1]
    return gateway, interface


def parse_dns_servers(text: str) -> Tuple[str, ...]:
    servers = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("nameserver"):
            parts = stripped.split()
            if len(parts) >= 2:
                servers.append(parts[1])
    return tuple(servers)


def parse_ssh_connection_port(text: str) -> Optional[int]:
    """The server port from ``$SSH_CONNECTION``.

    sshd sets ``SSH_CONNECTION`` to ``<client ip> <client port> <server ip>
    <server port>`` for every session it starts, including a non-interactive
    exec. The fourth field is therefore the port this very probe arrived on --
    authoritative, whatever the host runs SSH on.
    """

    parts = text.split()
    if len(parts) < 4:
        return None
    port = _int_or_none(parts[3])
    return port if port is not None and 0 <= port <= 65535 else None


def _is_netstat(text: str) -> bool:
    return any(
        line.strip().startswith(("Proto", "Active"))
        for line in text.splitlines()[:2]
    )


def parse_listening_ports(text: str) -> Dict[int, str]:
    """Map each listening TCP port to the process name serving it.

    ``ss -tlnp`` prints ``users:(("sshd",pid=…))``; ``netstat -tlnp`` prints
    ``1234/sshd``.  Process names are only visible to root, so an empty name
    is normal and must not discard the port.
    """

    netstat = _is_netstat(text)
    ports: Dict[int, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] in ("Netid", "State", "Proto", "Active"):
            continue
        if netstat:
            if len(parts) < 6 or parts[5] != "LISTEN":
                continue
            local = parts[3]
            process = ""
            if len(parts) > 6:
                match = re.search(r"/(\S+)", parts[6])
                process = match.group(1) if match else ""
        else:
            if len(parts) < 5:
                continue
            local = parts[3]
            process = ""
            if len(parts) > 5:
                match = re.search(r'users:\(\("([^"]+)"', " ".join(parts[5:]))
                process = match.group(1) if match else ""
        port = _port_or_none(local)
        if port is not None:
            ports.setdefault(port, process)
    return ports


def _established_rows(text: str) -> List[Tuple[str, str, str, str]]:
    """Yield ``(protocol, local, peer, process)`` for established sockets.

    ``ss -tunap state established`` prints ``Netid Recv-Q Send-Q Local Peer
    Process`` — the explicit state filter removes the ``State`` column, so the
    local endpoint is column 3.  ``netstat -tunap`` prints ``Proto Recv-Q
    Send-Q Local Foreign State PID/Program`` with the same local column but a
    trailing state that must be filtered, because the netstat fallback lists
    listening and waiting sockets too.
    """

    netstat = _is_netstat(text)
    rows: List[Tuple[str, str, str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] in ("Netid", "State", "Proto", "Active"):
            continue
        protocol, local, peer = parts[0], parts[3], parts[4]
        if netstat:
            if len(parts) > 5 and parts[5] != "ESTABLISHED":
                continue
            process = ""
            if len(parts) > 6:
                match = re.search(r"/(\S+)", parts[6])
                process = match.group(1) if match else ""
        else:
            process = ""
            if len(parts) > 5:
                match = re.search(r'users:\(\("([^"]+)"', " ".join(parts[5:]))
                process = match.group(1) if match else ""
        rows.append((protocol, local, peer, process))
    return rows


def parse_sockets(
    text: str, listening_ports: Sequence[int] = ()
) -> Tuple[SocketConnection, ...]:
    """Classify established sockets by direction.

    A socket whose local port is one the host listens on is inbound; anything
    else is a connection this host opened.  Falling back to the privileged
    port range only matters when the listening probe produced nothing.
    """

    listening = set(listening_ports)
    sockets: List[SocketConnection] = []
    for protocol, local, peer, process in _established_rows(text):
        local_port = _port_or_none(local)
        if listening:
            incoming = local_port in listening
        else:
            incoming = local_port is not None and local_port < 1024
        sockets.append(
            SocketConnection(
                protocol=protocol,
                local_address=_strip_port(local),
                local_port=local_port,
                peer_address=_strip_port(peer),
                peer_port=_port_or_none(peer),
                process=process,
                direction=SocketDirection.INCOMING if incoming else SocketDirection.OUTGOING,
            )
        )
    return tuple(sockets)


# ---------------------------------------------------------------------------
# Login sessions
# ---------------------------------------------------------------------------

def parse_who(text: str) -> Tuple[LoginSession, ...]:
    sessions: List[LoginSession] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        rest = " ".join(parts[2:])
        origin = ""
        origin_match = re.search(r"\((.+)\)", rest)
        if origin_match:
            origin = origin_match.group(1)
            rest = rest[: origin_match.start()].strip()
        sessions.append(
            LoginSession(
                user=parts[0],
                tty=parts[1],
                origin="" if origin in _LOCAL_ORIGINS else origin,
                since=rest,
                remote=origin not in _LOCAL_ORIGINS,
            )
        )
    return tuple(sessions)


def parse_w(text: str) -> Tuple[LoginSession, ...]:
    """Parse ``w -h`` (``USER TTY FROM LOGIN@ IDLE JCPU PCPU WHAT``)."""

    sessions: List[LoginSession] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        origin = parts[2]
        sessions.append(
            LoginSession(
                user=parts[0],
                tty=parts[1],
                origin="" if origin in _LOCAL_ORIGINS else origin,
                since=parts[3],
                remote=origin not in _LOCAL_ORIGINS,
            )
        )
    return tuple(sessions)


def sessions_from_sockets(
    sockets: Sequence[SocketConnection], ssh_ports: Sequence[int]
) -> Tuple[LoginSession, ...]:
    """Reconstruct remote logins from inbound SSH sockets.

    BusyBox hosts ship neither ``who`` nor ``w``, so the only evidence a user
    is connected is an established socket on a port the host's SSH server
    listens on.  The peer address is the login origin; the account name is not
    knowable this way and stays empty.
    """

    wanted = set(ssh_ports)
    if not wanted:
        return ()
    seen: set = set()
    sessions: List[LoginSession] = []
    for socket in sockets:
        if socket.direction is not SocketDirection.INCOMING:
            continue
        if socket.local_port not in wanted or not socket.peer_address:
            continue
        if socket.peer_address in seen:
            continue
        seen.add(socket.peer_address)
        sessions.append(
            LoginSession(user="", tty="", origin=socket.peer_address, since="", remote=True)
        )
    return tuple(sessions)


# ---------------------------------------------------------------------------
# Temperatures
# ---------------------------------------------------------------------------

def parse_thermal_zones(temps_text: str, types_text: str) -> Tuple[TemperatureReading, ...]:
    readings: Dict[str, int] = {}
    for line in temps_text.splitlines():
        match = re.match(r".*/thermal_zone(\d+)/temp:(-?\d+)", line)
        if match:
            readings[match.group(1)] = int(match.group(2))
    labels: Dict[str, str] = {}
    for line in types_text.splitlines():
        match = re.match(r".*/thermal_zone(\d+)/type:(.+)", line)
        if match:
            labels[match.group(1)] = match.group(2).strip()
    return tuple(
        TemperatureReading(labels.get(zone, f"thermal_zone{zone}"), readings[zone] / 1000.0)
        for zone in sorted(readings, key=lambda item: int(item))
    )


def parse_sensors(text: str) -> Tuple[TemperatureReading, ...]:
    """Parse ``sensors`` output for hosts without ``/sys/class/thermal``."""

    readings: List[TemperatureReading] = []
    adapter = ""
    for line in text.splitlines():
        if not line.strip() or line.startswith("Adapter:"):
            continue
        if not line[:1].isspace() and ":" not in line:
            adapter = line.strip()
            continue
        match = re.match(r"^(.+?):\s+\+?(-?[\d.]+)\s*°?C", line)
        if match:
            label = match.group(1).strip()
            readings.append(
                TemperatureReading(
                    f"{adapter} · {label}" if adapter else label, float(match.group(2))
                )
            )
    return tuple(readings)


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

def _boot_time(sections: Dict[str, str]) -> str:
    who_b = sections.get("BOOT_TIME", "").strip()
    if who_b:
        parts = who_b.split()
        if len(parts) >= 3:
            return " ".join(parts[-2:])
    return sections.get("UPTIME_SINCE", "").strip()


def parse_host_info(raw: str) -> HostInfoSnapshot:
    """Parse one full probe into a snapshot; absent sections stay empty."""

    sections = split_sections(raw)

    listening = parse_listening_ports(sections.get("SS_LISTEN", ""))
    # Prefer the port the probe itself arrived on, then any port sshd is seen
    # listening on. There is deliberately no fallback to 22: reporting nothing
    # is honest, while guessing 22 is wrong on every host that moved the port.
    session_port = parse_ssh_connection_port(sections.get("SSH_CONNECTION", ""))
    ssh_ports = [session_port] if session_port is not None else []
    ssh_ports.extend(
        port
        for port, process in sorted(listening.items())
        if process == "sshd" and port != session_port
    )
    sockets = parse_sockets(sections.get("SS_ESTAB", ""), tuple(listening))

    sessions = parse_who(sections.get("WHO", ""))
    if not sessions:
        sessions = parse_w(sections.get("W", ""))
    if not sessions:
        sessions = sessions_from_sockets(sockets, ssh_ports)

    temperatures = parse_thermal_zones(
        sections.get("TEMPS", ""), sections.get("TEMP_TYPES", "")
    )
    if not temperatures:
        temperatures = parse_sensors(sections.get("SENSORS", ""))

    gateway, gateway_interface = parse_default_route(sections.get("IP_ROUTE", ""))
    uptime = _float_or_none(sections.get("UPTIME", "").split()[0]) if sections.get(
        "UPTIME", ""
    ).split() else None

    return HostInfoSnapshot(
        hostname=sections.get("HOSTNAME", "").strip(),
        device_model=sections.get("DEVICE_MODEL", "").strip(),
        os_pretty_name=parse_os_release(sections.get("OS_RELEASE", "")).get(
            "PRETTY_NAME", ""
        ),
        kernel=sections.get("UNAME", "").strip(),
        uptime_seconds=uptime if uptime is not None and uptime >= 0 else None,
        boot_time=_boot_time(sections),
        cpu=parse_cpu(
            sections.get("LSCPU", ""),
            sections.get("CPUINFO", ""),
            sections.get("NPROC", ""),
        ),
        memory=parse_meminfo(sections.get("MEMINFO", "")),
        load_average=parse_load_average(sections.get("LOADAVG", "")),
        filesystems=parse_filesystems(sections.get("DF", "")),
        interfaces=parse_interfaces(
            sections.get("IP_LINK", ""),
            sections.get("IP_ADDR", ""),
            sections.get("WIRELESS", ""),
        ),
        temperatures=temperatures,
        sessions=sessions,
        sockets=sockets,
        default_gateway=gateway,
        default_gateway_interface=gateway_interface,
        dns_servers=parse_dns_servers(sections.get("DNS", "")),
        ssh_port=ssh_ports[0] if ssh_ports else None,
        ssh_process=listening.get(ssh_ports[0], "") if ssh_ports else "",
    )


def parse_counters_probe(raw: str) -> Tuple[InterfaceCounters, ...]:
    """Parse the lightweight bandwidth probe."""

    return parse_network_counters(split_sections(raw).get("NET_DEV", ""))
