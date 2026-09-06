"""Host Info dialog — remote host system information."""

from __future__ import annotations

import logging
import math
import re
import time
from datetime import datetime, timezone
from gettext import gettext as _
from typing import Any, Dict, List, Optional, Tuple

from gi.repository import Adw, GLib, Gtk, Gdk, Pango

try:
    import cairo
except ImportError:
    cairo = None

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Gather command — every section delimited by a unique marker
# ---------------------------------------------------------------------------

_GATHER_CMD = (
    'echo "===HOSTNAME==="; hostname 2>/dev/null;'
    'echo "===OS_RELEASE==="; cat /etc/os-release 2>/dev/null;'
    'echo "===UNAME==="; uname -srm 2>/dev/null;'
    'echo "===UPTIME==="; cat /proc/uptime 2>/dev/null;'
    'echo "===UPTIME_PRETTY==="; uptime -p 2>/dev/null;'
    'echo "===BOOT_TIME==="; who -b 2>/dev/null;'
    'echo "===UPTIME_SINCE==="; uptime -s 2>/dev/null;'
    'echo "===LOADAVG==="; cat /proc/loadavg 2>/dev/null;'
    'echo "===NPROC==="; nproc 2>/dev/null;'
    'echo "===LSCPU==="; lscpu 2>/dev/null;'
    'echo "===MEMINFO==="; cat /proc/meminfo 2>/dev/null;'
    'echo "===DF==="; df -T -B1 -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null;'
    'echo "===NET_DEV==="; cat /proc/net/dev 2>/dev/null;'
    'echo "===IP_ADDR==="; ip -o addr show 2>/dev/null;'
    'echo "===IP_LINK==="; ip -o link show 2>/dev/null;'
    'echo "===IP_ROUTE==="; ip route show default 2>/dev/null;'
    'echo "===DNS==="; cat /etc/resolv.conf 2>/dev/null;'
    'echo "===SS_LISTEN==="; ss -tlnp 2>/dev/null;'
    'echo "===SS_ESTAB==="; ss -tunap state established 2>/dev/null;'
    'echo "===WHO==="; who 2>/dev/null;'
    'echo "===W==="; w -h 2>/dev/null;'
    'echo "===TEMPS==="; for f in /sys/class/thermal/thermal_zone*/temp; do echo "$f:$(cat "$f" 2>/dev/null)"; done 2>/dev/null;'
    'echo "===TEMP_TYPES==="; for f in /sys/class/thermal/thermal_zone*/type; do echo "$f:$(cat "$f" 2>/dev/null)"; done 2>/dev/null;'
    'echo "===CPU_FREQ==="; cat /proc/cpuinfo 2>/dev/null | grep -i "cpu mhz" | head -1;'
    'echo "===CPU_STAT==="; head -1 /proc/stat 2>/dev/null;'
    'echo "===APT_UPGRADABLE==="; apt list --upgradable 2>/dev/null | tail -n +2 | wc -l;'
    'echo "===APT_SECURITY==="; apt list --upgradable 2>/dev/null | grep -ci security;'
    'echo "===REBOOT_REQ==="; cat /var/run/reboot-required 2>/dev/null || echo "no";'
    'echo "===APT_STAMP==="; stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null;'
    'echo "===END===";'
)

_TRAFFIC_CMD = 'cat /proc/net/dev 2>/dev/null'

# Accent colours matching the design
_BLUE = (0.208, 0.518, 0.894)      # #3584e4
_AMBER = (0.898, 0.647, 0.039)     # #e5a50a
_GREEN = (0.180, 0.761, 0.494)     # #2ec27e
_RED = (0.878, 0.106, 0.141)       # #e01b24
_PURPLE = (0.569, 0.255, 0.675)    # #9141ac
_TRACK = (0.0, 0.0, 0.0, 0.09)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_sections(raw: str) -> Dict[str, str]:
    sections: Dict[str, str] = {}
    current_key: Optional[str] = None
    current_lines: List[str] = []
    for line in raw.splitlines():
        m = re.match(r'^===([A-Z_]+)===$', line)
        if m:
            if current_key is not None:
                sections[current_key] = '\n'.join(current_lines).strip()
            current_key = m.group(1)
            current_lines = []
        elif current_key is not None:
            current_lines.append(line)
    if current_key is not None:
        sections[current_key] = '\n'.join(current_lines).strip()
    return sections


def _parse_os_release(text: str) -> Dict[str, str]:
    d: Dict[str, str] = {}
    for line in text.splitlines():
        if '=' in line:
            k, _, v = line.partition('=')
            d[k.strip()] = v.strip().strip('"')
    return d


def _parse_meminfo(text: str) -> Dict[str, int]:
    d: Dict[str, int] = {}
    for line in text.splitlines():
        m = re.match(r'^(\w+):\s+(\d+)', line)
        if m:
            d[m.group(1)] = int(m.group(2)) * 1024  # kB → bytes
    return d


def _parse_lscpu(text: str) -> Dict[str, str]:
    d: Dict[str, str] = {}
    for line in text.splitlines():
        if ':' in line:
            k, _, v = line.partition(':')
            d[k.strip()] = v.strip()
    return d


def _parse_df(text: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    lines = text.strip().splitlines()
    if not lines:
        return rows
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 7:
            rows.append({
                'fs': parts[0],
                'type': parts[1],
                'size': parts[2],
                'used': parts[3],
                'avail': parts[4],
                'pct': parts[5].rstrip('%'),
                'mount': ' '.join(parts[6:]),
            })
    return rows


def _parse_net_dev(text: str) -> Dict[str, Tuple[int, int]]:
    result: Dict[str, Tuple[int, int]] = {}
    for line in text.splitlines():
        m = re.match(r'\s*(\S+):\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)', line)
        if m:
            result[m.group(1)] = (int(m.group(2)), int(m.group(3)))
    return result


def _parse_ip_addr(text: str) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] in ('inet', 'inet6'):
            entries.append({
                'iface': parts[1],
                'family': parts[2],
                'addr': parts[3],
            })
    return entries


def _parse_ip_link(text: str) -> Dict[str, Dict[str, str]]:
    result: Dict[str, Dict[str, str]] = {}
    for line in text.splitlines():
        m = re.match(r'^\d+:\s+(\S+?)(?:@\S+)?:', line)
        if not m:
            continue
        iface = m.group(1)
        info: Dict[str, str] = {}
        mac_m = re.search(r'link/\S+\s+([\da-f:]{17})', line)
        if mac_m:
            info['mac'] = mac_m.group(1)
        if 'NO-CARRIER' in line:
            info['state'] = 'no-carrier'
        elif 'state UP' in line:
            info['state'] = 'up'
        elif 'state DOWN' in line:
            info['state'] = 'down'
        elif 'LOOPBACK' in line:
            info['state'] = 'loopback'
        mtu_m = re.search(r'mtu\s+(\d+)', line)
        if mtu_m:
            info['mtu'] = mtu_m.group(1)
        if 'LOOPBACK' in line:
            info['type'] = 'loopback'
        elif 'wl' in iface.lower() or 'wifi' in line.lower() or 'BROADCAST' in line and 'wl' in iface:
            info['type'] = 'wifi'
        else:
            info['type'] = 'ethernet'
        result[iface] = info
    return result


def _parse_who(text: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            row: Dict[str, str] = {'user': parts[0], 'tty': parts[1]}
            rest = ' '.join(parts[2:])
            paren_m = re.search(r'\((.+)\)', rest)
            if paren_m:
                row['from'] = paren_m.group(1)
                rest = rest[:paren_m.start()].strip()
            row['since'] = rest
            rows.append(row)
    return rows


def _parse_w(text: str) -> List[Dict[str, str]]:
    """Parse `w -h` output as a fallback when `who` returns nothing."""
    rows: List[Dict[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            row: Dict[str, str] = {
                'user': parts[0],
                'tty': parts[1],
                'from': parts[2] if len(parts) > 3 else '',
                'since': parts[3] if len(parts) > 3 else parts[2],
            }
            rows.append(row)
    return rows


def _ssh_sessions_from_ss(ss_text: str) -> List[Dict[str, str]]:
    """Extract SSH client sessions from ss established connections."""
    rows: List[Dict[str, str]] = []
    seen: set = set()
    for line in ss_text.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] in ('Netid', 'State'):
            continue
        local = parts[4] if len(parts) > 4 else ''
        peer = parts[5] if len(parts) > 5 else ''
        lm = re.search(r':(\d+)$', local)
        if not lm or lm.group(1) != '22':
            continue
        peer_addr = re.sub(r':\d+$', '', peer)
        if peer_addr in seen:
            continue
        seen.add(peer_addr)
        proc = ''
        rest = ' '.join(parts[6:])
        proc_m = re.search(r'users:\(\("([^"]+)"', rest)
        if proc_m:
            proc = proc_m.group(1)
        rows.append({
            'user': proc or 'sshd',
            'tty': 'ssh',
            'from': peer_addr,
            'since': '',
        })
    return rows


def _parse_ss_estab(text: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] in ('Netid', 'State'):
            continue
        row = {
            'proto': parts[0],
            'local': parts[3] if len(parts) > 3 else '',
            'peer': parts[4] if len(parts) > 4 else '',
        }
        if len(parts) > 5:
            proc_m = re.search(r'users:\(\("([^"]+)"', parts[5])
            row['proc'] = proc_m.group(1) if proc_m else ''
        else:
            row['proc'] = ''
        rows.append(row)
    return rows


def _parse_temps(text: str, types_text: str) -> List[Dict[str, Any]]:
    temps: Dict[str, int] = {}
    for line in text.splitlines():
        m = re.match(r'.*/thermal_zone(\d+)/temp:(\d+)', line)
        if m:
            temps[m.group(1)] = int(m.group(2))
    labels: Dict[str, str] = {}
    for line in types_text.splitlines():
        m = re.match(r'.*/thermal_zone(\d+)/type:(.+)', line)
        if m:
            labels[m.group(1)] = m.group(2).strip()
    result: List[Dict[str, Any]] = []
    for zone in sorted(temps):
        result.append({
            'label': labels.get(zone, f'zone{zone}'),
            'temp_c': temps[zone] / 1000.0,
        })
    return result


def _fmt_bytes(n: float) -> str:
    if n < 1024:
        return f"{n:.0f} B"
    for unit in ('KiB', 'MiB', 'GiB', 'TiB'):
        n /= 1024
        if n < 1024:
            return f"{n:.1f} {unit}" if n < 100 else f"{n:.0f} {unit}"
    return f"{n:.1f} PiB"


def _fmt_bytes_rate(n: float) -> str:
    if n < 1024:
        return f"{n:.0f} B/s"
    for unit in ('KiB/s', 'MiB/s', 'GiB/s'):
        n /= 1024
        if n < 1024:
            return f"{n:.1f} {unit}" if n < 100 else f"{n:.0f} {unit}"
    return f"{n:.1f} TiB/s"


def _fmt_bytes_si(n: float) -> str:
    if n < 1000:
        return f"{n:.0f} B"
    for unit in ('KB', 'MB', 'GB', 'TB'):
        n /= 1000
        if n < 1000:
            return f"{n:.1f} {unit}" if n < 100 else f"{n:.0f} {unit}"
    return f"{n:.1f} PB"


def _fmt_uptime_seconds(secs: float) -> str:
    days = int(secs // 86400)
    hours = int((secs % 86400) // 3600)
    minutes = int((secs % 3600) // 60)
    parts = []
    if days:
        parts.append(f"{days} {'day' if days == 1 else 'days'}")
    if hours:
        parts.append(f"{hours} {'hour' if hours == 1 else 'hours'}")
    if minutes:
        parts.append(f"{minutes} {'minute' if minutes == 1 else 'minutes'}")
    return ', '.join(parts) or '< 1 minute'


# ---------------------------------------------------------------------------
# Donut gauge drawing
# ---------------------------------------------------------------------------

def _draw_donut(area, cr, width, height, fraction, color_rgb, label):
    """Draw a donut-chart gauge with a percentage label in the centre."""
    cx, cy = width / 2, height / 2
    radius = min(cx, cy) - 6
    line_w = max(8, radius * 0.22)

    cr.set_line_width(line_w)
    cr.set_line_cap(1)  # ROUND

    cr.set_source_rgba(*_TRACK)
    cr.arc(cx, cy, radius, 0, 2 * math.pi)
    cr.stroke()

    if fraction > 0:
        cr.set_source_rgb(*color_rgb)
        start = -math.pi / 2
        cr.arc(cx, cy, radius, start, start + 2 * math.pi * min(fraction, 1.0))
        cr.stroke()

    pct_text = f"{int(round(fraction * 100))}%"
    cr.set_source_rgb(0.18, 0.20, 0.21)
    cr.select_font_face("Cantarell", 0, 1)
    cr.set_font_size(max(16, radius * 0.5))
    ext = cr.text_extents(pct_text)
    cr.move_to(cx - ext.width / 2 - ext.x_bearing,
               cy - ext.height / 2 - ext.y_bearing)
    cr.show_text(pct_text)


# ---------------------------------------------------------------------------
# Widget helpers
# ---------------------------------------------------------------------------

def _card_box() -> Gtk.Box:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    box.add_css_class("card")
    return box


def _section_label(text: str) -> Gtk.Label:
    label = Gtk.Label(label=text)
    label.set_xalign(0)
    label.add_css_class("heading")
    label.set_opacity(0.65)
    label.add_css_class("caption")
    return label


def _kv_row(key: str, value: str, *, mono: bool = False,
            last: bool = False) -> Gtk.Box:
    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
    row.set_margin_start(16)
    row.set_margin_end(16)
    row.set_margin_top(12)
    row.set_margin_bottom(12)

    key_label = Gtk.Label(label=key)
    key_label.set_xalign(0)
    key_label.set_opacity(0.6)
    key_label.set_size_request(200, -1)
    row.append(key_label)

    val_label = Gtk.Label(label=value)
    val_label.set_xalign(0)
    val_label.set_hexpand(True)
    val_label.set_wrap(True)
    val_label.set_selectable(True)
    if mono:
        val_label.add_css_class("monospace")
    row.append(val_label)

    wrapper = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    wrapper.append(row)
    if not last:
        sep = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        wrapper.append(sep)
    return wrapper


def _progress_bar_box(fraction: float, color_hex: str,
                      height: int = 8) -> Gtk.Box:
    outer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
    outer.set_hexpand(True)

    bar = Gtk.LevelBar()
    bar.set_min_value(0)
    bar.set_max_value(1.0)
    bar.set_value(min(max(fraction, 0), 1.0))
    bar.set_hexpand(True)
    bar.set_valign(Gtk.Align.CENTER)
    bar.set_size_request(-1, height)
    bar.add_css_class("machine-info-bar")
    outer.append(bar)
    return outer


def _mono_label(text: str) -> Gtk.Label:
    label = Gtk.Label(label=text)
    label.add_css_class("monospace")
    label.set_selectable(True)
    return label


# ---------------------------------------------------------------------------
# Main dialog
# ---------------------------------------------------------------------------

class MachineInfoDialog:
    """System information dialog for a remote SSH host."""

    def __init__(self, window, connection) -> None:
        self._window = window
        self._connection = connection
        self._data: Dict[str, str] = {}
        self._last_refresh: float = 0
        self._age_timer_id: int = 0
        self._traffic_timer_id: int = 0
        self._prev_net_dev: Optional[Dict[str, Tuple[int, int]]] = None
        self._prev_net_time: float = 0
        self._closed = False

        self._dialog = Adw.Dialog()
        self._dialog.set_content_width(900)
        self._dialog.set_content_height(716)

        toolbar = Adw.ToolbarView()
        self._header = self._build_header()
        toolbar.add_top_bar(self._header)

        self._body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self._body.set_vexpand(True)

        self._stack = None
        self._switcher_box = None
        self._content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self._content_box.set_vexpand(True)

        self._body.append(self._content_box)
        toolbar.set_content(self._body)

        self._dialog.set_child(toolbar)
        self._dialog.connect('closed', self._on_closed)

        self._show_spinner()
        self._dialog.present(window)

        self._run_gather()

    # ── Header ─────────────────────────────────────────────────────────

    def _build_header(self) -> Adw.HeaderBar:
        header = Adw.HeaderBar()
        header.set_show_start_title_buttons(False)
        header.set_show_end_title_buttons(False)

        icon = Gtk.Image.new_from_icon_name('info-outline-symbolic')
        icon.set_opacity(0.65)

        title_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        title_row.set_halign(Gtk.Align.CENTER)
        title_row.set_valign(Gtk.Align.CENTER)
        title_row.append(icon)

        title_col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        title_label = Gtk.Label(label=_("Host Info"))
        title_label.add_css_class("title")
        title_col.append(title_label)

        nickname = getattr(self._connection, 'nickname', '') or ''
        user = getattr(self._connection, 'username', '') or ''
        host = getattr(self._connection, 'host', '') or ''
        subtitle = nickname
        if user and host:
            subtitle = f"{nickname} — {user}@{host}"
        elif host:
            subtitle = f"{nickname} — {host}"
        self._subtitle_label = Gtk.Label(label=subtitle)
        self._subtitle_label.add_css_class("subtitle")
        self._subtitle_label.set_opacity(0.55)
        title_col.append(self._subtitle_label)

        title_row.append(title_col)
        header.set_title_widget(title_row)

        close_btn = Gtk.Button()
        close_btn.set_icon_name('window-close-symbolic')
        close_btn.add_css_class("circular")
        close_btn.set_tooltip_text(_("Close"))
        close_btn.connect('clicked', lambda _b: self._dialog.close())
        header.pack_end(close_btn)

        refresh_btn = Gtk.Button()
        refresh_btn.set_icon_name('view-refresh-symbolic')
        refresh_btn.set_label(_("Refresh"))
        refresh_btn.set_tooltip_text(_("Refresh host information"))
        refresh_btn.connect('clicked', lambda _b: self._on_refresh())
        self._refresh_btn = refresh_btn
        header.pack_end(refresh_btn)

        self._age_label = Gtk.Label(label="")
        self._age_label.add_css_class("dim-label")
        self._age_label.add_css_class("caption")
        header.pack_end(self._age_label)

        return header

    # ── Spinner / placeholder ──────────────────────────────────────────

    def _clear_content(self):
        child = self._content_box.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self._content_box.remove(child)
            child = nxt

    def _show_spinner(self):
        self._clear_content()
        center = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        center.set_valign(Gtk.Align.CENTER)
        center.set_vexpand(True)
        spinner = Gtk.Spinner()
        spinner.set_size_request(32, 32)
        spinner.start()
        center.append(spinner)
        center.append(Gtk.Label(label=_("Gathering host information…")))
        self._content_box.append(center)

    def _show_error(self, message: str):
        self._clear_content()
        center = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        center.set_valign(Gtk.Align.CENTER)
        center.set_vexpand(True)
        center.set_margin_start(24)
        center.set_margin_end(24)
        lbl = Gtk.Label(label=message)
        lbl.set_wrap(True)
        lbl.set_justify(Gtk.Justification.CENTER)
        lbl.add_css_class("dim-label")
        center.append(lbl)
        self._content_box.append(center)

    # ── Data gathering ─────────────────────────────────────────────────

    def _run_gather(self, traffic_only: bool = False):
        client = getattr(self._window, 'client', None)
        bridge = getattr(self._window, 'client_bridge', None)
        if client is None or bridge is None:
            self._show_error(_("Daemon connection unavailable."))
            return

        cmd = _TRAFFIC_CMD if traffic_only else _GATHER_CMD
        conn = self._connection

        def _execute():
            from .api.models.broadcast import (
                BroadcastCommandRequest,
                BroadcastExecutionPolicy,
            )
            from .api.models.interactions import ExecutionInteractionMode

            daemon_conn = next(
                (item for item in client.list_connections()
                 if getattr(item, 'nickname', None)
                 == getattr(conn, 'nickname', None)),
                None,
            )
            if daemon_conn is None:
                raise RuntimeError(
                    f"Connection '{getattr(conn, 'nickname', '?')}' "
                    "not found in daemon"
                )

            policy = BroadcastExecutionPolicy(
                concurrency_limit=1,
                timeout_seconds=30,
                interaction_mode=ExecutionInteractionMode.AUTOFILL_ONLY,
            )
            request = BroadcastCommandRequest(
                (daemon_conn.id,), cmd, policy,
            )
            summary = client.start_broadcast_command(request)

            terminal_states = {'succeeded', 'failed', 'cancelled'}
            deadline = time.monotonic() + 30
            while summary.operation.state.value not in terminal_states:
                if time.monotonic() >= deadline:
                    try:
                        client.cancel_broadcast_command(
                            summary.operation.operation_id)
                    except Exception:
                        pass
                    raise TimeoutError("Timed out gathering host info")
                time.sleep(0.1)
                summary = client.get_broadcast_command(
                    summary.operation.operation_id)

            target = summary.targets[0] if summary.targets else None
            if target is None or target.exit_code is None:
                raise RuntimeError("No output from remote host")
            return target.stdout or ''

        if traffic_only:
            bridge.submit(
                _execute,
                on_success=self._on_traffic_data,
                on_error=lambda e: logger.debug(
                    "Traffic poll failed: %s", e),
            )
        else:
            bridge.submit(
                _execute,
                on_success=self._on_data,
                on_error=self._on_error,
            )

    def _on_data(self, raw_output: str):
        if self._closed:
            return
        self._data = _parse_sections(raw_output)
        self._last_refresh = time.monotonic()
        self._build_tabs()
        self._start_age_timer()

    def _on_error(self, error: BaseException):
        if self._closed:
            return
        logger.warning("Machine info gather failed: %s", error)
        self._show_error(
            _("Could not gather host information.\n\n%s") % str(error))

    def _on_refresh(self):
        self._refresh_btn.set_sensitive(False)
        self._stop_traffic_timer()
        self._show_spinner()
        self._run_gather()

    def _on_traffic_data(self, raw_output: str):
        if self._closed:
            return
        new_dev = _parse_net_dev(raw_output)
        now = time.monotonic()
        if self._prev_net_dev is not None and self._traffic_content is not None:
            dt = now - self._prev_net_time
            if dt > 0:
                self._update_traffic_rates(self._prev_net_dev, new_dev, dt)
        self._prev_net_dev = new_dev
        self._prev_net_time = now

    # ── Age timer ──────────────────────────────────────────────────────

    def _start_age_timer(self):
        if self._age_timer_id:
            GLib.source_remove(self._age_timer_id)
        self._update_age_label()
        self._age_timer_id = GLib.timeout_add_seconds(1, self._tick_age)

    def _tick_age(self) -> bool:
        if self._closed:
            return False
        self._update_age_label()
        return True

    def _update_age_label(self):
        if not self._last_refresh:
            self._age_label.set_text("")
            return
        elapsed = int(time.monotonic() - self._last_refresh)
        if elapsed < 60:
            self._age_label.set_text(
                _("Updated %d s ago") % elapsed)
        else:
            mins = elapsed // 60
            self._age_label.set_text(
                _("Updated %d min ago") % mins)

    def _get_logged_in_users(self) -> List[Dict[str, str]]:
        rows = _parse_who(self._data.get('WHO', ''))
        if not rows:
            rows = _parse_w(self._data.get('W', ''))
        if not rows:
            rows = _ssh_sessions_from_ss(self._data.get('SS_ESTAB', ''))
        return rows

    # ── Traffic polling ────────────────────────────────────────────────

    def _start_traffic_timer(self):
        if self._traffic_timer_id:
            return
        self._prev_net_dev = _parse_net_dev(
            self._data.get('NET_DEV', ''))
        self._prev_net_time = time.monotonic()
        self._traffic_timer_id = GLib.timeout_add(2000, self._tick_traffic)

    def _stop_traffic_timer(self):
        if self._traffic_timer_id:
            GLib.source_remove(self._traffic_timer_id)
            self._traffic_timer_id = 0
        self._prev_net_dev = None

    def _tick_traffic(self) -> bool:
        if self._closed:
            return False
        self._run_gather(traffic_only=True)
        return True

    # ── Cleanup ────────────────────────────────────────────────────────

    def _on_closed(self, *_args):
        self._closed = True
        if self._age_timer_id:
            GLib.source_remove(self._age_timer_id)
            self._age_timer_id = 0
        self._stop_traffic_timer()

    # ── Tab construction ───────────────────────────────────────────────

    def _build_tabs(self):
        self._clear_content()
        self._refresh_btn.set_sensitive(True)

        self._traffic_content = None

        pages = [
            ('overview', _("Overview"), self._build_overview()),
            ('resources', _("Resources"), self._build_resources()),
            ('storage', _("Storage"), self._build_storage()),
            ('network', _("Network"), self._build_network()),
            ('traffic', _("Traffic"), self._build_traffic()),
            ('system', _("System"), self._build_system()),
        ]

        stack = Adw.ViewStack()
        stack.set_vexpand(True)
        self._stack = stack

        for name, title, widget in pages:
            scrolled = Gtk.ScrolledWindow()
            scrolled.set_policy(Gtk.PolicyType.NEVER,
                                Gtk.PolicyType.AUTOMATIC)
            scrolled.set_vexpand(True)
            scrolled.set_child(widget)
            stack.add_titled(scrolled, name, title)

        use_inline = hasattr(Adw, 'InlineViewSwitcher')
        if use_inline:
            switcher = Adw.InlineViewSwitcher()
            switcher.set_stack(stack)
            switcher.set_hexpand(True)
            switcher.set_halign(Gtk.Align.FILL)
            try:
                switcher.set_display_mode(
                    Adw.InlineViewSwitcherDisplayMode.LABELS)
            except Exception:
                pass
        else:
            switcher = Gtk.StackSwitcher(stack=stack)
            switcher.set_halign(Gtk.Align.CENTER)

        switcher_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        switcher_card.add_css_class("card")
        switcher_card.set_hexpand(True)
        switcher_card.set_margin_start(24)
        switcher_card.set_margin_end(24)
        switcher_card.set_margin_top(12)
        switcher_card.append(switcher)

        container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        container.set_vexpand(True)
        container.append(switcher_card)
        container.append(stack)

        self._content_box.append(container)

        stack.connect('notify::visible-child-name',
                      self._on_tab_changed)

    def _on_tab_changed(self, stack, _pspec):
        name = stack.get_visible_child_name()
        if name == 'traffic':
            self._start_traffic_timer()
        else:
            self._stop_traffic_timer()

    # ── Overview tab ───────────────────────────────────────────────────

    def _build_overview(self) -> Gtk.Box:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        page.set_margin_top(18)
        page.set_margin_bottom(24)
        page.set_margin_start(24)
        page.set_margin_end(24)

        mem = _parse_meminfo(self._data.get('MEMINFO', ''))
        mem_total = mem.get('MemTotal', 1)
        mem_used = mem_total - mem.get('MemAvailable', mem_total)
        mem_frac = mem_used / mem_total if mem_total else 0

        df_rows = _parse_df(self._data.get('DF', ''))
        root_row = next((r for r in df_rows if r['mount'] == '/'), None)
        root_frac = 0.0
        root_used_str = root_size_str = root_type_str = ''
        if root_row:
            try:
                size = int(root_row['size'])
                used = int(root_row['used'])
                root_frac = used / size if size else 0
                root_used_str = _fmt_bytes_si(used)
                root_size_str = _fmt_bytes_si(size)
            except (ValueError, ZeroDivisionError):
                pass
            root_type_str = root_row.get('type', '')

        loadavg = self._data.get('LOADAVG', '').split()
        nproc = 1
        try:
            nproc = int(self._data.get('NPROC', '1'))
        except ValueError:
            pass
        cpu_load = 0.0
        if loadavg:
            try:
                cpu_load = float(loadavg[0]) / nproc
            except (ValueError, IndexError):
                pass

        freq_text = ''
        freq_line = self._data.get('CPU_FREQ', '')
        m = re.search(r'([\d.]+)', freq_line)
        if m:
            try:
                freq_text = f"{float(m.group(1)) / 1000:.2f} GHz"
            except ValueError:
                freq_text = f"{m.group(1)} MHz"

        gauges = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        gauges.set_homogeneous(True)

        cpu_color = _RED if cpu_load > 0.85 else _BLUE
        gauges.append(self._gauge_card(
            cpu_load, cpu_color, _("CPU"), freq_text,
            _("load %s") % ' · '.join(loadavg[:3]) if loadavg else ''))

        mem_color = _RED if mem_frac > 0.85 else _AMBER
        swap_total = mem.get('SwapTotal', 0)
        swap_free = mem.get('SwapFree', 0)
        swap_used = swap_total - swap_free
        swap_text = ''
        if swap_total:
            swap_text = _("swap %s / %s") % (
                _fmt_bytes(swap_used), _fmt_bytes(swap_total))
        gauges.append(self._gauge_card(
            mem_frac, mem_color, _("Memory"),
            f"{_fmt_bytes(mem_used)} / {_fmt_bytes(mem_total)}",
            swap_text))

        root_color = _RED if root_frac > 0.85 else _GREEN
        root_dev = ''
        if root_row:
            root_dev = f"{root_row.get('type', '')} on {root_row.get('fs', '')}"
        gauges.append(self._gauge_card(
            root_frac, root_color, _("Root filesystem"),
            f"{root_used_str} / {root_size_str}" if root_used_str else '',
            root_dev))

        page.append(gauges)

        # Identity card
        identity_label = _section_label(_("Identity"))
        page.append(identity_label)

        identity_card = _card_box()

        hostname = self._data.get('HOSTNAME', '').strip()
        identity_card.append(_kv_row(_("Hostname"), hostname, mono=True))

        osr = _parse_os_release(self._data.get('OS_RELEASE', ''))
        os_text = osr.get('PRETTY_NAME', '')
        identity_card.append(_kv_row(_("Operating system"), os_text))

        uname = self._data.get('UNAME', '').strip()
        identity_card.append(_kv_row(_("Kernel"), uname, mono=True))

        uptime_secs = 0.0
        uptime_raw = self._data.get('UPTIME', '').strip()
        if uptime_raw:
            try:
                uptime_secs = float(uptime_raw.split()[0])
            except (ValueError, IndexError):
                pass
        uptime_pretty = self._data.get('UPTIME_PRETTY', '').strip()
        if uptime_pretty.startswith('up '):
            uptime_pretty = uptime_pretty[3:]
        if not uptime_pretty and uptime_secs:
            uptime_pretty = _fmt_uptime_seconds(uptime_secs)
        identity_card.append(_kv_row(_("Uptime"), uptime_pretty))

        boot_time = self._data.get('BOOT_TIME', '').strip()
        boot_text = ''
        if boot_time:
            parts = boot_time.split()
            if len(parts) >= 3:
                boot_text = ' '.join(parts[-2:])
        if not boot_text:
            boot_text = self._data.get('UPTIME_SINCE', '').strip()
        identity_card.append(_kv_row(_("Booted"), boot_text, last=True))

        page.append(identity_card)
        return page

    def _gauge_card(self, fraction: float, color: Tuple,
                    title: str, detail: str,
                    sub_detail: str) -> Gtk.Box:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        card.add_css_class("card")
        card.set_halign(Gtk.Align.FILL)

        inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        inner.set_margin_top(16)
        inner.set_margin_bottom(12)
        inner.set_margin_start(12)
        inner.set_margin_end(12)

        area = Gtk.DrawingArea()
        area.set_size_request(96, 96)
        area.set_halign(Gtk.Align.CENTER)
        area.set_content_width(96)
        area.set_content_height(96)

        frac = fraction
        col = color

        def _on_draw(a, cr, w, h):
            _draw_donut(a, cr, w, h, frac, col, '')

        area.set_draw_func(_on_draw)
        inner.append(area)

        title_lbl = Gtk.Label(label=title)
        title_lbl.set_halign(Gtk.Align.CENTER)
        title_lbl.add_css_class("heading")
        inner.append(title_lbl)

        if detail:
            detail_lbl = Gtk.Label(label=detail)
            detail_lbl.set_halign(Gtk.Align.CENTER)
            detail_lbl.add_css_class("monospace")
            detail_lbl.add_css_class("caption")
            inner.append(detail_lbl)

        if sub_detail:
            sub_lbl = Gtk.Label(label=sub_detail)
            sub_lbl.set_halign(Gtk.Align.CENTER)
            sub_lbl.add_css_class("caption")
            sub_lbl.set_opacity(0.6)
            inner.append(sub_lbl)

        card.append(inner)
        return card

    # ── Resources tab ──────────────────────────────────────────────────

    def _build_resources(self) -> Gtk.Box:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        page.set_margin_top(18)
        page.set_margin_bottom(24)
        page.set_margin_start(24)
        page.set_margin_end(24)

        lscpu = _parse_lscpu(self._data.get('LSCPU', ''))

        # Processor
        page.append(_section_label(_("Processor")))
        proc_card = _card_box()
        model = lscpu.get('Model name', '')
        proc_card.append(_kv_row(_("Model"), model))

        cores = lscpu.get('Core(s) per socket', '?')
        threads_per = lscpu.get('Thread(s) per core', '1')
        sockets = lscpu.get('Socket(s)', '1')
        try:
            total_threads = int(cores) * int(threads_per) * int(sockets)
        except ValueError:
            total_threads = '?'
        topo_text = (f"{cores} cores · {total_threads} threads"
                     f" · {sockets} socket{'s' if sockets != '1' else ''}")
        proc_card.append(_kv_row(_("Topology"), topo_text))

        freq_text = ''
        freq_line = self._data.get('CPU_FREQ', '')
        fm = re.search(r'([\d.]+)', freq_line)
        if fm:
            try:
                freq_text = f"{float(fm.group(1)) / 1000:.2f} GHz"
            except ValueError:
                freq_text = f"{fm.group(1)} MHz"
        proc_card.append(_kv_row(_("Current frequency"), freq_text,
                                 mono=True, last=True))
        page.append(proc_card)

        # Load average
        loadavg = self._data.get('LOADAVG', '').split()
        nproc = 1
        try:
            nproc = int(self._data.get('NPROC', '1'))
        except ValueError:
            pass

        page.append(_section_label(_("Load average")))
        load_grid = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        load_grid.set_homogeneous(True)
        for i, label in enumerate(('1 min', '5 min', '15 min')):
            val = 0.0
            val_text = '0.00'
            if i < len(loadavg):
                try:
                    val = float(loadavg[i])
                    val_text = loadavg[i]
                except ValueError:
                    pass
            frac = min(val / nproc, 1.0) if nproc else 0

            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            card.add_css_class("card")

            inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            inner.set_margin_top(14)
            inner.set_margin_bottom(14)
            inner.set_margin_start(16)
            inner.set_margin_end(16)

            header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
            lbl = Gtk.Label(label=label)
            lbl.set_opacity(0.6)
            lbl.add_css_class("caption")
            header.append(lbl)
            spacer = Gtk.Box()
            spacer.set_hexpand(True)
            header.append(spacer)
            val_lbl = Gtk.Label(label=val_text)
            val_lbl.add_css_class("monospace")
            val_lbl.add_css_class("heading")
            header.append(val_lbl)
            inner.append(header)

            bar = Gtk.LevelBar()
            bar.set_min_value(0)
            bar.set_max_value(1.0)
            bar.set_value(frac)
            bar.set_hexpand(True)
            bar.set_size_request(-1, 6)
            inner.append(bar)

            card.append(inner)
            load_grid.append(card)

        page.append(load_grid)

        note = Gtk.Label(label=_("Relative to %d logical CPUs") % nproc)
        note.set_xalign(0)
        note.add_css_class("caption")
        note.set_opacity(0.55)
        page.append(note)

        # Memory + Temperatures side by side
        two_col = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        two_col.set_homogeneous(True)

        # Memory
        mem = _parse_meminfo(self._data.get('MEMINFO', ''))
        mem_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        mem_box.append(_section_label(_("Memory")))
        mem_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        mem_card.add_css_class("card")

        mem_inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        mem_inner.set_margin_top(16)
        mem_inner.set_margin_bottom(16)
        mem_inner.set_margin_start(16)
        mem_inner.set_margin_end(16)

        mem_total = mem.get('MemTotal', 1)
        mem_free = mem.get('MemFree', 0)
        mem_avail = mem.get('MemAvailable', 0)
        mem_cached = mem.get('Cached', 0) + mem.get('Buffers', 0)
        mem_used = mem_total - mem_avail
        mem_frac = mem_used / mem_total if mem_total else 0

        bar = Gtk.LevelBar()
        bar.set_min_value(0)
        bar.set_max_value(1.0)
        bar.set_value(min(mem_frac, 1.0))
        bar.set_hexpand(True)
        bar.set_size_request(-1, 10)
        mem_inner.append(bar)

        stats = Gtk.FlowBox()
        stats.set_selection_mode(Gtk.SelectionMode.NONE)
        stats.set_homogeneous(False)
        stats.set_max_children_per_line(4)
        stats.set_min_children_per_line(2)
        for k, v in [(_("Used"), _fmt_bytes(mem_used)),
                     (_("Cache"), _fmt_bytes(mem_cached)),
                     (_("Free"), _fmt_bytes(mem_free)),
                     (_("Available"), _fmt_bytes(mem_avail))]:
            item = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            kl = Gtk.Label(label=k)
            kl.set_opacity(0.6)
            item.append(kl)
            vl = Gtk.Label(label=v)
            vl.add_css_class("monospace")
            item.append(vl)
            stats.insert(item, -1)
        mem_inner.append(stats)

        mem_card.append(mem_inner)

        swap_total = mem.get('SwapTotal', 0)
        swap_free = mem.get('SwapFree', 0)
        swap_used = swap_total - swap_free
        if swap_total:
            sep = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
            mem_card.append(sep)
            swap_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            swap_box.set_margin_top(12)
            swap_box.set_margin_bottom(16)
            swap_box.set_margin_start(16)
            swap_box.set_margin_end(16)
            swap_header = Gtk.Box(
                orientation=Gtk.Orientation.HORIZONTAL)
            sl = Gtk.Label(label=_("Swap"))
            sl.set_opacity(0.6)
            swap_header.append(sl)
            spacer = Gtk.Box()
            spacer.set_hexpand(True)
            swap_header.append(spacer)
            swap_pct = int(swap_used / swap_total * 100) if swap_total else 0
            sv = _mono_label(
                f"{_fmt_bytes(swap_used)} / {_fmt_bytes(swap_total)}"
                f" · {swap_pct}%")
            swap_header.append(sv)
            swap_box.append(swap_header)
            swap_bar = Gtk.LevelBar()
            swap_bar.set_min_value(0)
            swap_bar.set_max_value(1.0)
            swap_bar.set_value(
                min(swap_used / swap_total, 1.0) if swap_total else 0)
            swap_bar.set_size_request(-1, 6)
            swap_box.append(swap_bar)
            mem_card.append(swap_box)

        mem_box.append(mem_card)
        two_col.append(mem_box)

        # Temperatures
        temps = _parse_temps(
            self._data.get('TEMPS', ''),
            self._data.get('TEMP_TYPES', ''))
        temp_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        temp_box.append(_section_label(_("Temperatures")))
        temp_card = _card_box()
        if temps:
            for i, t in enumerate(temps):
                temp_c = t['temp_c']
                label_text = t['label']
                frac = min(temp_c / 100, 1.0)
                color = _RED if temp_c > 80 else (_AMBER if temp_c > 60 else _GREEN)

                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL,
                              spacing=12)
                row.set_margin_start(16)
                row.set_margin_end(16)
                row.set_margin_top(11)
                row.set_margin_bottom(11)

                name_lbl = Gtk.Label(label=label_text)
                name_lbl.set_opacity(0.6)
                name_lbl.set_size_request(120, -1)
                name_lbl.set_xalign(0)
                row.append(name_lbl)

                bar = Gtk.LevelBar()
                bar.set_min_value(0)
                bar.set_max_value(1.0)
                bar.set_value(frac)
                bar.set_hexpand(True)
                bar.set_size_request(-1, 6)
                bar.set_valign(Gtk.Align.CENTER)
                row.append(bar)

                val_lbl = _mono_label(f"{int(temp_c)} °C")
                val_lbl.set_size_request(48, -1)
                val_lbl.set_xalign(1)
                row.append(val_lbl)

                wrapper = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
                wrapper.append(row)
                if i < len(temps) - 1:
                    wrapper.append(Gtk.Separator(
                        orientation=Gtk.Orientation.HORIZONTAL))
                temp_card.append(wrapper)
        else:
            no_temp = Gtk.Label(label=_("No temperature sensors detected"))
            no_temp.set_margin_top(16)
            no_temp.set_margin_bottom(16)
            no_temp.add_css_class("dim-label")
            temp_card.append(no_temp)

        temp_box.append(temp_card)
        two_col.append(temp_box)
        page.append(two_col)

        return page

    # ── Storage tab ────────────────────────────────────────────────────

    def _build_storage(self) -> Gtk.Box:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        page.set_margin_top(18)
        page.set_margin_bottom(24)
        page.set_margin_start(24)
        page.set_margin_end(24)

        page.append(_section_label(_("Filesystems")))

        df_rows = _parse_df(self._data.get('DF', ''))
        card = _card_box()

        # Header
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        header.set_margin_start(16)
        header.set_margin_end(16)
        header.set_margin_top(10)
        header.set_margin_bottom(10)
        for text, width in [(_("Mount point"), 150), (_("Device"), 190),
                            (_("Usage"), -1), (_("Used / Size"), 130)]:
            lbl = Gtk.Label(label=text)
            lbl.set_xalign(0 if width != 130 else 1)
            lbl.add_css_class("caption")
            lbl.add_css_class("heading")
            lbl.set_opacity(0.6)
            if width > 0:
                lbl.set_size_request(width, -1)
            else:
                lbl.set_hexpand(True)
            header.append(lbl)
        card.append(header)
        card.append(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))

        for i, r in enumerate(df_rows):
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
            row.set_margin_start(16)
            row.set_margin_end(16)
            row.set_margin_top(14)
            row.set_margin_bottom(14)

            mount_lbl = _mono_label(r['mount'])
            mount_lbl.set_size_request(150, -1)
            mount_lbl.set_xalign(0)
            row.append(mount_lbl)

            dev_name = r['fs'].split('/')[-1] if '/' in r['fs'] else r['fs']
            dev_lbl = _mono_label(f"{dev_name} · {r['type']}")
            dev_lbl.set_size_request(190, -1)
            dev_lbl.set_xalign(0)
            dev_lbl.set_opacity(0.7)
            dev_lbl.add_css_class("caption")
            row.append(dev_lbl)

            pct = 0
            try:
                pct = int(r['pct'])
            except ValueError:
                pass
            frac = pct / 100.0

            usage_box = Gtk.Box(
                orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            usage_box.set_hexpand(True)
            usage_box.set_valign(Gtk.Align.CENTER)
            bar = Gtk.LevelBar()
            bar.set_min_value(0)
            bar.set_max_value(1.0)
            bar.set_value(frac)
            bar.set_hexpand(True)
            bar.set_size_request(-1, 8)
            bar.set_valign(Gtk.Align.CENTER)
            usage_box.append(bar)
            pct_lbl = _mono_label(f"{pct}%")
            pct_lbl.set_size_request(34, -1)
            pct_lbl.add_css_class("caption")
            usage_box.append(pct_lbl)
            row.append(usage_box)

            try:
                used_str = _fmt_bytes_si(int(r['used']))
                size_str = _fmt_bytes_si(int(r['size']))
            except ValueError:
                used_str = r.get('used', '?')
                size_str = r.get('size', '?')
            size_lbl = _mono_label(f"{used_str} / {size_str}")
            size_lbl.set_size_request(130, -1)
            size_lbl.set_xalign(1)
            size_lbl.add_css_class("caption")
            row.append(size_lbl)

            wrapper = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            wrapper.append(row)
            if i < len(df_rows) - 1:
                wrapper.append(
                    Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))
            card.append(wrapper)

        page.append(card)

        note = Gtk.Label(
            label=_("Excludes tmpfs, devtmpfs and overlay mounts."))
        note.set_xalign(0)
        note.add_css_class("caption")
        note.set_opacity(0.55)
        page.append(note)
        return page

    # ── Network tab ────────────────────────────────────────────────────

    def _build_network(self) -> Gtk.Box:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        page.set_margin_top(18)
        page.set_margin_bottom(24)
        page.set_margin_start(24)
        page.set_margin_end(24)

        ip_addrs = _parse_ip_addr(self._data.get('IP_ADDR', ''))
        ip_links = _parse_ip_link(self._data.get('IP_LINK', ''))
        net_dev = _parse_net_dev(self._data.get('NET_DEV', ''))

        page.append(_section_label(_("Interfaces")))
        iface_card = _card_box()

        seen_ifaces = []
        for iface in ip_links:
            if iface in seen_ifaces:
                continue
            seen_ifaces.append(iface)

        for idx, iface in enumerate(seen_ifaces):
            link = ip_links.get(iface, {})
            addrs = [a for a in ip_addrs
                     if a['iface'] == iface and a['family'] == 'inet']

            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
            row.set_margin_start(16)
            row.set_margin_end(16)
            row.set_margin_top(14)
            row.set_margin_bottom(14)

            icon_name = 'network-wireless-symbolic'
            itype = link.get('type', 'ethernet')
            if itype == 'loopback':
                icon_name = 'network-transmit-receive-symbolic'
            elif itype == 'ethernet':
                icon_name = 'network-idle-symbolic'

            state = link.get('state', 'unknown')
            icon = Gtk.Image.new_from_icon_name(icon_name)
            icon.set_pixel_size(16)
            if state == 'up':
                pass
            elif state in ('no-carrier', 'down'):
                icon.set_opacity(0.5)
            row.append(icon)

            name_lbl = _mono_label(iface)
            name_lbl.set_size_request(180, -1)
            name_lbl.set_xalign(0)
            name_lbl.add_css_class("caption")
            row.append(name_lbl)

            detail_box = Gtk.Box(
                orientation=Gtk.Orientation.VERTICAL, spacing=2)
            detail_box.set_hexpand(True)
            if addrs:
                addr_lbl = _mono_label(addrs[0]['addr'])
                addr_lbl.set_xalign(0)
                addr_lbl.add_css_class("caption")
                detail_box.append(addr_lbl)
            elif state == 'no-carrier':
                nc_lbl = Gtk.Label(label=_("No carrier"))
                nc_lbl.set_xalign(0)
                nc_lbl.set_opacity(0.6)
                nc_lbl.add_css_class("caption")
                detail_box.append(nc_lbl)

            mac = link.get('mac', '')
            mtu = link.get('mtu', '')
            sub_parts = []
            if mac:
                sub_parts.append(mac)
            sub_parts.append(itype)
            if mtu:
                sub_parts.append(f"MTU {mtu}")
            sub_lbl = _mono_label(' · '.join(sub_parts))
            sub_lbl.set_xalign(0)
            sub_lbl.set_opacity(0.55)
            sub_lbl.add_css_class("caption")
            detail_box.append(sub_lbl)
            row.append(detail_box)

            wrapper = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            wrapper.append(row)
            if idx < len(seen_ifaces) - 1:
                wrapper.append(
                    Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))
            iface_card.append(wrapper)

        page.append(iface_card)

        # Routing & resolution
        page.append(_section_label(_("Routing & resolution")))
        route_card = _card_box()

        default_route = self._data.get('IP_ROUTE', '').strip()
        gw_text = ''
        if default_route:
            parts = default_route.split()
            gw = ''
            dev = ''
            for j, p in enumerate(parts):
                if p == 'via' and j + 1 < len(parts):
                    gw = parts[j + 1]
                if p == 'dev' and j + 1 < len(parts):
                    dev = parts[j + 1]
            gw_text = gw
            if dev:
                gw_text += f" via {dev}"
        route_card.append(_kv_row(_("Default gateway"), gw_text, mono=True))

        dns_text = self._data.get('DNS', '')
        servers = []
        for line in dns_text.splitlines():
            if line.strip().startswith('nameserver'):
                servers.append(line.split()[-1])
        route_card.append(_kv_row(
            _("DNS servers"), ', '.join(servers), mono=True))

        ss_listen = self._data.get('SS_LISTEN', '')
        ssh_port = ''
        for line in ss_listen.splitlines():
            if ':22 ' in line or line.strip().endswith(':22'):
                proc_m = re.search(r'users:\(\("([^"]+)"', line)
                proc_name = proc_m.group(1) if proc_m else 'sshd'
                ssh_port = f"22/tcp ({proc_name})"
                break
        route_card.append(_kv_row(
            _("Listening SSH port"), ssh_port, mono=True, last=True))

        page.append(route_card)
        return page

    # ── Traffic tab ────────────────────────────────────────────────────

    def _build_traffic(self) -> Gtk.Box:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        page.set_margin_top(18)
        page.set_margin_bottom(24)
        page.set_margin_start(24)
        page.set_margin_end(24)

        # Live banner
        banner = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        banner.set_margin_start(12)
        banner.set_margin_end(12)
        banner.set_margin_top(8)
        banner.set_margin_bottom(8)

        dot = Gtk.DrawingArea()
        dot.set_size_request(8, 8)
        dot.set_valign(Gtk.Align.CENTER)
        dot.set_content_width(8)
        dot.set_content_height(8)
        dot.set_draw_func(
            lambda _a, cr, w, h: (
                cr.set_source_rgb(*_BLUE),
                cr.arc(w / 2, h / 2, 4, 0, 2 * math.pi),
                cr.fill(),
            ))
        banner.append(dot)
        banner_lbl = Gtk.Label(
            label=_("Live — sampling every 2 s while this"
                    " window is open. Rates are averaged over"
                    " the last sample."))
        banner_lbl.add_css_class("caption")
        banner_lbl.set_wrap(True)
        banner.append(banner_lbl)
        page.append(banner)

        # Bandwidth per interface
        net_dev = _parse_net_dev(self._data.get('NET_DEV', ''))
        ip_links = _parse_ip_link(self._data.get('IP_LINK', ''))

        page.append(_section_label(_("Bandwidth")))
        bw_card = _card_box()

        bw_hdr = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        bw_hdr.set_margin_start(16)
        bw_hdr.set_margin_end(16)
        bw_hdr.set_margin_top(10)
        bw_hdr.set_margin_bottom(10)
        for text, w in [(_("Interface"), 140), (_("Received"), 120),
                        (_("Transmitted"), 120), (_("Rate ↓"), -1),
                        (_("Rate ↑"), 90)]:
            lbl = Gtk.Label(label=text)
            lbl.set_xalign(1 if text != _("Interface") else 0)
            lbl.add_css_class("caption")
            lbl.add_css_class("heading")
            lbl.set_opacity(0.6)
            if w > 0:
                lbl.set_size_request(w, -1)
            else:
                lbl.set_hexpand(True)
                lbl.set_xalign(1)
            bw_hdr.append(lbl)
        bw_card.append(bw_hdr)
        bw_card.append(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))

        self._bw_rate_labels: Dict[str, Tuple[Gtk.Label, Gtk.Label]] = {}
        ifaces = [i for i in net_dev if i != 'lo']
        if not ifaces:
            ifaces = list(net_dev.keys())

        for idx, iface in enumerate(ifaces):
            rx, tx = net_dev.get(iface, (0, 0))

            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
            row.set_margin_start(16)
            row.set_margin_end(16)
            row.set_margin_top(12)
            row.set_margin_bottom(12)

            name_lbl = _mono_label(iface)
            name_lbl.set_size_request(140, -1)
            name_lbl.set_xalign(0)
            name_lbl.add_css_class("caption")
            row.append(name_lbl)

            rx_lbl = _mono_label(_fmt_bytes(rx))
            rx_lbl.set_size_request(120, -1)
            rx_lbl.set_xalign(1)
            rx_lbl.add_css_class("caption")
            row.append(rx_lbl)

            tx_lbl = _mono_label(_fmt_bytes(tx))
            tx_lbl.set_size_request(120, -1)
            tx_lbl.set_xalign(1)
            tx_lbl.add_css_class("caption")
            row.append(tx_lbl)

            rate_rx = _mono_label("—")
            rate_rx.set_hexpand(True)
            rate_rx.set_xalign(1)
            rate_rx.add_css_class("caption")
            row.append(rate_rx)

            rate_tx = _mono_label("—")
            rate_tx.set_size_request(90, -1)
            rate_tx.set_xalign(1)
            rate_tx.add_css_class("caption")
            row.append(rate_tx)

            self._bw_rate_labels[iface] = (rate_rx, rate_tx)

            wrapper = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            wrapper.append(row)
            if idx < len(ifaces) - 1:
                wrapper.append(
                    Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))
            bw_card.append(wrapper)

        page.append(bw_card)

        # Connected SSH clients
        page.append(_section_label(_("Connected SSH clients")))
        who_rows = self._get_logged_in_users()
        ss_rows = _parse_ss_estab(self._data.get('SS_ESTAB', ''))

        clients_card = _card_box()

        # Header
        hdr = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        hdr.set_margin_start(16)
        hdr.set_margin_end(16)
        hdr.set_margin_top(10)
        hdr.set_margin_bottom(10)
        for text, w in [(_("User"), 110), (_("From"), 190),
                        (_("TTY"), 90), (_("Since"), -1)]:
            lbl = Gtk.Label(label=text)
            lbl.set_xalign(0 if w != -1 else 1)
            lbl.add_css_class("caption")
            lbl.add_css_class("heading")
            lbl.set_opacity(0.6)
            if w > 0:
                lbl.set_size_request(w, -1)
            else:
                lbl.set_hexpand(True)
                lbl.set_xalign(1)
            hdr.append(lbl)
        clients_card.append(hdr)
        clients_card.append(
            Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))

        for i, who in enumerate(who_rows):
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
            row.set_margin_start(16)
            row.set_margin_end(16)
            row.set_margin_top(13)
            row.set_margin_bottom(13)

            user_box = Gtk.Box(
                orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            user_box.set_size_request(110, -1)
            d2 = Gtk.DrawingArea()
            d2.set_size_request(8, 8)
            d2.set_valign(Gtk.Align.CENTER)
            d2.set_content_width(8)
            d2.set_content_height(8)
            is_ssh = 'from' in who and who['from'] not in (
                '', ':0', ':1', 'local console')
            color = _GREEN if is_ssh else (0.467, 0.463, 0.482)
            d2.set_draw_func(
                lambda _a, cr, w, h, c=color: (
                    cr.set_source_rgb(*c),
                    cr.arc(w / 2, h / 2, 4, 0, 2 * math.pi),
                    cr.fill(),
                ))
            user_box.append(d2)
            ul = Gtk.Label(label=who['user'])
            ul.add_css_class("heading")
            user_box.append(ul)
            row.append(user_box)

            from_text = who.get('from', '')
            if not from_text:
                from_text = _("local console")
            fl = Gtk.Label(label=from_text)
            fl.set_size_request(190, -1)
            fl.set_xalign(0)
            if from_text != _("local console"):
                fl.add_css_class("monospace")
            else:
                fl.set_opacity(0.6)
            fl.add_css_class("caption")
            row.append(fl)

            tl = _mono_label(who['tty'])
            tl.set_size_request(90, -1)
            tl.set_xalign(0)
            tl.add_css_class("caption")
            row.append(tl)

            sl = Gtk.Label(label=who.get('since', ''))
            sl.set_hexpand(True)
            sl.set_xalign(1)
            sl.add_css_class("caption")
            row.append(sl)

            wrapper = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            wrapper.append(row)
            if i < len(who_rows) - 1:
                wrapper.append(
                    Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))
            clients_card.append(wrapper)

        if not who_rows:
            empty = Gtk.Label(label=_("No logged-in users"))
            empty.set_margin_top(16)
            empty.set_margin_bottom(16)
            empty.add_css_class("dim-label")
            clients_card.append(empty)

        page.append(clients_card)

        # TCP connections: incoming vs outgoing
        incoming = []
        outgoing = []
        for s in ss_rows:
            local_port = ''
            peer_port = ''
            lp = s.get('local', '')
            pp = s.get('peer', '')
            lm = re.search(r':(\d+)$', lp)
            pm = re.search(r':(\d+)$', pp)
            if lm:
                local_port = lm.group(1)
            if pm:
                peer_port = pm.group(1)
            try:
                if int(local_port) < 1024 or int(local_port) in (3306, 5432, 6379, 8080, 9100):
                    incoming.append(s)
                else:
                    outgoing.append(s)
            except ValueError:
                outgoing.append(s)

        two_col = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        two_col.set_homogeneous(True)

        for label_text, conns in [
            (_("Incoming · %d established") % len(incoming), incoming),
            (_("Outgoing · %d established") % len(outgoing), outgoing),
        ]:
            col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            col.append(_section_label(label_text))
            conn_card = _card_box()
            for j, s in enumerate(conns[:8]):
                lp = s.get('local', '')
                pp = s.get('peer', '')
                lm = re.search(r':(\d+)$', lp)
                port = f":{lm.group(1)}" if lm else lp

                r = Gtk.Box(
                    orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
                r.set_margin_start(16)
                r.set_margin_end(16)
                r.set_margin_top(11)
                r.set_margin_bottom(11)

                pl = _mono_label(port)
                pl.set_size_request(56, -1)
                pl.set_xalign(0)
                pl.add_css_class("caption")
                r.append(pl)

                peer_lbl = _mono_label(pp)
                peer_lbl.set_hexpand(True)
                peer_lbl.set_xalign(0)
                peer_lbl.set_opacity(0.75)
                peer_lbl.add_css_class("caption")
                r.append(peer_lbl)

                proc_lbl = Gtk.Label(label=s.get('proc', ''))
                proc_lbl.add_css_class("caption")
                proc_lbl.set_opacity(0.55)
                r.append(proc_lbl)

                w2 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
                w2.append(r)
                if j < len(conns) - 1 and j < 7:
                    w2.append(Gtk.Separator(
                        orientation=Gtk.Orientation.HORIZONTAL))
                conn_card.append(w2)
            if not conns:
                empty = Gtk.Label(label=_("None"))
                empty.set_margin_top(12)
                empty.set_margin_bottom(12)
                empty.add_css_class("dim-label")
                conn_card.append(empty)
            col.append(conn_card)
            two_col.append(col)

        page.append(two_col)

        note = Gtk.Label(label=_(
            "Sockets from ss -tunap; process names for other users’"
            " sockets need root and are shown blank otherwise."))
        note.set_xalign(0)
        note.add_css_class("caption")
        note.set_opacity(0.55)
        note.set_wrap(True)
        page.append(note)

        self._traffic_content = page
        return page

    def _update_traffic_rates(self, prev, curr, dt):
        if not hasattr(self, '_bw_rate_labels'):
            return
        for iface, (rx_lbl, tx_lbl) in self._bw_rate_labels.items():
            prev_rx, prev_tx = prev.get(iface, (0, 0))
            curr_rx, curr_tx = curr.get(iface, (0, 0))
            rx_rate = max(0, (curr_rx - prev_rx) / dt)
            tx_rate = max(0, (curr_tx - prev_tx) / dt)
            rx_lbl.set_text(_fmt_bytes_rate(rx_rate))
            tx_lbl.set_text(_fmt_bytes_rate(tx_rate))

    # ── System tab ─────────────────────────────────────────────────────

    def _build_system(self) -> Gtk.Box:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        page.set_margin_top(18)
        page.set_margin_bottom(24)
        page.set_margin_start(24)
        page.set_margin_end(24)

        # Logged-in users
        page.append(_section_label(_("Logged-in users")))
        users_card = _card_box()

        who_rows = self._get_logged_in_users()
        for i, who in enumerate(who_rows):
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            row.set_margin_start(16)
            row.set_margin_end(16)
            row.set_margin_top(12)
            row.set_margin_bottom(12)

            ul = Gtk.Label(label=who['user'])
            ul.add_css_class("heading")
            ul.set_size_request(70, -1)
            ul.set_xalign(0)
            row.append(ul)

            from_text = who.get('from', '')
            detail = f"{who['tty']}"
            if from_text:
                detail += f" · {from_text}"
            elif 'tty' in who['tty'] and 'pts' not in who['tty']:
                detail += f" · local console"
            dl = _mono_label(detail)
            dl.set_hexpand(True)
            dl.set_xalign(0)
            dl.set_opacity(0.75)
            dl.add_css_class("caption")
            row.append(dl)

            sl = Gtk.Label(label=who.get('since', ''))
            sl.add_css_class("caption")
            sl.set_opacity(0.55)
            row.append(sl)

            w2 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            w2.append(row)
            if i < len(who_rows) - 1:
                w2.append(Gtk.Separator(
                    orientation=Gtk.Orientation.HORIZONTAL))
            users_card.append(w2)

        if not who_rows:
            empty = Gtk.Label(label=_("No logged-in users"))
            empty.set_margin_top(16)
            empty.set_margin_bottom(16)
            empty.add_css_class("dim-label")
            users_card.append(empty)

        page.append(users_card)

        # Updates
        page.append(_section_label(_("Updates")))
        updates_card = _card_box()

        apt_up = self._data.get('APT_UPGRADABLE', '').strip()
        apt_sec = self._data.get('APT_SECURITY', '').strip()
        reboot = self._data.get('REBOOT_REQ', '').strip()
        apt_stamp = self._data.get('APT_STAMP', '').strip()

        updates_card.append(_kv_row(
            _("Upgradable packages"), apt_up or '0', mono=True))
        updates_card.append(_kv_row(
            _("Security updates"), apt_sec or '0', mono=True))

        reboot_text = _("No")
        if reboot and reboot != 'no':
            reboot_text = _("Yes — %s") % reboot
        updates_card.append(_kv_row(_("Reboot required"), reboot_text))

        last_update = ''
        if apt_stamp:
            try:
                ts = int(apt_stamp)
                last_update = datetime.fromtimestamp(
                    ts, tz=timezone.utc).strftime('%d %b %Y, %H:%M')
            except (ValueError, OSError):
                last_update = apt_stamp
        updates_card.append(_kv_row(
            _("Last apt update"), last_update, mono=True, last=True))

        page.append(updates_card)
        return page
