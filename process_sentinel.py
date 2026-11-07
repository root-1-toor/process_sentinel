#!/usr/bin/env python3
"""PROCESS SENTINEL - a terminal process tree viewer for Linux.

Reads /proc directly (standard library only). Shows a process tree with CPU%,
RAM%, listening TCP port, plus a details panel for the selected process.

Usage:
    ./process_sentinel.py                 interactive TUI
    ./process_sentinel.py --once          print one snapshot and exit
    ./process_sentinel.py --once --width 64 --height 20
    ./process_sentinel.py --serve         web UI at http://127.0.0.1:8000
    ./process_sentinel.py --serve --port 9000 --host 0.0.0.0
      (--host 0.0.0.0 exposes process info to your network: use with care)

Keys:
    Up/Down PgUp/PgDn Home/End   move selection
    Enter                        inspect the selected process
    Space / Left / Right         collapse or expand the selected branch
    e                            show/hide network event history
    F1 or ?     help             F2 or t   tree / flat (sorted by CPU)
    F3 or /     search           F4 or d   details panel on/off
    F5 or r     refresh now      Q         quit
    k           show/hide kernel threads   Esc  clear search
"""
try:
    import curses
except ImportError:          # Windows without windows-curses
    curses = None
import locale
from collections import deque
import json
import os
import threading
try:
    import pwd
except ImportError:          # Windows
    pwd = None
import socket
import sys
import time

sys.setrecursionlimit(5000)
USE_PROC = sys.platform.startswith("linux") and os.path.isdir("/proc")
CLK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
PAGE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
REFRESH_SECS = 1.0
EVENT_LINES = 5        # rows in the events panel
MAX_EVENTS = 500
PIDW, USERW, CPUW, RAMW, PORTW = 18, 8, 5, 5, 6
DASH = "—"


# --------------------------------------------------------------------------
# Data collection
# --------------------------------------------------------------------------
class Proc:
    __slots__ = ("pid", "ppid", "name", "user", "ticks", "cpu", "ram",
                 "exe", "cmdline", "start", "ports")


def _read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return b""


def _decode_addr(hexaddr, v6):
    raw = bytes.fromhex(hexaddr)
    if v6:
        raw = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
        return socket.inet_ntop(socket.AF_INET6, raw)
    return socket.inet_ntoa(raw[::-1])


def listening_sockets():
    """inode -> (ip, port) for every TCP socket in LISTEN state."""
    result = {}
    for path, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        lines = _read(path).decode(errors="replace").splitlines()[1:]
        for line in lines:
            f = line.split()
            if len(f) < 10 or f[3] != "0A":
                continue
            addr, port = f[1].split(":")
            try:
                result[f[9]] = (_decode_addr(addr, v6), int(port, 16))
            except ValueError:
                continue
    return result


def fmt_endpoint(ip, port):
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


class Sampler:
    def __init__(self):
        self.prev_ticks = {}
        self.prev_time = None
        self.prev_cpu = None
        self.users = {}
        self.btime = 0
        for line in _read("/proc/stat").decode().splitlines():
            if line.startswith("btime"):
                self.btime = int(line.split()[1])
        self.mem_total = 1

    def _user(self, uid):
        if uid not in self.users:
            try:
                self.users[uid] = pwd.getpwuid(uid).pw_name
            except KeyError:
                self.users[uid] = str(uid)
        return self.users[uid]

    def _total_cpu(self):
        line = _read("/proc/stat").decode().splitlines()[0].split()[1:]
        vals = [int(x) for x in line[:8]]
        idle = vals[3] + vals[4]
        total = sum(vals)
        pct = 0.0
        if self.prev_cpu:
            dt, di = total - self.prev_cpu[0], idle - self.prev_cpu[1]
            if dt > 0:
                pct = 100.0 * (1 - di / dt)
        self.prev_cpu = (total, idle)
        return pct

    def _mem_pct(self):
        info = {}
        for line in _read("/proc/meminfo").decode().splitlines():
            k, _, v = line.partition(":")
            info[k] = int(v.split()[0]) if v.split() else 0
        total = info.get("MemTotal", 1) or 1
        self.mem_total = total * 1024
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        return 100.0 * (total - avail) / total

    def sample(self):
        now = time.monotonic()
        elapsed = (now - self.prev_time) if self.prev_time else None
        socks = listening_sockets()
        procs, new_ticks = {}, {}
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            base = f"/proc/{pid}"
            stat = _read(base + "/stat").decode(errors="replace")
            rp = stat.rfind(")")
            if rp < 0:
                continue
            rest = stat[rp + 2:].split()
            if len(rest) < 20:
                continue
            p = Proc()
            p.pid = pid
            p.name = stat[stat.find("(") + 1:rp]
            p.ppid = int(rest[1])
            p.ticks = int(rest[11]) + int(rest[12])
            new_ticks[pid] = p.ticks
            start_ticks = int(rest[19])
            p.start = self.btime + start_ticks / CLK
            try:
                p.user = self._user(os.stat(base).st_uid)
            except OSError:
                p.user = "?"
            statm = _read(base + "/statm").split()
            rss = int(statm[1]) * PAGE if len(statm) > 1 else 0
            p.ram = 100.0 * rss / self.mem_total if self.mem_total > 1 else 0.0
            p.cpu = 0.0
            if elapsed and pid in self.prev_ticks:
                p.cpu = max(0.0, 100.0 * (p.ticks - self.prev_ticks[pid]) / CLK / elapsed)
            args = _read(base + "/cmdline").split(b"\0")
            p.cmdline = " ".join(a.decode(errors="replace") for a in args if a)
            try:
                p.exe = os.readlink(base + "/exe")
            except OSError:
                p.exe = args[0].decode(errors="replace") if args and args[0] else ""
            ports = set()
            if socks:
                try:
                    for fd in os.listdir(base + "/fd"):
                        try:
                            link = os.readlink(f"{base}/fd/{fd}")
                        except OSError:
                            continue
                        if link.startswith("socket:["):
                            hit = socks.get(link[8:-1])
                            if hit:
                                ports.add(hit)
                except OSError:
                    pass
            p.ports = sorted(ports, key=lambda x: (x[1], x[0]))
            procs[pid] = p
        self.prev_ticks, self.prev_time = new_ticks, now
        return procs, self._total_cpu(), self._mem_pct()


# --------------------------------------------------------------------------
# State and row building
# --------------------------------------------------------------------------
class PsutilSampler:
    """Sampler for Windows/macOS, built on psutil (pip install psutil)."""

    def __init__(self):
        import psutil
        self.ps = psutil
        self.prev = {}
        self.prev_time = None
        self.mem_total = psutil.virtual_memory().total
        psutil.cpu_percent(None)

    def sample(self):
        ps = self.ps
        now = time.monotonic()
        elapsed = (now - self.prev_time) if self.prev_time else None

        def get(fn, default):
            try:
                return fn()
            except (ps.Error, OSError):
                return default

        ports = {}
        try:
            for c in ps.net_connections(kind="tcp"):
                if c.status == ps.CONN_LISTEN and c.pid and c.laddr:
                    ports.setdefault(c.pid, set()).add((c.laddr.ip, c.laddr.port))
        except (ps.Error, OSError):
            pass

        procs, new = {}, {}
        for pr in ps.process_iter():
            pid = pr.pid
            name = get(pr.name, None)
            if name is None:
                continue
            p = Proc()
            p.pid = pid
            p.name = name
            p.ppid = get(pr.ppid, 0)
            p.user = (get(pr.username, None) or "?").split("\\")[-1]
            t = get(pr.cpu_times, None)
            secs = (t.user + t.system) if t else 0.0
            p.ticks = secs
            new[pid] = secs
            p.cpu = 0.0
            if elapsed and pid in self.prev:
                p.cpu = max(0.0, 100.0 * (secs - self.prev[pid]) / elapsed)
            mi = get(pr.memory_info, None)
            p.ram = 100.0 * mi.rss / self.mem_total if mi else 0.0
            p.exe = get(pr.exe, "") or ""
            p.cmdline = " ".join(get(pr.cmdline, []) or [])
            p.start = get(pr.create_time, 0.0)
            p.ports = sorted(ports.get(pid, ()), key=lambda x: (x[1], x[0]))
            procs[pid] = p
        self.prev, self.prev_time = new, now
        return procs, ps.cpu_percent(None), ps.virtual_memory().percent


def make_sampler():
    return Sampler() if USE_PROC else PsutilSampler()


class State:
    def __init__(self):
        self.procs = {}
        self.rows = []          # (pid, prefix, collapsed_marker)
        self.sel = 0
        self.sel_pid = None
        self.top = 0
        self.mode = "tree"
        self.flt = ""
        self.collapsed = set()
        self.show_details = True
        self.show_kernel = False
        self.cpu = 0.0
        self.ram = 0.0
        self.input_mode = False
        self.input_buf = ""
        self.input_prev = ""
        self.sampler = make_sampler()
        self.show_events = True
        self.events = deque(maxlen=MAX_EVENTS)   # (time, "OPEN"|"CLOSE"|"INFO", text)
        self.listeners = None                    # {(pid, ip, port): name}

    def log(self, kind, text):
        self.events.append((time.time(), kind, text))

    def track_listeners(self):
        """Diff listening sockets against the previous sample and log changes."""
        cur = {}
        for p in self.procs.values():
            for ip, port in p.ports:
                cur[(p.pid, ip, port)] = p.name
        if self.listeners is None:
            self.log("INFO", f"monitoring started, {len(cur)} listener(s) visible")
        else:
            for key in sorted(set(cur) - set(self.listeners), key=lambda k: (k[2], k[0])):
                pid, ip, port = key
                self.log("OPEN", f"{cur[key]} (PID {pid}) listening on TCP {fmt_endpoint(ip, port)}")
            for key in sorted(set(self.listeners) - set(cur), key=lambda k: (k[2], k[0])):
                pid, ip, port = key
                self.log("CLOSE", f"{self.listeners[key]} (PID {pid}) stopped TCP {fmt_endpoint(ip, port)}")
        self.listeners = cur

    def refresh(self):
        self.procs, self.cpu, self.ram = self.sampler.sample()
        self.track_listeners()
        self.rebuild()

    def is_kernel(self, p):
        return p.pid == 0 or p.pid == 2 or p.ppid == 2

    def matches(self, p, needle):
        hay = " ".join([p.name, p.user, str(p.pid), p.exe, p.cmdline] +
                       [str(port) for _, port in p.ports]).lower()
        return needle in hay

    def rebuild(self):
        procs = self.procs
        vis = {pid for pid, p in procs.items()
               if self.show_kernel or not self.is_kernel(p)}
        keep = vis
        if self.flt:
            needle = self.flt.lower()
            match = {pid for pid in vis if self.matches(procs[pid], needle)}
            keep = set(match)
            if self.mode == "tree":
                for pid in match:
                    parent = procs[pid].ppid
                    while parent in vis and parent not in keep:
                        keep.add(parent)
                        parent = procs[parent].ppid
        rows = []
        if self.mode == "flat":
            for pid in sorted(keep, key=lambda x: (-procs[x].cpu, x)):
                rows.append((pid, "", ""))
        else:
            children = {}
            for pid in keep:
                if procs[pid].ppid != pid:
                    children.setdefault(procs[pid].ppid, []).append(pid)
            for kids in children.values():
                kids.sort()
            roots = sorted(pid for pid in keep
                           if procs[pid].ppid not in keep or procs[pid].ppid == pid)

            def walk(pid, prefix, last, root):
                label = "" if root else prefix + ("└─ " if last else "├─ ")
                kids = children.get(pid, [])
                folded = pid in self.collapsed and kids and not self.flt
                rows.append((pid, label, " +" if folded else ""))
                if folded:
                    return
                child_prefix = "" if root else prefix + ("   " if last else "│  ")
                for i, k in enumerate(kids):
                    walk(k, child_prefix, i == len(kids) - 1, False)

            for r in roots:
                walk(r, "", True, True)
        self.rows = rows
        idx = next((i for i, r in enumerate(rows) if r[0] == self.sel_pid), None)
        if idx is None:
            idx = min(self.sel, max(0, len(rows) - 1))
        self.sel = idx
        self.sel_pid = rows[idx][0] if rows else None

    def move(self, delta=None, to=None):
        if not self.rows:
            return
        i = to if to is not None else self.sel + delta
        self.sel = max(0, min(len(self.rows) - 1, i))
        self.sel_pid = self.rows[self.sel][0]

    def toggle_collapse(self):
        if self.sel_pid is None or self.mode != "tree":
            return
        self.collapsed ^= {self.sel_pid}
        self.rebuild()


# --------------------------------------------------------------------------
# Rendering (pure text, shared by curses and --once)
# --------------------------------------------------------------------------
def fit(s, n):
    s = s if len(s) <= n else s[:max(0, n - 1)] + "…"
    return s.ljust(n)


def render(st, W, H):
    """Return (lines, index_of_selected_line_or_None)."""
    W = max(W, 40)
    inner = W - 2

    def box(text=""):
        return "│" + fit(text, inner) + "│"

    def sep():
        return "├" + "─" * inner + "┤"

    overhead = 8 + (7 if st.show_details else 0) + (EVENT_LINES + 1 if st.show_events else 0)
    list_h = max(1, H - overhead)
    # keep selection visible
    if st.sel < st.top:
        st.top = st.sel
    if st.sel >= st.top + list_h:
        st.top = st.sel - list_h + 1
    st.top = max(0, min(st.top, max(0, len(st.rows) - list_h)))

    lines = ["┌" + "─" * inner + "┐"]
    left = " PROCESS SENTINEL"
    if st.flt:
        left += f"  /{st.flt}"
    if st.mode == "flat":
        left += "  [flat]"
    right = f"CPU {st.cpu:.0f}% | RAM {st.ram:.0f}% "
    gap = max(1, inner - len(left) - len(right))
    lines.append(box(left + " " * gap + right))
    lines.append(sep())
    comm_w = max(4, inner - (1 + PIDW + 1 + USERW + 1 + CPUW + 1 + RAMW + 1 + PORTW + 2))
    head = (f" {'PID':<{PIDW}} {'USER':<{USERW}} {'CPU%':>{CPUW}} {'RAM%':>{RAMW}} "
            f"{'PORT':>{PORTW}}  {'PROCESS':<{comm_w}}")
    lines.append(box(head))
    lines.append(sep())

    sel_line = None
    for i in range(list_h):
        ri = st.top + i
        if ri >= len(st.rows):
            lines.append(box())
            continue
        pid, prefix, mark = st.rows[ri]
        p = st.procs[pid]
        if p.ports:
            port = str(p.ports[0][1]) + ("+" if len(p.ports) > 1 else "")
        else:
            port = DASH
        row = (f" {fit(prefix + str(pid) + mark, PIDW)} {fit(p.user, USERW)} "
               f"{p.cpu:>{CPUW}.1f} {p.ram:>{RAMW}.1f} {port:>{PORTW}}  "
               f"{fit(p.name, comm_w)}")
        if ri == st.sel:
            sel_line = len(lines)
        lines.append(box(row))

    if st.show_details:
        lines.append(sep())
        p = st.procs.get(st.sel_pid) if st.sel_pid is not None else None
        if p:
            started = time.localtime(p.start)
            same_day = time.strftime("%Y%m%d", started) == time.strftime("%Y%m%d")
            started_s = time.strftime("%H:%M:%S" if same_day else "%b %d %H:%M:%S", started)
            listening = ", ".join("TCP " + fmt_endpoint(ip, port) for ip, port in p.ports) or DASH
            lines += [
                box(f" SELECTED: {p.name} (PID {p.pid})"),
                box(f" Executable: {p.exe or DASH}"),
                box(f" Parent PID: {p.ppid}"),
                box(f" Started: {started_s}"),
                box(f" Listening: {listening}"),
                box(f" Command: {p.cmdline or DASH}"),
            ]
        else:
            lines += [box(" SELECTED: (none)")] + [box()] * 5

    if st.show_events:
        lines.append(sep())
        shown = list(st.events)[-EVENT_LINES:]
        shown = [None] * (EVENT_LINES - len(shown)) + shown
        for ev in shown:
            if ev is None:
                lines.append(box())
                continue
            ts, kind, text = ev
            tag = {"OPEN": "+ OPEN ", "CLOSE": "- CLOSE", "INFO": "· INFO "}[kind]
            lines.append(box(f" {time.strftime('%H:%M:%S', time.localtime(ts))} {tag} {text}"))

    lines.append(sep())
    if st.input_mode:
        lines.append(box(f" Search: {st.input_buf}_   (Enter accept, Esc cancel)"))
    else:
        lines.append(box(" Enter Inspect  F1 Help  F2 Tree  F3 Find  E Events  Q Quit"))
    lines.append("└" + "─" * inner + "┘")
    return lines, sel_line


def inspect_lines(st, pid):
    p = st.procs.get(pid)
    if not p:
        return ["Process has exited.", "", "Press any key to close"]
    parent = st.procs.get(p.ppid)
    started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.start))
    up = int(time.time() - p.start)
    uptime = f"{up // 3600}h {up % 3600 // 60}m {up % 60}s"
    lines = [
        f"{p.name}  (PID {p.pid})",
        "",
        f"User:        {p.user}",
        f"Executable:  {p.exe or DASH}",
        f"Command:     {p.cmdline or DASH}",
        f"Parent:      {p.ppid}" + (f" ({parent.name})" if parent else ""),
        f"Started:     {started}  (up {uptime})",
        f"CPU / RAM:   {p.cpu:.1f}% / {p.ram:.1f}%",
        "Listening:   " + (", ".join("TCP " + fmt_endpoint(ip, pt) for ip, pt in p.ports) or DASH),
        "",
        "Recent network events for this PID:",
    ]
    mine = [e for e in st.events if f"(PID {pid})" in e[2]][-5:]
    for ts, kind, text in mine:
        lines.append(f"  {time.strftime('%H:%M:%S', time.localtime(ts))} {kind:<5} {text}")
    if not mine:
        lines.append("  none")
    return lines + ["", "Press any key to close"]


HELP_TEXT = [
    "PROCESS SENTINEL - help",
    "",
    "Up/Down, PgUp/PgDn, Home/End   move selection",
    "Enter           inspect selected process (full details)",
    "Space / Left / Right   collapse or expand branch",
    "e               show/hide network event history",
    "F2 or t         toggle tree / flat (sorted by CPU)",
    "F3 or /         search name, user, PID, port, path",
    "Esc             clear the search filter",
    "F4 or d         show/hide details panel",
    "F5 or r         refresh now (auto every 1s)",
    "k               show/hide kernel threads",
    "Q               quit",
    "",
    "Press any key to close",
]


# --------------------------------------------------------------------------
# Curses UI
# --------------------------------------------------------------------------
def draw(stdscr, st):
    H, W = stdscr.getmaxyx()
    lines, sel_line = render(st, W, H)
    stdscr.erase()
    for i, line in enumerate(lines[:H]):
        attr = curses.A_REVERSE if i == sel_line else 0
        if i == 1:
            attr = curses.A_BOLD
        try:
            stdscr.addstr(i, 0, line[:W], attr)
        except curses.error:
            pass  # bottom-right cell write


def show_popup(stdscr, text_lines):
    H, W = stdscr.getmaxyx()
    w = min(W, max(len(l) for l in text_lines) + 4)
    h = min(H, len(text_lines) + 2)
    y0, x0 = max(0, (H - h) // 2), max(0, (W - w) // 2)
    win = curses.newwin(h, w, y0, x0)
    win.box()
    for i, line in enumerate(text_lines[:h - 2]):
        try:
            win.addstr(i + 1, 2, line[:w - 4], curses.A_BOLD if i == 0 else 0)
        except curses.error:
            pass
    win.refresh()
    stdscr.timeout(-1)
    stdscr.getch()
    stdscr.timeout(250)


def show_help(stdscr):
    show_popup(stdscr, HELP_TEXT)


def run(stdscr):
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    stdscr.keypad(True)
    stdscr.timeout(250)
    st = State()
    st.sampler.sample()          # prime CPU deltas
    time.sleep(0.25)
    st.refresh()
    last = time.monotonic()

    while True:
        if time.monotonic() - last >= REFRESH_SECS:
            st.refresh()
            last = time.monotonic()
        draw(stdscr, st)
        ch = stdscr.getch()
        if ch == -1:
            continue

        if st.input_mode:
            if ch in (10, 13, curses.KEY_ENTER):
                st.input_mode = False
            elif ch == 27:
                st.flt = st.input_prev
                st.input_mode = False
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                st.input_buf = st.input_buf[:-1]
                st.flt = st.input_buf
            elif 32 <= ch < 127:
                st.input_buf += chr(ch)
                st.flt = st.input_buf
            st.rebuild()
            continue

        H = stdscr.getmaxyx()[0]
        page = max(1, H - 10)
        if ch in (ord("q"), ord("Q")):
            return
        elif ch == curses.KEY_UP:
            st.move(-1)
        elif ch == curses.KEY_DOWN:
            st.move(1)
        elif ch == curses.KEY_PPAGE:
            st.move(-page)
        elif ch == curses.KEY_NPAGE:
            st.move(page)
        elif ch == curses.KEY_HOME:
            st.move(to=0)
        elif ch == curses.KEY_END:
            st.move(to=len(st.rows) - 1)
        elif ch in (10, 13, curses.KEY_ENTER):
            if st.sel_pid is not None:
                show_popup(stdscr, inspect_lines(st, st.sel_pid))
        elif ch in (32, curses.KEY_LEFT, curses.KEY_RIGHT):
            st.toggle_collapse()
        elif ch in (ord("e"), ord("E")):
            st.show_events = not st.show_events
        elif ch in (curses.KEY_F1, ord("?")):
            show_help(stdscr)
        elif ch in (curses.KEY_F2, ord("t")):
            st.mode = "flat" if st.mode == "tree" else "tree"
            st.rebuild()
        elif ch in (curses.KEY_F3, ord("/")):
            st.input_mode = True
            st.input_prev = st.flt
            st.input_buf = st.flt
        elif ch in (curses.KEY_F4, ord("d")):
            st.show_details = not st.show_details
        elif ch in (curses.KEY_F5, ord("r")):
            st.refresh()
            last = time.monotonic()
        elif ch == ord("k"):
            st.show_kernel = not st.show_kernel
            st.rebuild()
        elif ch == 27:
            if st.flt:
                st.flt = ""
                st.rebuild()


# --------------------------------------------------------------------------
# Web mode (--serve)
# --------------------------------------------------------------------------
WEB_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Process Sentinel</title>
<style>
:root{--bg:#0f1419;--fg:#d6dde6;--dim:#7d8b99;--line:#26303b;--sel:#1f3a5f;--open:#4ade80;--close:#f87171;--info:#7d8b99}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:13px/1.45 ui-monospace,Menlo,Consolas,monospace}
header{display:flex;gap:16px;align-items:center;padding:10px 14px;border-bottom:1px solid var(--line);flex-wrap:wrap}
header h1{font-size:14px;margin:0;letter-spacing:.08em}
header input{background:#18202a;color:var(--fg);border:1px solid var(--line);padding:4px 8px;border-radius:4px;font:inherit}
.sp{flex:1}.dim{color:var(--dim)}
main{display:grid;grid-template-columns:minmax(0,1fr) 340px;grid-template-rows:minmax(0,1fr) 170px;height:calc(100vh - 47px)}
#tree{overflow:auto;border-right:1px solid var(--line)}
table{border-collapse:collapse;width:100%}
th{position:sticky;top:0;background:#151c24;text-align:left;padding:4px 8px;color:var(--dim);font-weight:normal}
td{padding:2px 8px;white-space:pre}
td.n{text-align:right}
tr.row{cursor:pointer}tr.row:hover{background:#18222d}tr.sel{background:var(--sel)!important}
#detail{padding:12px;overflow:auto}
#detail h2{font-size:13px;margin:0 0 8px}
#detail dt{color:var(--dim);margin-top:8px}#detail dd{margin:0;word-break:break-all}
#events{grid-column:1/3;border-top:1px solid var(--line);overflow:auto;padding:6px 12px}
.ev{white-space:pre-wrap}.OPEN{color:var(--open)}.CLOSE{color:var(--close)}.INFO{color:var(--info)}
@media(max-width:800px){main{grid-template-columns:1fr;grid-template-rows:55% auto 150px}#events{grid-column:1}}
</style></head><body>
<header>
 <h1>PROCESS SENTINEL</h1>
 <input id="q" placeholder="filter: name, user, pid, port" size="28">
 <span class="sp"></span>
 <span>CPU <b id="cpu">-</b></span><span>RAM <b id="ram">-</b></span>
 <span class="dim" id="status">connecting</span>
</header>
<main>
 <div id="tree"><table><thead><tr>
  <th>PID</th><th>USER</th><th class="n">CPU%</th><th class="n">RAM%</th><th class="n">PORT</th><th>PROCESS</th>
 </tr></thead><tbody id="rows"></tbody></table></div>
 <div id="detail"></div>
 <div id="events"></div>
</main>
<script>
var rows=[],events=[],sel=null,filter="";
function $(id){return document.getElementById(id);}
function pad2(n){return n<10?"0"+n:""+n;}
function clock(ts){var d=new Date(ts*1000);return pad2(d.getHours())+":"+pad2(d.getMinutes())+":"+pad2(d.getSeconds());}
function cell(tr,text,cls){var td=document.createElement("td");td.textContent=text;if(cls)td.className=cls;tr.appendChild(td);}
function visible(){
  if(!filter)return rows;
  var f=filter.toLowerCase();
  return rows.filter(function(r){
    return (r.name+" "+r.user+" "+r.pid+" "+r.cmd+" "+r.ports.join(" ")).toLowerCase().indexOf(f)>=0;
  });
}
function drawRows(){
  var tb=$("rows");tb.textContent="";
  visible().forEach(function(r){
    var tr=document.createElement("tr");
    tr.className="row"+(r.pid===sel?" sel":"");
    tr.id="p"+r.pid;
    tr.onclick=function(){sel=r.pid;drawRows();drawDetail();};
    cell(tr,r.prefix+r.pid);cell(tr,r.user);
    cell(tr,r.cpu.toFixed(1),"n");cell(tr,r.ram.toFixed(1),"n");
    cell(tr,r.ports.length?r.ports[0].split(":").pop()+(r.ports.length>1?"+":""):"-","n");
    cell(tr,r.name);
    tb.appendChild(tr);
  });
}
function drawDetail(){
  var d=$("detail");d.textContent="";
  var r=rows.filter(function(x){return x.pid===sel;})[0];
  if(!r){d.textContent="No process selected";return;}
  var h=document.createElement("h2");h.textContent=r.name+" (PID "+r.pid+")";d.appendChild(h);
  var dl=document.createElement("dl");
  var parent=rows.filter(function(x){return x.pid===r.ppid;})[0];
  var items=[["User",r.user],["Executable",r.exe||"-"],["Command",r.cmd||"-"],
    ["Parent",r.ppid+(parent?" ("+parent.name+")":"")],
    ["Started",new Date(r.start*1000).toLocaleString()],
    ["CPU / RAM",r.cpu.toFixed(1)+"% / "+r.ram.toFixed(1)+"%"],
    ["Listening",r.ports.length?r.ports.map(function(p){return "TCP "+p;}).join(", "):"-"]];
  items.forEach(function(it){
    var dt=document.createElement("dt");dt.textContent=it[0];
    var dd=document.createElement("dd");dd.textContent=it[1];
    dl.appendChild(dt);dl.appendChild(dd);
  });
  d.appendChild(dl);
}
function drawEvents(){
  var box=$("events");box.textContent="";
  if(!events.length){box.textContent="No network events yet";return;}
  events.slice().reverse().forEach(function(e){
    var div=document.createElement("div");div.className="ev "+e.kind;
    var tag=e.kind==="OPEN"?"+ OPEN ":e.kind==="CLOSE"?"- CLOSE":"* INFO ";
    div.textContent=clock(e.t)+" "+tag+" "+e.text;
    box.appendChild(div);
  });
}
function tick(){
  fetch("/api/state").then(function(r){return r.json();}).then(function(d){
    $("cpu").textContent=d.cpu.toFixed(0)+"%";$("ram").textContent=d.ram.toFixed(0)+"%";
    rows=d.rows;events=d.events;
    if(sel===null||!rows.some(function(r){return r.pid===sel;}))sel=rows.length?rows[0].pid:null;
    drawRows();drawDetail();drawEvents();$("status").textContent="live";
  }).catch(function(){$("status").textContent="disconnected";});
}
$("q").oninput=function(e){filter=e.target.value;drawRows();};
document.addEventListener("keydown",function(e){
  if(e.target.id==="q"||(e.key!=="ArrowUp"&&e.key!=="ArrowDown"))return;
  var v=visible();if(!v.length)return;
  var i=v.findIndex(function(r){return r.pid===sel;});
  i=Math.max(0,Math.min(v.length-1,i+(e.key==="ArrowDown"?1:-1)));
  sel=v[i].pid;drawRows();drawDetail();
  var el=$("p"+sel);if(el)el.scrollIntoView({block:"nearest"});
  e.preventDefault();
});
tick();setInterval(tick,1000);
</script></body></html>
"""


def snapshot(st):
    rows = []
    for pid, prefix, mark in st.rows:
        p = st.procs[pid]
        rows.append({
            "pid": pid, "prefix": prefix, "ppid": p.ppid, "user": p.user,
            "cpu": round(p.cpu, 1), "ram": round(p.ram, 1), "name": p.name,
            "exe": p.exe, "cmd": p.cmdline, "start": p.start,
            "ports": [fmt_endpoint(ip, pt) for ip, pt in p.ports],
        })
    events = [{"t": ts, "kind": k, "text": t} for ts, k, t in list(st.events)[-100:]]
    return {"cpu": st.cpu, "ram": st.ram, "rows": rows, "events": events}


def serve(host, port):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    st = State()
    lock = threading.Lock()
    st.sampler.sample()
    time.sleep(0.4)
    st.refresh()

    def loop():
        while True:
            time.sleep(REFRESH_SECS)
            with lock:
                try:
                    st.refresh()
                except Exception:
                    pass

    threading.Thread(target=loop, daemon=True).start()

    class SentinelHandler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, ctype, body):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                self._send(200, "text/html; charset=utf-8", WEB_PAGE.encode())
            elif path == "/api/state":
                with lock:
                    data = snapshot(st)
                self._send(200, "application/json", json.dumps(data).encode())
            else:
                self._send(404, "text/plain", b"not found")

    try:
        srv = ThreadingHTTPServer((host, port), SentinelHandler)
    except OSError as e:
        sys.exit(f"cannot listen on {host}:{port}: {e}")
    shown = "127.0.0.1" if host in ("0.0.0.0", "") else host
    print(f"Process Sentinel running on http://{shown}:{port}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


def main():
    args = sys.argv[1:]
    if "-h" in args or "--help" in args:
        print(__doc__)
        return
    if not USE_PROC:
        try:
            import psutil  # noqa: F401
        except ImportError:
            sys.exit("On Windows/macOS this needs psutil. Run: pip install psutil")

    def opt(name, default):
        if name in args:
            try:
                return int(args[args.index(name) + 1])
            except (IndexError, ValueError):
                sys.exit(f"{name} needs a number")
        return default

    if "--serve" in args:
        host = "127.0.0.1"
        if "--host" in args:
            try:
                host = args[args.index("--host") + 1]
            except IndexError:
                sys.exit("--host needs an address")
        serve(host, opt("--port", 8000))
        return

    if "--once" in args:
        st = State()
        st.sampler.sample()
        time.sleep(0.4)
        st.refresh()
        # select our own bash/python for a meaningful details panel
        st.sel_pid = os.getpid()
        st.rebuild()
        lines, _ = render(st, opt("--width", 78), opt("--height", 28))
        print("\n".join(lines))
        return

    if curses is None:
        sys.exit("The terminal UI needs curses. On Windows run: pip install windows-curses\n"
                 "Or use the browser UI instead: python process_sentinel.py --serve")
    locale.setlocale(locale.LC_ALL, "")
    try:
        curses.wrapper(run)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()