"""Data Collection Layer (Fig 3.1) — ICMP, TCP-fallback, optional SNMP, and
clearly-labelled simulated probes.

Each probe returns a ProbeResult; nothing in here touches the database.
"""
from __future__ import annotations

import ipaddress
import logging
import math
import platform
import random
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")


@dataclass
class ProbeResult:
    reachable: bool
    latency_ms: float | None = None
    packet_loss_percent: float | None = None
    method: str = "icmp"
    error: str | None = None
    cpu_percent: float | None = None
    memory_percent: float | None = None
    raw: dict = field(default_factory=dict)


# ------------------------------------------------------------------ validation
def validate_host(value: str) -> str:
    """Return a normalised IP address or hostname, or raise ValueError.

    Guards against argument injection into the ping command (e.g. '-f')."""
    value = (value or "").strip()
    if not value:
        raise ValueError("IP address or hostname is required.")
    if len(value) > 253:
        raise ValueError("Address is too long.")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if value.startswith("-") or not HOSTNAME_RE.match(value) or value.replace(".", "").isdigit():
        raise ValueError("Enter a valid IPv4/IPv6 address or hostname (e.g. 192.168.1.1 or router.local).")
    return value.lower().rstrip(".")


# ------------------------------------------------------------------ ICMP via OS ping
def _is_windows():
    return platform.system().lower().startswith("win")


def build_ping_command(host: str, count: int, timeout_s: float):
    exe = shutil.which("ping")
    if not exe:
        return None
    is_v6 = ":" in host
    if _is_windows():
        cmd = [exe, "-n", str(count), "-w", str(int(timeout_s * 1000))]
        if is_v6:
            cmd.append("-6")
    else:
        cmd = [exe, "-c", str(count), "-W", str(max(1, math.ceil(timeout_s)))]
        if platform.system() == "Linux":
            cmd += ["-i", "0.2"]
        if is_v6:
            cmd.append("-6")
    cmd.append(host)  # host already validated; list-form args => no shell
    return cmd


_LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)%\s*(?:packet\s+)?loss", re.I)
_SENT_RECV_RE = re.compile(r"(\d+)\s+packets?\s+transmitted,\s*(\d+)\s+(?:packets\s+)?received", re.I)
_RTT_RE = re.compile(r"(?:rtt|round-trip)[^=]*=\s*([\d.]+)/([\d.]+)/([\d.]+)", re.I)
_WIN_SENT_RE = re.compile(r"Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+)", re.I)
_WIN_AVG_RE = re.compile(r"Average\s*=\s*(\d+)\s*ms", re.I)
_WIN_REPLY_RE = re.compile(r"time[=<](\d+)ms.*TTL=", re.I)


def parse_ping_output(output: str, count: int) -> tuple[float | None, float | None]:
    """Return (packet_loss_percent, avg_latency_ms) parsed from ping output.

    Supports Linux iputils, BusyBox, macOS/BSD and Windows formats."""
    loss = avg = None
    m = _SENT_RECV_RE.search(output)
    if m:
        sent, recv = int(m.group(1)), int(m.group(2))
        loss = round((sent - recv) / sent * 100, 1) if sent else None
    else:
        replies = _WIN_REPLY_RE.findall(output)
        if _WIN_SENT_RE.search(output):
            # Windows counts "Destination host unreachable" as Received, so count real TTL replies.
            sent = int(_WIN_SENT_RE.search(output).group(1))
            loss = round((sent - len(replies)) / sent * 100, 1) if sent else None
            win_avg = _WIN_AVG_RE.search(output)
            if replies and win_avg:
                avg = float(win_avg.group(1))  # Windows' own average (handles "time<1ms")
            elif replies:
                avg = round(sum(int(r) for r in replies) / len(replies), 3)
        elif _LOSS_RE.search(output):
            loss = float(_LOSS_RE.search(output).group(1))
    r = _RTT_RE.search(output)
    if r:
        avg = float(r.group(2))
    elif avg is None and _WIN_AVG_RE.search(output) and loss is not None and loss < 100:
        avg = float(_WIN_AVG_RE.search(output).group(1))
    return loss, avg


class IcmpUnavailable(Exception):
    """Raised when the host OS will not let us send ICMP (no binary / no permission)."""


def icmp_probe(host: str, count: int = 4, timeout_s: float = 2.0) -> ProbeResult:
    cmd = build_ping_command(host, count, timeout_s)
    if cmd is None:
        raise IcmpUnavailable("ping command not found")
    deadline = count * (timeout_s + 0.5) + 5
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=deadline)
    except subprocess.TimeoutExpired:
        return ProbeResult(False, None, 100.0, "icmp", "Ping timed out")
    except (PermissionError, OSError) as exc:
        raise IcmpUnavailable(str(exc)) from exc
    out = (proc.stdout or "") + (proc.stderr or "")
    lowered = out.lower()
    if "operation not permitted" in lowered or "permission denied" in lowered or "socket:" in lowered:
        raise IcmpUnavailable(out.strip()[:200])
    if "unknown host" in lowered or "name or service not known" in lowered or "could not find host" in lowered \
            or "temporary failure in name resolution" in lowered:
        return ProbeResult(False, None, 100.0, "icmp", "Hostname could not be resolved")
    loss, avg = parse_ping_output(out, count)
    if loss is None:
        if proc.returncode not in (0, 1):
            raise IcmpUnavailable(out.strip()[:200] or f"ping exited {proc.returncode}")
        loss = 0.0 if proc.returncode == 0 else 100.0
    reachable = loss < 100
    err = None if reachable else "No echo replies received (device down, or ICMP blocked by a firewall)"
    return ProbeResult(reachable, avg if reachable else None, loss, "icmp", err, raw={"output": out[-500:]})


# ------------------------------------------------------------------ TCP connect fallback
def tcp_probe(host: str, ports=(80, 443, 22), count: int = 4, timeout_s: float = 2.0) -> ProbeResult:
    """Reachability + round-trip estimate via TCP handshake.

    A completed handshake OR an immediate refusal (RST) both prove the host is
    up; a timeout counts as a lost probe. Used where ICMP is unavailable (many
    cloud hosts). The method is recorded on the result so it is never confused
    with ICMP."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        family, addr = infos[0][0], infos[0][4][0]
    except socket.gaierror:
        return ProbeResult(False, None, 100.0, "tcp", "Hostname could not be resolved")

    def attempt(port):
        start = time.perf_counter()
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        try:
            s.connect((addr, port))
            return (time.perf_counter() - start) * 1000
        except ConnectionRefusedError:
            return (time.perf_counter() - start) * 1000
        except OSError:
            return None
        finally:
            s.close()

    port_used, rtts, sent = None, [], 0
    for p in ports:  # discover a responsive port (bounded time for down hosts)
        sent = 1
        rtt = attempt(p)
        if rtt is not None:
            port_used, rtts = p, [rtt]
            break
    if port_used is None:
        return ProbeResult(False, None, 100.0, "tcp",
                           f"No TCP response on ports {', '.join(map(str, ports))} (timeout)")
    for _ in range(count - 1):
        sent += 1
        rtt = attempt(port_used)
        if rtt is not None:
            rtts.append(rtt)
    loss = round((sent - len(rtts)) / sent * 100, 1)
    return ProbeResult(True, round(sum(rtts) / len(rtts), 3), loss, "tcp", None, raw={"port": port_used})


# ------------------------------------------------------------------ optional SNMP
def snmp_probe(host: str, community: str, timeout_s: float = 2.0):
    """Optional SNMP v2c collection (§2.2.6). Returns (cpu%, mem%, error).

    CPU: HOST-RESOURCES-MIB hrProcessorLoad (averaged across processors).
    Memory: UCD-SNMP-MIB memTotalReal / memAvailReal (Net-SNMP agents).
    Devices that do not expose these OIDs simply return None for that metric."""
    try:
        import asyncio
        from pysnmp.hlapi.v3arch.asyncio import (CommunityData, ContextData, ObjectIdentity, ObjectType,
                                                 SnmpEngine, UdpTransportTarget, get_cmd, walk_cmd)
    except ImportError:
        return None, None, "pysnmp is not installed"

    async def run():
        engine = SnmpEngine()
        target = await UdpTransportTarget.create((host, 161), timeout=timeout_s, retries=0)
        auth = CommunityData(community or "public", mpModel=1)
        cpu_vals = []
        async for err_ind, err_stat, _i, binds in walk_cmd(
                engine, auth, target, ContextData(), ObjectType(ObjectIdentity("1.3.6.1.2.1.25.3.3.1.2")),
                lexicographicMode=False):
            if err_ind or err_stat:
                break
            cpu_vals += [float(v) for _o, v in binds]
        cpu = round(sum(cpu_vals) / len(cpu_vals), 1) if cpu_vals else None
        mem = None
        err_ind, err_stat, _i, binds = await get_cmd(
            engine, auth, target, ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.4.1.2021.4.5.0")),
            ObjectType(ObjectIdentity("1.3.6.1.4.1.2021.4.6.0")))
        if not err_ind and not err_stat:
            try:
                total, avail = float(binds[0][1]), float(binds[1][1])
                if total > 0:
                    mem = round((total - avail) / total * 100, 1)
            except (TypeError, ValueError):
                mem = None
        engine.close_dispatcher()
        if cpu is None and mem is None:
            return None, None, "SNMP agent did not answer (check community string / UDP 161)"
        return cpu, mem, None

    try:
        return asyncio.run(asyncio.wait_for(run(), timeout=timeout_s * 4 + 2))
    except Exception as exc:  # never let SNMP break a check (NFR2)
        log.info("SNMP probe of %s failed: %s", host, exc)
        return None, None, "SNMP query failed"


# ------------------------------------------------------------------ simulated (demo mode)
def simulated_probe(device_id: int, profile: str | None, device_type: str, now: float | None = None,
                    rng: random.Random | None = None) -> ProbeResult:
    """Realistic *synthetic* measurement for demonstration devices.

    Always tagged method='simulated'. Profiles:
      stable   — low latency, rare minor loss
      degraded — latency drifts high during 'business hours' (breaches thresholds)
      flaky    — goes down for ~12 minutes in every hour
    """
    rng = rng or random.Random()
    now = now if now is not None else time.time()
    base = {"router": 2.0, "switch": 1.2, "server": 4.0, "access_point": 6.0, "firewall": 2.5}.get(device_type, 5.0)
    profile = profile or "stable"
    if profile == "flaky":
        phase = (now + device_id * 137) % 3600
        if phase < 720:
            return ProbeResult(False, None, 100.0, "simulated", "Simulated outage")
        lat = base * 3 + rng.gauss(0, base)
        loss = 50.0 if rng.random() < 0.04 else (25.0 if rng.random() < 0.1 else 0.0)
    elif profile == "degraded":
        wave = (math.sin((now + device_id * 911) / 1800.0) + 1) / 2  # 0..1, ~3h period
        lat = 190 + wave * 140 + rng.gauss(0, 10)  # persistently above a 150 ms warning rule
        loss = 50.0 if wave > 0.8 and rng.random() < 0.1 else 0.0
    else:
        lat = base + abs(rng.gauss(0, base * 0.35))
        loss = 25.0 if rng.random() < 0.02 else 0.0
    lat = round(max(0.2, lat), 2)
    cpu = round(min(99, max(2, 25 + rng.gauss(0, 10) + (30 if profile == "degraded" else 0))), 1)
    mem = round(min(99, max(5, 55 + rng.gauss(0, 6))), 1)
    return ProbeResult(True, lat, loss, "simulated", None, cpu_percent=cpu, memory_percent=mem)


# ------------------------------------------------------------------ dispatcher
_icmp_broken = {"flag": False}


def probe(host: str, *, method: str = "auto", count: int = 4, timeout_s: float = 2.0,
          tcp_ports=(80, 443, 22)) -> ProbeResult:
    """Run the configured reachability check against a real host."""
    if method == "tcp":
        return tcp_probe(host, tcp_ports, count, timeout_s)
    if method == "icmp" or not _icmp_broken["flag"]:
        try:
            return icmp_probe(host, count, timeout_s)
        except IcmpUnavailable as exc:
            if method == "icmp":
                return ProbeResult(False, None, None, "icmp", f"ICMP unavailable on this host: {exc}"[:255])
            log.warning("ICMP unavailable (%s); falling back to TCP-connect probes", exc)
            _icmp_broken["flag"] = True
    return tcp_probe(host, tcp_ports, count, timeout_s)


def icmp_status():
    """For the Settings page: which method will actually be used."""
    return {"ping_binary": shutil.which("ping"), "icmp_fallback_active": _icmp_broken["flag"]}
