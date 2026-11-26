#!/usr/bin/env python3
"""Netwatch on-site agent - monitors devices on a private network (LAN) for a cloud Netwatch server.

Why it exists
    A cloud server cannot reach private addresses such as 192.168.1.1 or 10.150.121.187: they only
    exist inside the local network. This agent runs on any computer INSIDE that network, checks the
    devices assigned to its site, and sends the results to Netwatch over HTTPS. It only makes outgoing
    connections, so no router configuration, port forwarding or public IP address is needed.

Requirements
    Python 3.9 or newer. Nothing else - it uses only the Python standard library.

Usage
    python netwatch_agent.py --server https://your-netwatch.onrender.com --key nwa_... --save
    python netwatch_agent.py --once        one round of checks, print the results, exit
    python netwatch_agent.py               run continuously (leave the window open)
    python netwatch_agent.py --scan        list the addresses that answer on this computer's network
    python netwatch_agent.py --scan 192.168.1.0/24

Settings are read from (highest priority first): command-line options, the environment variables
NETWATCH_SERVER and NETWATCH_AGENT_KEY, then netwatch-agent.ini next to this file (written by --save).
"""
from __future__ import annotations

import argparse
import configparser
import ipaddress
import json
import math
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

VERSION = "1.0.0"
CONFIG_FILE = Path(__file__).resolve().with_name("netwatch-agent.ini")
HTTP_TIMEOUT = 75  # a free cloud host may take ~1 minute to wake up
MAX_WORKERS = 16


# =================================================================== output
def log(msg: str) -> None:
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S}  {msg}", flush=True)


# =================================================================== probing (same rules as the server)
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")


def validate_host(value: str) -> str:
    """Reject anything that is not a plain IP address or hostname (guards the ping command)."""
    value = (value or "").strip()
    if not value or len(value) > 253:
        raise ValueError("bad address")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if value.startswith("-") or not HOSTNAME_RE.match(value) or value.replace(".", "").isdigit():
        raise ValueError("bad address")
    return value.lower().rstrip(".")


def _is_windows() -> bool:
    return platform.system().lower().startswith("win")


def build_ping_command(host: str, count: int, timeout_s: float):
    exe = shutil.which("ping")
    if not exe:
        return None
    is_v6 = ":" in host
    if _is_windows():
        cmd = [exe, "-n", str(count), "-w", str(int(timeout_s * 1000))]
    else:
        cmd = [exe, "-c", str(count), "-W", str(max(1, math.ceil(timeout_s)))]
        if platform.system() == "Linux":
            cmd += ["-i", "0.2"]
    if is_v6:
        cmd.append("-6")
    cmd.append(host)
    return cmd


_SENT_RECV_RE = re.compile(r"(\d+)\s+packets?\s+transmitted,\s*(\d+)\s+(?:packets\s+)?received", re.I)
_LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)%\s*(?:packet\s+)?loss", re.I)
_RTT_RE = re.compile(r"(?:rtt|round-trip)[^=]*=\s*([\d.]+)/([\d.]+)/([\d.]+)", re.I)
_WIN_SENT_RE = re.compile(r"Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+)", re.I)
_WIN_AVG_RE = re.compile(r"Average\s*=\s*(\d+)\s*ms", re.I)
_WIN_REPLY_RE = re.compile(r"time[=<](\d+)ms.*TTL=", re.I)


def parse_ping_output(output: str, count: int):
    """Return (packet_loss_percent, avg_latency_ms). Linux, BusyBox, macOS/BSD and Windows formats."""
    loss = avg = None
    m = _SENT_RECV_RE.search(output)
    if m:
        sent, recv = int(m.group(1)), int(m.group(2))
        loss = round((sent - recv) / sent * 100, 1) if sent else None
    else:
        replies = _WIN_REPLY_RE.findall(output)
        win_sent = _WIN_SENT_RE.search(output)
        if win_sent:
            # Windows counts "Destination host unreachable" as Received, so count real TTL replies.
            sent = int(win_sent.group(1))
            loss = round((sent - len(replies)) / sent * 100, 1) if sent else None
            win_avg = _WIN_AVG_RE.search(output)
            if replies and win_avg:
                avg = float(win_avg.group(1))
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
    pass


def icmp_probe(host: str, count: int, timeout_s: float) -> dict:
    cmd = build_ping_command(host, count, timeout_s)
    if cmd is None:
        raise IcmpUnavailable("ping command not found")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                              timeout=count * (timeout_s + 0.5) + 5)
    except subprocess.TimeoutExpired:
        return {"reachable": False, "latency_ms": None, "packet_loss_percent": 100.0, "method": "icmp",
                "error": "Ping timed out"}
    except OSError as exc:
        raise IcmpUnavailable(str(exc)) from exc
    out = (proc.stdout or "") + (proc.stderr or "")
    low = out.lower()
    if "operation not permitted" in low or "permission denied" in low:
        raise IcmpUnavailable(out.strip()[:200])
    if ("unknown host" in low or "name or service not known" in low or "could not find host" in low
            or "temporary failure in name resolution" in low):
        return {"reachable": False, "latency_ms": None, "packet_loss_percent": 100.0, "method": "icmp",
                "error": "Hostname could not be resolved"}
    loss, avg = parse_ping_output(out, count)
    if loss is None:
        if proc.returncode not in (0, 1):
            raise IcmpUnavailable(out.strip()[:200] or f"ping exited {proc.returncode}")
        loss = 0.0 if proc.returncode == 0 else 100.0
    reachable = loss < 100
    return {"reachable": reachable, "latency_ms": avg if reachable else None, "packet_loss_percent": loss,
            "method": "icmp",
            "error": None if reachable else "No echo replies received (device down, or ICMP blocked by a firewall)"}


_lock = threading.Lock()
_refusal = {"trusted": None, "checked_at": 0.0}
# Reserved for documentation (RFC 5737): no real host can ever have this address.
CANARY = ("203.0.113.1", 9)


def refusals_are_trustworthy() -> bool:
    """A refused TCP connection normally proves the host is alive (it answered with a reset). Some
    firewalls, VPN clients and security products instead refuse EVERY connection themselves, which
    would make switched-off devices look up. Test once (re-tested every 10 minutes) with an address
    that cannot exist: if even that is 'refused', only completed connections count as proof of life."""
    with _lock:
        if _refusal["trusted"] is not None and time.monotonic() - _refusal["checked_at"] < 600:
            return _refusal["trusted"]
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try:
            s.connect(CANARY)
            trusted = False  # something answered for a non-existent host
        except ConnectionRefusedError:
            trusted = False
        except OSError:
            trusted = True  # timeout / unreachable: the normal behaviour
        finally:
            s.close()
        if _refusal["trusted"] is None and not trusted:
            log("Note: this network answers connections on behalf of hosts that do not exist (firewall/VPN/"
                "security software). TCP checks will only count completed connections.")
        _refusal.update(trusted=trusted, checked_at=time.monotonic())
        return trusted


def tcp_probe(host: str, ports, count: int, timeout_s: float) -> dict:
    """Reachability via TCP handshake: a completed connection or an immediate refusal both prove the
    host is up. Used when ICMP gets no reply (many PCs and phones block ping)."""
    try:
        family, _t, _p, _c, sockaddr = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)[0]
        addr = sockaddr[0]
    except socket.gaierror:
        return {"reachable": False, "latency_ms": None, "packet_loss_percent": 100.0, "method": "tcp",
                "error": "Hostname could not be resolved"}
    trust_refusal = refusals_are_trustworthy() or ipaddress.ip_address(addr).is_loopback

    def attempt(port):
        start = time.perf_counter()
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        try:
            s.connect((addr, port))
            return (time.perf_counter() - start) * 1000
        except ConnectionRefusedError:
            return (time.perf_counter() - start) * 1000 if trust_refusal else None
        except OSError:
            return None
        finally:
            s.close()

    port_used, rtts, sent = None, [], 0
    for p in ports:
        sent = 1
        rtt = attempt(p)
        if rtt is not None:
            port_used, rtts = p, [rtt]
            break
    if port_used is None:
        return {"reachable": False, "latency_ms": None, "packet_loss_percent": 100.0, "method": "tcp",
                "error": f"No response to ping or on TCP ports {', '.join(map(str, ports))}"}
    for _ in range(count - 1):
        sent += 1
        rtt = attempt(port_used)
        if rtt is not None:
            rtts.append(rtt)
    return {"reachable": True, "latency_ms": round(sum(rtts) / len(rtts), 3),
            "packet_loss_percent": round((sent - len(rtts)) / sent * 100, 1), "method": "tcp", "error": None}


_icmp_broken = {"flag": False}


def probe(host: str, settings: dict) -> dict:
    method = settings.get("method", "auto")
    count = int(settings.get("ping_count", 4))
    timeout_s = float(settings.get("timeout_seconds", 2))
    ports = [int(p) for p in settings.get("tcp_ports") or [80, 443, 22]]
    if method == "tcp" or _icmp_broken["flag"]:
        return tcp_probe(host, ports, count, timeout_s)
    try:
        res = icmp_probe(host, count, timeout_s)
    except IcmpUnavailable as exc:
        if method == "icmp":
            return {"reachable": False, "latency_ms": None, "packet_loss_percent": None, "method": "icmp",
                    "error": f"ICMP unavailable on the agent computer: {exc}"[:255]}
        with _lock:
            if not _icmp_broken["flag"]:
                log(f"ICMP is not available on this computer ({exc}); using TCP checks instead")
            _icmp_broken["flag"] = True
        return tcp_probe(host, ports, count, timeout_s)
    if res["reachable"] or method == "icmp":
        return res
    # No ping reply. Many Windows PCs and phones drop ping but are up: confirm over TCP before
    # reporting the device as unreachable.
    tcp = tcp_probe(host, ports, max(1, min(count, 2)), timeout_s)
    if tcp["reachable"]:
        return tcp
    return res


# =================================================================== server API
class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class Client:
    def __init__(self, server: str, key: str):
        self.server = server.rstrip("/")
        self.key = key
        self.info = {"hostname": socket.gethostname()[:100], "version": VERSION,
                     "platform": f"{platform.system()} {platform.release()} / Python {platform.python_version()}"[:100]}

    def _call(self, path: str, body: dict) -> dict:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.server + path, data=data, method="POST", headers={
            "Authorization": f"Bearer {self.key}", "Content-Type": "application/json",
            "Accept": "application/json", "User-Agent": f"netwatch-agent/{VERSION}"})
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read().decode("utf-8")).get("message", "")
            except Exception:
                detail = ""
            if exc.code == 422:  # nothing stored; the body explains why
                return {"stored": 0, "rejected": [{"error": detail or "rejected"}]}
            raise ApiError(exc.code, detail or f"HTTP {exc.code} from server") from None
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise ApiError(0, f"cannot reach {self.server} ({reason})") from None

    def jobs(self) -> dict:
        return self._call("/api/agent/v1/jobs", self.info)

    def send(self, results: list) -> dict:
        return self._call("/api/agent/v1/results", {"agent": self.info, "results": results})


def run_jobs(jobs: list, settings: dict) -> list:
    def one(job):
        try:
            host = validate_host(job.get("host", ""))
        except ValueError:
            return {"device_id": job.get("device_id"), "reachable": False, "latency_ms": None,
                    "packet_loss_percent": None, "method": "icmp", "error": "Invalid address from server"}
        try:
            res = probe(host, settings)
        except Exception as exc:  # never let one device stop the others
            res = {"reachable": False, "latency_ms": None, "packet_loss_percent": None, "method": "icmp",
                   "error": f"Agent error: {type(exc).__name__}"}
        res["device_id"] = job.get("device_id")
        return res

    if not jobs:
        return []
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(jobs))) as pool:
        return list(pool.map(one, jobs))


def describe(job: dict, res: dict) -> str:
    state = "UP  " if res["reachable"] else "DOWN"
    lat = f"{res['latency_ms']:.1f} ms" if res.get("latency_ms") is not None else "-"
    loss = f"{res['packet_loss_percent']:g}%" if res.get("packet_loss_percent") is not None else "-"
    extra = f"  {res['error']}" if res.get("error") and not res["reachable"] else ""
    return f"  {state} {job.get('name', '?')[:28]:28} {job.get('host', ''):18} {lat:>10}  loss {loss:>5}  [{res['method']}]{extra}"


def cycle(client: Client, verbose: bool = True):
    """One round: fetch due devices, check them, report. Returns the server's poll interval."""
    info = client.jobs()
    jobs = info.get("jobs") or []
    settings = info.get("probe") or {}
    if jobs:
        results = run_jobs(jobs, settings)
        reply = client.send(results)
        by_id = {j.get("device_id"): j for j in jobs}
        if verbose:
            for r in results:
                log(describe(by_id.get(r["device_id"], {}), r))
        for rej in reply.get("rejected") or []:
            log(f"  server did not store device {rej.get('device_id', '?')}: {rej.get('error')}")
    return info, len(jobs)


def run_forever(client: Client) -> int:
    log(f"Netwatch agent {VERSION} on {client.info['hostname']} -> {client.server}")
    log("Press Ctrl+C to stop. Keep this window open while you want the network monitored.")
    backoff, announced = 5, False
    while True:
        try:
            info, n = cycle(client)
            if not announced:
                site = info.get("site", {}).get("name", "?")
                log(f"Connected to site '{site}': {info.get('device_count', 0)} device(s) assigned.")
                if not info.get("device_count"):
                    log("No devices are assigned to this site yet - add them in Netwatch (Sites > this site > Add device).")
                announced = True
            backoff = 5
            time.sleep(max(3, int(info.get("poll_seconds", 10))))
        except ApiError as exc:
            if exc.status == 401:
                log(f"The server rejected the agent key: {exc}")
                log("Fix: copy the key from the site's page in Netwatch and run again with --key ... --save")
                return 2
            if exc.status == 403:
                log(f"Site disabled: {exc} - retrying in 60 s")
                time.sleep(60)
                continue
            log(f"Problem talking to the server: {exc} - retrying in {backoff} s")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
            announced = False


def run_once(client: Client) -> int:
    log(f"Netwatch agent {VERSION}: one round of checks against {client.server}")
    try:
        # A device is only 'due' when its interval has passed; the first round after starting
        # usually includes every device.
        info, n = cycle(client)
    except ApiError as exc:
        log(f"FAILED: {exc}")
        if exc.status == 401:
            log("The agent key is wrong. Copy it from the site's page in Netwatch (or create a new key there).")
        elif exc.status == 0:
            log("Check the --server address and this computer's internet connection.")
        return 2
    site = info.get("site", {}).get("name", "?")
    log(f"Connected to site '{site}'. {info.get('device_count', 0)} device(s) assigned; {n} checked now.")
    if info.get("device_count") and not n:
        log("No device was due this round (they were checked recently). Run without --once to keep monitoring.")
    if not info.get("device_count"):
        log("Add devices to this site in Netwatch, then run again.")
    return 0


# =================================================================== network scan helper
def local_ipv4() -> str | None:
    """The address this computer uses on its LAN (no packets are actually sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def scan(cidr: str | None) -> int:
    if not cidr:
        ip = local_ipv4()
        if not ip:
            print("Could not work out this computer's network. Give it explicitly, e.g. --scan 192.168.1.0/24")
            return 2
        cidr = str(ipaddress.ip_network(f"{ip}/24", strict=False))
        print(f"This computer is {ip}; scanning {cidr} (assuming a /24 network).")
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        print(f"'{cidr}' is not a network, e.g. 192.168.1.0/24")
        return 2
    if net.num_addresses > 1024:
        print("That network is too large to scan; use a /22 or smaller (at most 1024 addresses).")
        return 2
    hosts = [str(h) for h in net.hosts()]
    print(f"Pinging {len(hosts)} addresses, please wait about {max(5, len(hosts) // 64 * 2)} seconds...")

    def ping1(h):
        cmd = build_ping_command(h, 1, 1.0)
        if cmd is None:
            return None
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            return None
        loss, avg = parse_ping_output(p.stdout + p.stderr, 1)
        return (h, avg) if loss is not None and loss < 100 else None

    with ThreadPoolExecutor(max_workers=64) as pool:
        found = [r for r in pool.map(ping1, hosts) if r]
    if not found:
        print("No device answered ping. Some devices (Windows PCs, phones) ignore ping; your router usually answers.")
        return 1
    print(f"\n{len(found)} address(es) answered:\n")
    me = local_ipv4()
    for h, avg in found:
        note = "  <- this computer" if h == me else ""
        lat = f"{avg:.0f} ms" if avg is not None else ""
        print(f"  {h:18} {lat:>7}{note}")
    print("\nTip: on Windows, 'ipconfig' shows the router as 'Default Gateway'. Register the addresses you want")
    print("monitored in Netwatch under this site.")
    return 0


# =================================================================== settings
def load_settings(args) -> tuple[str, str]:
    cfg = configparser.ConfigParser()
    if CONFIG_FILE.is_file():
        cfg.read(CONFIG_FILE, encoding="utf-8")
    section = cfg["agent"] if cfg.has_section("agent") else {}
    server = args.server or os.environ.get("NETWATCH_SERVER") or section.get("server", "")
    key = args.key or os.environ.get("NETWATCH_AGENT_KEY") or section.get("key", "")
    return server.strip().rstrip("/"), key.strip()


def save_settings(server: str, key: str) -> None:
    cfg = configparser.ConfigParser()
    cfg["agent"] = {"server": server, "key": key}
    with open(CONFIG_FILE, "w", encoding="utf-8") as fh:
        fh.write("# Netwatch agent settings. Keep this file private: the key works like a password.\n")
        cfg.write(fh)
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Netwatch on-site agent: monitors private-network devices for a cloud Netwatch server.")
    p.add_argument("--server", help="Netwatch address, e.g. https://netwatch-yegu.onrender.com")
    p.add_argument("--key", help="agent key from the site's page in Netwatch (starts with nwa_)")
    p.add_argument("--save", action="store_true", help=f"remember --server and --key in {CONFIG_FILE.name}")
    p.add_argument("--once", action="store_true", help="run one round of checks and exit")
    p.add_argument("--scan", nargs="?", const="", metavar="NETWORK",
                   help="list devices that answer ping on this network (default: this computer's /24)")
    p.add_argument("--version", action="version", version=f"netwatch-agent {VERSION}")
    args = p.parse_args(argv)

    if args.scan is not None:
        return scan(args.scan or None)

    server, key = load_settings(args)
    if not server or not key:
        print("Missing settings. Run once with:\n  python netwatch_agent.py --server https://YOUR-NETWATCH --key nwa_... --save")
        return 2
    if not server.startswith(("https://", "http://")):
        server = "https://" + server
    if server.startswith("http://") and not re.match(r"^http://(localhost|127\.|10\.|192\.168\.)", server):
        print("Warning: the server address uses http://, so the agent key is sent unencrypted. Use https:// if possible.")
    if not key.startswith("nwa_"):
        print("That does not look like a Netwatch agent key (it should start with nwa_).")
        return 2
    if args.save:
        save_settings(server, key)
        print(f"Saved to {CONFIG_FILE}. Next time just run:  python {Path(__file__).name}")
    client = Client(server, key)
    try:
        return run_once(client) if args.once else run_forever(client)
    except KeyboardInterrupt:
        log("Stopped.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
