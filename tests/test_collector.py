"""FR5 — data collection layer: ping parsing, probes, timeouts, simulated values."""
import sys
import time

import pytest

from conftest import REFUSAL_TIMEOUT_S
from netwatch.services import collector
from netwatch.services.collector import ProbeResult, parse_ping_output, validate_host

LINUX_OK = """PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.12 ms
--- 192.168.1.1 ping statistics ---
4 packets transmitted, 3 received, 25% packet loss, time 603ms
rtt min/avg/max/mdev = 0.981/1.204/1.503/0.221 ms"""
LINUX_DOWN = """PING 10.9.9.9 (10.9.9.9) 56(84) bytes of data.
--- 10.9.9.9 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3061ms"""
BUSYBOX = """--- 8.8.8.8 ping statistics ---
4 packets transmitted, 4 packets received, 0% packet loss
round-trip min/avg/max = 10.1/12.5/15.0 ms"""
MAC = """--- 1.1.1.1 ping statistics ---
4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 5.0/6.25/8.0/1.1 ms"""
WINDOWS_OK = """Pinging 192.168.1.1 with 32 bytes of data:
Reply from 192.168.1.1: bytes=32 time=2ms TTL=64
Reply from 192.168.1.1: bytes=32 time=4ms TTL=64
Reply from 192.168.1.1: bytes=32 time<1ms TTL=64
Request timed out.

Ping statistics for 192.168.1.1:
    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 4ms, Average = 2ms"""
WINDOWS_UNREACH = """Pinging 192.168.1.250 with 32 bytes of data:
Reply from 192.168.1.5: Destination host unreachable.
Reply from 192.168.1.5: Destination host unreachable.
Reply from 192.168.1.5: Destination host unreachable.
Reply from 192.168.1.5: Destination host unreachable.

Ping statistics for 192.168.1.250:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),"""


@pytest.mark.parametrize("text,loss,avg", [(LINUX_OK, 25.0, 1.204), (LINUX_DOWN, 100.0, None),
                                           (BUSYBOX, 0.0, 12.5), (MAC, 0.0, 6.25), (WINDOWS_OK, 25.0, 2.0),
                                           (WINDOWS_UNREACH, 100.0, None)])
def test_parse_ping_output(text, loss, avg):
    assert parse_ping_output(text, 4) == (loss, avg)


@pytest.mark.parametrize("value,expected", [("192.168.001.1", None), (" 10.0.0.1 ", "10.0.0.1"),
                                            ("Router.Local.", "router.local"), ("fe80::1", "fe80::1")])
def test_validate_host(value, expected):
    if expected is None:
        with pytest.raises(ValueError):
            validate_host(value)
    else:
        assert validate_host(value) == expected


@pytest.mark.parametrize("bad", ["-c", "--help", "a b", "x;y", "$(id)", "1.2.3.4/24", "....", ""])
def test_validate_host_blocks_injection(bad):
    with pytest.raises(ValueError):
        validate_host(bad)


def test_build_ping_command_is_argument_list():
    cmd = collector.build_ping_command("10.0.0.1", 4, 2)
    if cmd is None:
        pytest.skip("ping not installed on this machine")
    assert isinstance(cmd, list) and cmd[-1] == "10.0.0.1"


def test_tcp_probe_reachable_listener(listening_port):
    r = collector.tcp_probe("127.0.0.1", ports=(listening_port,), count=4, timeout_s=1)
    assert r.reachable and r.method == "tcp" and r.packet_loss_percent == 0.0
    assert r.latency_ms is not None and 0 <= r.latency_ms < 1000


def test_tcp_probe_closed_port_still_proves_host_is_up():
    # connection refused (RST) => the host answered
    r = collector.tcp_probe("127.0.0.1", ports=(1,), count=2, timeout_s=REFUSAL_TIMEOUT_S)
    assert r.reachable


UNROUTABLE = "203.0.113.9"  # TEST-NET-3 (RFC 5737): never assigned to a real host


def test_tcp_probe_timeout_logic_is_bounded(monkeypatch):
    """Deterministic: every connect times out -> 100% loss, only one attempt per port."""
    import socket as _s
    calls = []

    class SilentSocket(_s.socket):
        def connect(self, addr):
            calls.append(addr)
            raise _s.timeout("timed out")
    monkeypatch.setattr(collector.socket, "socket", SilentSocket)
    r = collector.tcp_probe("10.0.0.1", ports=(80, 443, 22), count=4, timeout_s=1)
    assert not r.reachable and r.packet_loss_percent == 100.0 and r.latency_ms is None
    assert len(calls) == 3  # port discovery only; no further retries against a dead host


def test_tcp_probe_real_unroutable_address_times_out():
    start = time.monotonic()
    r = collector.tcp_probe(UNROUTABLE, ports=(22,), count=4, timeout_s=1)
    elapsed = time.monotonic() - start
    if r.reachable:
        pytest.skip("this network answers unroutable addresses (firewall/proxy RST) - see README limitations")
    assert r.packet_loss_percent == 100.0 and r.latency_ms is None
    assert elapsed < 4, f"took {elapsed:.1f}s"


def test_unresolvable_hostname():
    r = collector.tcp_probe("no-such-host.invalid", count=1, timeout_s=1)
    assert not r.reachable and "resolved" in r.error


def test_probe_auto_falls_back_to_tcp_when_icmp_unavailable(monkeypatch, listening_port):
    def no_icmp(*a, **k):
        raise collector.IcmpUnavailable("ping command not found")
    monkeypatch.setattr(collector, "icmp_probe", no_icmp)
    monkeypatch.setitem(collector._icmp_broken, "flag", False)
    r = collector.probe("127.0.0.1", method="auto", count=2, timeout_s=1, tcp_ports=(listening_port,))
    assert r.reachable and r.method == "tcp"
    # icmp-only mode reports the problem instead of silently switching
    monkeypatch.setitem(collector._icmp_broken, "flag", False)
    r = collector.probe("127.0.0.1", method="icmp", count=2, timeout_s=1)
    assert not r.reachable and "ICMP unavailable" in r.error


def test_simulated_probe_is_labelled_and_realistic():
    import random
    rng = random.Random(1)
    vals = [collector.simulated_probe(1, "stable", "router", now=1000 + i * 60, rng=rng) for i in range(200)]
    assert all(v.method == "simulated" for v in vals)
    assert all(v.reachable for v in vals)
    assert all(0 < v.latency_ms < 20 for v in vals)
    flaky = [collector.simulated_probe(2, "flaky", "access_point", now=i * 60, rng=rng) for i in range(120)]
    assert any(not v.reachable for v in flaky) and any(v.reachable for v in flaky)
    degraded = [collector.simulated_probe(3, "degraded", "firewall", now=i * 60, rng=rng) for i in range(120)]
    assert min(v.latency_ms for v in degraded) > 150


def test_snmp_failure_is_graceful():
    cpu, mem, err = collector.snmp_probe("127.0.0.1", "public", timeout_s=0.5)
    assert cpu is None and mem is None and err


def test_probe_result_defaults():
    r = ProbeResult(False)
    assert r.latency_ms is None and r.method == "icmp"


@pytest.fixture
def fake_ping(tmp_path, monkeypatch):
    """Put a stand-in `ping` executable on PATH that prints canned output and exit code."""
    import os
    import stat
    import sys

    def install(output, code=0):
        script = tmp_path / "ping"
        out_file = tmp_path / "ping_out.txt"
        out_file.write_text(output)
        script.write_text(f"#!{sys.executable}\nimport sys\nsys.stdout.write(open({str(out_file)!r}).read())\n"
                          f"open({str(tmp_path / 'args.txt')!r}, 'w').write(' '.join(sys.argv[1:]))\nsys.exit({code})\n")
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
        monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
        return tmp_path / "args.txt"
    if sys.platform.startswith("win"):
        pytest.skip("stand-in ping script is POSIX-only")
    return install


def test_icmp_probe_runs_os_ping_and_parses(fake_ping):
    args_file = fake_ping(LINUX_OK, 0)
    r = collector.icmp_probe("192.168.1.1", count=4, timeout_s=2)
    assert r.reachable and r.method == "icmp" and r.latency_ms == 1.204 and r.packet_loss_percent == 25.0
    args = args_file.read_text().split()
    assert args[-1] == "192.168.1.1" and "-c" in args and "4" in args


def test_icmp_probe_down_host(fake_ping):
    fake_ping(LINUX_DOWN, 1)
    r = collector.icmp_probe("10.9.9.9", count=4, timeout_s=1)
    assert not r.reachable and r.packet_loss_percent == 100.0 and "No echo replies" in r.error


def test_icmp_permission_denied_raises_unavailable(fake_ping):
    fake_ping("ping: socket: Operation not permitted\n", 2)
    with pytest.raises(collector.IcmpUnavailable):
        collector.icmp_probe("10.0.0.1", count=1, timeout_s=1)


def test_icmp_unknown_host(fake_ping):
    fake_ping("ping: nohost.invalid: Name or service not known\n", 2)
    r = collector.icmp_probe("nohost.invalid", count=1, timeout_s=1)
    assert not r.reachable and "resolved" in r.error
