"""
network_monitor.py - Monitors THIS application's network connections.

What it observes (metadata only, never packet contents):
  * TCP/UDP sockets owned by this process, or using the app's port
  * connection states (LISTEN, ESTABLISHED, TIME_WAIT, SYN_RECV ...)
  * system-wide bytes/packets transferred per interval (network adapter counters)

Only local, authorised monitoring: no scanning, no packet sniffing.
"""
import logging
import os
import socket
import ssl
import threading
import time
from collections import Counter
from datetime import datetime, timezone

import psutil
from cryptography import x509
from cryptography.hazmat.primitives import hashes

import config
import intrusion_detection
import models

net_log = logging.getLogger("secureshop.network")

# Protocol names are inferred from port numbers. (Telling HTTP from HTTPS by
# looking at the traffic itself would need packet inspection, which we avoid.)
WELL_KNOWN_PORTS = {53: "DNS", 80: "HTTP", 443: "HTTPS"}


# ---------------------------------------------------------------
# 1. COLLECTING CONNECTIONS
# ---------------------------------------------------------------
def describe_protocol(local_port, remote_port):
    if local_port == config.PORT:
        return "HTTPS (TLS)"            # our server only speaks TLS
    for port in (local_port, remote_port):
        if port in WELL_KNOWN_PORTS:
            return WELL_KNOWN_PORTS[port]
    return "-"


def _format_addr(addr):
    return f"{addr.ip}:{addr.port}" if addr else ""


def collect_connections():
    """Return a list of dicts describing connections that belong to this app."""
    my_pid = os.getpid()
    try:
        raw = psutil.net_connections(kind="inet")           # whole system, then filtered
    except (psutil.AccessDenied, PermissionError):
        # Some systems (e.g. macOS) require admin rights for the system-wide list.
        # Fall back to this process's own connections only.
        process = psutil.Process(my_pid)
        if hasattr(process, "net_connections"):
            raw = process.net_connections(kind="inet")
        else:
            raw = process.connections(kind="inet")

    connections = []
    for c in raw:
        local_port = c.laddr.port if c.laddr else None
        pid = getattr(c, "pid", my_pid)                      # per-process lists have no pid
        if pid != my_pid and local_port != config.PORT:
            continue                                         # not our application's traffic

        remote_port = c.raddr.port if c.raddr else None
        status = c.status

        if status == "LISTEN" or not c.raddr:
            direction = "LISTENING"
        elif local_port == config.PORT:
            direction = "INBOUND"                            # a client connected to our server
        else:
            direction = "OUTBOUND"

        connections.append({
            "protocol": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
            "local_addr": _format_addr(c.laddr),
            "remote_addr": _format_addr(c.raddr),
            "remote_ip": c.raddr.ip if c.raddr else "",
            "local_port": local_port,
            "status": status,
            "direction": direction,
            "app_protocol": describe_protocol(local_port, remote_port),
            "pid": pid,
        })
    return connections


def summarize(connections):
    """Counts used by the dashboard."""
    return {
        "total": len(connections),
        "tcp_count": sum(1 for c in connections if c["protocol"] == "TCP"),
        "udp_count": sum(1 for c in connections if c["protocol"] == "UDP"),
        "by_state": dict(Counter(c["status"] for c in connections)),
        "by_direction": dict(Counter(c["direction"] for c in connections)),
        "top_remote_ips": Counter(c["remote_ip"] for c in connections
                                  if c["remote_ip"]).most_common(5),
    }


def take_snapshot():
    """One-off reading (does not touch the database)."""
    connections = collect_connections()
    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "connections": connections,
        "summary": summarize(connections),
    }


# ---------------------------------------------------------------
# 2. THE BACKGROUND MONITOR
# ---------------------------------------------------------------
class NetworkMonitor(threading.Thread):
    def __init__(self):
        super().__init__(name="NetworkMonitor", daemon=True)   # daemon: ends with the app
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._latest = None
        self._seen = set()          # connections already logged
        self._previous_io = None
        self._cycle = 0

    def run(self):
        net_log.info("Network monitor started (interval=%ss, port=%s)",
                     config.MONITOR_INTERVAL_SEC, config.PORT)
        while not self._stop_event.is_set():
            try:
                self.sample()
            except Exception:                                   # keep monitoring no matter what
                net_log.exception("Monitor cycle failed")
            self._stop_event.wait(config.MONITOR_INTERVAL_SEC)
        net_log.info("Network monitor stopped")

    def stop(self):
        self._stop_event.set()

    def sample(self):
        """One monitoring cycle."""
        self._cycle += 1
        snapshot = take_snapshot()
        connections = snapshot["connections"]
        summary = snapshot["summary"]

        # Traffic during this interval = change in the adapter counters
        io = psutil.net_io_counters()
        if self._previous_io is None:
            sent = recv = pkts_sent = pkts_recv = 0
        else:
            sent = max(0, io.bytes_sent - self._previous_io.bytes_sent)
            recv = max(0, io.bytes_recv - self._previous_io.bytes_recv)
            pkts_sent = max(0, io.packets_sent - self._previous_io.packets_sent)
            pkts_recv = max(0, io.packets_recv - self._previous_io.packets_recv)
        self._previous_io = io

        # Log connections we have not seen before
        current = {(c["protocol"], c["local_addr"], c["remote_addr"]): c for c in connections}
        new_events = [c for key, c in current.items() if key not in self._seen]
        self._seen = set(current)
        for c in new_events:
            net_log.info("NEW_CONNECTION %s %s -> %s state=%s direction=%s protocol=%s",
                         c["protocol"], c["local_addr"], c["remote_addr"] or "-",
                         c["status"], c["direction"], c["app_protocol"])

        models.save_network_events(new_events)
        models.save_traffic_stats(sent, recv, pkts_sent, pkts_recv,
                                  summary["tcp_count"], summary["udp_count"])

        # Hand the connection list to the detection engine
        intrusion_detection.run_all_checks(connections)

        if self._cycle % 12 == 0:                               # about once a minute
            net_log.info("SUMMARY connections=%d tcp=%d udp=%d states=%s sent=%dB recv=%dB",
                         summary["total"], summary["tcp_count"], summary["udp_count"],
                         summary["by_state"], sent, recv)
            models.prune_network_data()

        with self._lock:
            self._latest = snapshot

    def get_latest(self):
        with self._lock:
            return self._latest


_monitor = None


def start_monitor():
    """Start the background monitor (safe to call more than once)."""
    global _monitor
    if _monitor is None or not _monitor.is_alive():
        _monitor = NetworkMonitor()
        _monitor.start()
    return _monitor


def stop_monitor():
    if _monitor is not None:
        _monitor.stop()


def get_latest_snapshot():
    """Newest reading from the monitor, or a fresh one-off reading."""
    latest = _monitor.get_latest() if _monitor is not None else None
    return latest if latest is not None else take_snapshot()


# ---------------------------------------------------------------
# 3. SOCKET-LEVEL HELPERS (DNS and TLS demonstrations)
# ---------------------------------------------------------------
def local_network_info():
    """DNS resolution and addressing information about this machine."""
    def resolve(name):
        try:
            return socket.gethostbyname(name)          # asks the OS resolver (hosts file / DNS)
        except socket.gaierror:
            return "unresolved"

    hostname = socket.gethostname()
    return {
        "hostname": hostname,
        "host_ip": resolve(hostname),
        "localhost_resolves_to": resolve("localhost"),
        "server_address": f"{config.HOST}:{config.PORT}",
    }


def inspect_tls(host="127.0.0.1", port=None, timeout=3):
    """Connect to OUR OWN server, perform a real TLS handshake and report what
    was negotiated. Refuses any address that is not local."""
    if host not in ("127.0.0.1", "localhost"):
        return {"ok": False, "error": "Refused: only local connections are allowed."}
    port = port or config.PORT

    context = ssl.create_default_context()
    context.check_hostname = False             # our certificate is self-signed,
    context.verify_mode = ssl.CERT_NONE        # so we inspect it instead of verifying it

    try:
        started = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname="localhost") as tls:
                handshake_ms = (time.perf_counter() - started) * 1000
                version = tls.version()
                cipher_name, _, key_bits = tls.cipher()
                cert_der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as error:
        return {"ok": False, "error": str(error)}

    cert = x509.load_der_x509_certificate(cert_der)
    return {
        "ok": True,
        "tls_version": version,
        "cipher": cipher_name,
        "key_bits": key_bits,
        "handshake_ms": round(handshake_ms, 1),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "valid_until": cert.not_valid_after_utc.strftime("%Y-%m-%d"),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }


def monitor_is_running():
    """True while the background monitor thread is alive."""
    return _monitor is not None and _monitor.is_alive()
