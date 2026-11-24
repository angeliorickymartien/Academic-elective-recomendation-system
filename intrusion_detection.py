"""
intrusion_detection.py - Rule-based detection of suspicious behaviour.

Detection rules
  BRUTE_FORCE_LOGIN      many failed logins from one IP
  REQUEST_FLOOD          too many requests per minute from one IP
  INVALID_REQUESTS       many 400/404/405 responses for one IP
  ADMIN_ACCESS_ATTEMPTS  repeated attempts to reach admin pages
  CONNECTION_SPIKE       too many active connections overall
  CONNECTION_PATTERN     too many simultaneous connections from one IP
  SYN_FLOOD_SUSPECTED    many half-open (SYN_RECV) connections from one IP
  EXTERNAL_CONNECTION    inbound connection from a non-local address
  UNEXPECTED_LISTENER    this app is listening on a port it should not use

Call run_all_checks() regularly (the network monitor does this every cycle).
"""
import logging
import os
from collections import Counter

import config
import models
import security

log = logging.getLogger("secureshop.security")

LOOPBACK_ADDRESSES = ("127.0.0.1", "::1", "localhost")

# TIME_WAIT sockets are normal leftovers of finished connections, so they are
# NOT counted as "active". Counting them would raise false alarms during
# ordinary browsing.
ACTIVE_STATES = ("ESTABLISHED", "SYN_RECV", "SYN_SENT")


def _raise_alert(alert_type, severity, ip, description):
    """Save an alert unless the same one was raised recently.
    Returns the alert as a dict, or None if it was a duplicate."""
    ip = ip or "local"
    if models.has_recent_alert(alert_type, ip, config.ALERT_COOLDOWN_MIN):
        return None
    models.create_alert(alert_type, severity, ip, description)
    log.warning("ALERT type=%s severity=%s ip=%s | %s", alert_type, severity, ip, description)
    return {"alert_type": alert_type, "severity": severity,
            "ip_address": ip, "description": description}


# ---------------------------------------------------------------
# RULES BASED ON APPLICATION BEHAVIOUR
# ---------------------------------------------------------------
def check_failed_logins():
    alerts = []
    for row in models.get_ips_with_failed_logins(config.FAILED_LOGIN_WINDOW_MIN,
                                                 config.MAX_FAILED_LOGINS):
        alerts.append(_raise_alert(
            "BRUTE_FORCE_LOGIN", "HIGH", row["ip_address"],
            f"{row['attempts']} failed logins within {config.FAILED_LOGIN_WINDOW_MIN} minutes "
            f"(threshold: {config.MAX_FAILED_LOGINS})."))
    return [a for a in alerts if a is not None]   # drop duplicates that were suppressed


def check_request_rate():
    alerts = []
    for ip, count in security.request_counter.snapshot().items():
        if count > config.MAX_REQUESTS_PER_MINUTE:
            alerts.append(_raise_alert(
                "REQUEST_FLOOD", "HIGH", ip,
                f"{count} requests in the last minute (limit: {config.MAX_REQUESTS_PER_MINUTE}). "
                "Further requests are answered with HTTP 429."))
    return [a for a in alerts if a is not None]   # drop duplicates that were suppressed


def check_invalid_requests():
    alerts = []
    for ip, count in security.invalid_counter.snapshot().items():
        if count >= config.MAX_INVALID_REQUESTS:
            alerts.append(_raise_alert(
                "INVALID_REQUESTS", "MEDIUM", ip,
                f"{count} invalid requests (400/404/405) within {config.INVALID_WINDOW_MIN} minutes."))
    return [a for a in alerts if a is not None]   # drop duplicates that were suppressed


def check_admin_access():
    alerts = []
    for ip, count in security.admin_attempt_counter.snapshot().items():
        if count >= config.MAX_ADMIN_ACCESS_ATTEMPTS:
            alerts.append(_raise_alert(
                "ADMIN_ACCESS_ATTEMPTS", "HIGH", ip,
                f"{count} unauthorised attempts to open admin pages in 5 minutes."))
    return [a for a in alerts if a is not None]   # drop duplicates that were suppressed


# ---------------------------------------------------------------
# RULES BASED ON NETWORK CONNECTIONS
# `connections` is the list of dicts produced by network_monitor.py
# ---------------------------------------------------------------
def check_connections(connections):
    alerts = []
    my_pid = os.getpid()

    active = [c for c in connections if c["status"] in ACTIVE_STATES]

    # 1. Too many active connections in total
    if len(active) > config.MAX_CONNECTIONS_ALERT:
        alerts.append(_raise_alert(
            "CONNECTION_SPIKE", "MEDIUM", "local",
            f"{len(active)} active connections (limit: {config.MAX_CONNECTIONS_ALERT})."))

    # 2. Too many simultaneous connections from a single address
    per_ip = Counter(c["remote_ip"] for c in active if c["remote_ip"])
    for ip, count in per_ip.items():
        if count > config.MAX_CONNECTIONS_PER_IP:
            alerts.append(_raise_alert(
                "CONNECTION_PATTERN", "MEDIUM", ip,
                f"{count} simultaneous connections from one address "
                f"(limit: {config.MAX_CONNECTIONS_PER_IP})."))

    # 3. Many half-open connections: the TCP three-way handshake (SYN, SYN-ACK, ACK)
    #    is started but never completed. This is the signature of a SYN flood.
    half_open = Counter(c["remote_ip"] for c in connections
                        if c["status"] == "SYN_RECV" and c["remote_ip"])
    for ip, count in half_open.items():
        if count >= config.MAX_HALF_OPEN_CONNECTIONS:
            alerts.append(_raise_alert(
                "SYN_FLOOD_SUSPECTED", "HIGH", ip,
                f"{count} half-open (SYN_RECV) connections; the TCP handshake is not being completed."))

    # 4. Inbound connection from outside, although the server only listens on localhost
    if config.HOST in LOOPBACK_ADDRESSES:
        for c in connections:
            if (c["direction"] == "INBOUND" and c["remote_ip"]
                    and c["remote_ip"] not in LOOPBACK_ADDRESSES):
                alerts.append(_raise_alert(
                    "EXTERNAL_CONNECTION", "MEDIUM", c["remote_ip"],
                    f"Inbound connection from a non-local address to {c['local_addr']}, "
                    f"but the server is bound to {config.HOST}."))

    # 5. This process is listening on a port other than its configured one
    for c in connections:
        if (c["status"] == "LISTEN" and c.get("pid") == my_pid
                and c["local_port"] != config.PORT):
            alerts.append(_raise_alert(
                "UNEXPECTED_LISTENER", "HIGH", "local",
                f"The application is listening on unexpected port {c['local_port']} "
                f"(expected only {config.PORT})."))

    return [a for a in alerts if a is not None]   # drop duplicates that were suppressed


# ---------------------------------------------------------------
# RUN EVERYTHING
# ---------------------------------------------------------------
def run_all_checks(connections=None):
    """Run every rule. Returns the list of NEW alerts that were raised."""
    results = []
    results += check_failed_logins()
    results += check_request_rate()
    results += check_invalid_requests()
    results += check_admin_access()
    if connections is not None:
        results += check_connections(connections)
    return [alert for alert in results if alert is not None]
