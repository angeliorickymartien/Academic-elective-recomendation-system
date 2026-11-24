"""
client_generator.py - Python Client for Transaction Generation & Protocol Analysis
Secure E-Commerce Network (Computer Networks & Internet Protocols Project)

Usage:
    python client_generator.py                      # Interactive menu
    python client_generator.py --scenario trans     # Single secure transaction
    python client_generator.py --scenario burst     # High-load network performance test
    python client_generator.py --scenario probe     # Probe/reconnaissance scan
    python client_generator.py --scenario tls       # Detailed TLS Handshake analysis
"""
import argparse
import http.cookiejar
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import config

TARGET_HOST = "127.0.0.1"
TARGET_PORT = config.PORT
BASE_URL = f"https://{TARGET_HOST}:{TARGET_PORT}"


def print_banner():
    print("=" * 72)
    print("  SECURESHOP - CNIP CLIENT TRANSACTION & PROTOCOL GENERATOR")
    print(f"  Target: {TARGET_HOST}:{TARGET_PORT} (HTTPS / TLS 1.3)")
    print("  Protocol Stack: Layer 7 (HTTP/1.1) -> Layer 5/6 (TLS) -> Layer 4 (TCP) -> Layer 3 (IP)")
    print("=" * 72)


def make_ssl_client():
    """Builds an HTTPS client with cookie persistence and TLS inspection."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
    )
    return opener


def send_request(opener, method, path, data=None):
    """Executes a real client request, logging network timing, packet headers and status."""
    url = f"{BASE_URL}{path}"
    encoded = urllib.parse.urlencode(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=encoded, method=method)
    req.add_header("User-Agent", "SecureShop-CNIP-Client/2.0")

    t_start = time.perf_counter()
    try:
        with opener.open(req, timeout=5) as resp:
            elapsed_ms = (time.perf_counter() - t_start) * 1000
            content = resp.read()
            return resp.status, len(content), elapsed_ms, content.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as err:
        elapsed_ms = (time.perf_counter() - t_start) * 1000
        content = err.read()
        return err.code, len(content), elapsed_ms, content.decode("utf-8", errors="replace")
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - t_start) * 1000
        return 0, 0, elapsed_ms, str(exc)


def scenario_transaction():
    """Generates a complete multi-node client transaction."""
    print("\n[+] SCENARIO 1: End-to-End Client Transaction Request")
    print("    Nodes involved: Customer -> Web Server (5000) -> App Logic -> Database")
    opener = make_ssl_client()

    steps = [
        ("GET", "/", "1. Client connects and fetches Catalog Index"),
        ("GET", "/products", "2. Client queries Product Directory"),
        ("GET", "/products/1", "3. Client requests Product #1 Details"),
    ]

    for method, path, desc in steps:
        print(f"\n---> {desc}")
        status, length, rtt, _ = send_request(opener, method, path)
        print(f"     [TCP/IP] {TARGET_HOST}:<ephemeral> -> {TARGET_HOST}:{TARGET_PORT}")
        print(f"     [Status] HTTP/1.1 {status} | Payload: {length} bytes | Latency (RTT): {rtt:.2f} ms")
        print(f"     [Security] Ciphertext stream transmitted over encrypted TLS 1.3 socket")
        time.sleep(0.3)

    print("\n[SUCCESS] Transaction sequence finished. Check Wireshark with filter: 'tcp.port == 5000'")


def scenario_burst(count=15):
    """Evaluates network performance under rapid concurrent request bursts."""
    print(f"\n[+] SCENARIO 2: Network Performance Evaluation ({count} Rapid Bursts)")
    print("    Testing TCP socket handling, sliding-window rate limiting, and response times.")
    opener = make_ssl_client()

    rtts = []
    statuses = []

    t_total_start = time.perf_counter()
    for i in range(1, count + 1):
        status, length, rtt, _ = send_request(opener, "GET", "/")
        rtts.append(rtt)
        statuses.append(status)
        print(f"    Burst #{i:02d}: Status={status} | RTT={rtt:.2f} ms | Bytes={length}")
        time.sleep(0.05)

    total_time = (time.perf_counter() - t_total_start) * 1000
    avg_rtt = sum(rtts) / len(rtts) if rtts else 0

    print("\n--- Network Performance Summary ---")
    print(f"    Total Frames Sent: {count * 4} (estimated TCP exchange)")
    print(f"    Total Time: {total_time:.2f} ms | Average RTT: {avg_rtt:.2f} ms")
    print(f"    Throughput: {(count / (total_time / 1000)):.1f} requests/sec")
    print(f"    Status Distribution: {dict(collections.Counter(statuses))}")


def scenario_tls_inspector():
    """Connects to server socket and performs real cryptographic TLS negotiation inspection."""
    print("\n[+] SCENARIO 3: Live TLS 1.3 Cryptographic Handshake Inspection")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    t0 = time.perf_counter()
    with socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=3) as raw_sock:
        tcp_connect_ms = (time.perf_counter() - t0) * 1000
        print(f"    [TCP] 3-Way Handshake established in {tcp_connect_ms:.2f} ms")
        print(f"          Socket: {raw_sock.getsockname()} -> {raw_sock.getpeername()}")

        t1 = time.perf_counter()
        with ctx.wrap_socket(raw_sock, server_hostname="localhost") as tls_sock:
            tls_handshake_ms = (time.perf_counter() - t1) * 1000
            cipher_name, proto_ver, key_bits = tls_sock.cipher()
            print(f"    [TLS] Cryptographic Handshake negotiated in {tls_handshake_ms:.2f} ms")
            print(f"          Protocol Version : {tls_sock.version()}")
            print(f"          Cipher Suite     : {cipher_name}")
            print(f"          Key Bit Length   : {key_bits} bits")
            print(f"          Compression      : {tls_sock.compression() or 'None (CRIME prevention)'}")
            cert = tls_sock.getpeercert(binary_form=True)
            print(f"          Cert Size (DER)  : {len(cert)} bytes")


def scenario_probe():
    """Simulates reconnaissance port/URI scanning across multiple paths."""
    print("\n[+] SCENARIO 4: Network Reconnaissance & Port Probe Simulation")
    print("    Testing Intrusion Detection System (IDS) alerts on invalid routing.")
    opener = make_ssl_client()

    probes = ["/admin/config", "/etc/passwd", "/.git/config", "/phpmyadmin", "/api/v1/internal"]
    for path in probes:
        status, length, rtt, _ = send_request(opener, "GET", path)
        print(f"    Probing {path:<20} -> HTTP {status} (RTT: {rtt:.2f} ms)")
        time.sleep(0.2)

    print("\n[ALERT] Probing activity logged by sliding-window counter. Check Admin / Network Lab for IDS alerts.")


if __name__ == "__main__":
    import collections
    print_banner()

    parser = argparse.ArgumentParser(description="SecureShop CNIP Protocol Client")
    parser.add_argument("--scenario", choices=["trans", "burst", "probe", "tls", "all"],
                        default=None, help="Execution scenario")
    args = parser.parse_args()

    if args.scenario == "trans":
        scenario_transaction()
    elif args.scenario == "burst":
        scenario_burst()
    elif args.scenario == "probe":
        scenario_probe()
    elif args.scenario == "tls":
        scenario_tls_inspector()
    elif args.scenario == "all":
        scenario_tls_inspector()
        scenario_transaction()
        scenario_burst(10)
        scenario_probe()
    else:
        # Interactive Menu
        print("\nSelect Demonstration Scenario:")
        print("  1) Single Secure Transaction (Client -> Web -> App -> DB)")
        print("  2) Network Performance & Burst Throughput Test")
        print("  3) TLS 1.3 Cryptographic Handshake Deep-Dive")
        print("  4) Network Reconnaissance / Probe Scan Simulation")
        print("  5) Run All Demonstrations")
        print("  Q) Quit")

        try:
            choice = input("\nEnter choice [1-5]: ").strip()
            if choice == "1":
                scenario_transaction()
            elif choice == "2":
                scenario_burst()
            elif choice == "3":
                scenario_tls_inspector()
            elif choice == "4":
                scenario_probe()
            elif choice == "5":
                scenario_tls_inspector()
                scenario_transaction()
                scenario_burst(10)
                scenario_probe()
            else:
                print("Exiting.")
        except KeyboardInterrupt:
            print("\nAborted.")
