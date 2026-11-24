"""
generate_cert.py - Creates a self-signed TLS certificate for local HTTPS.
Run with:   python generate_cert.py
Use --force to replace an existing certificate.
"""
import datetime
import ipaddress
import os
import ssl
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import config


def generate_certificate(force=False):
    if not force and os.path.exists(config.CERT_FILE) and os.path.exists(config.KEY_FILE):
        print("Certificate already exists. Use --force to regenerate.")
        print(f"  {config.CERT_FILE}")
        return

    print("Generating 2048-bit RSA key and self-signed certificate...")

    # 1. Private key: this must stay SECRET. Anyone with it can impersonate the server.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 2. Certificate identity. Self-signed, so subject and issuer are the same.
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureShop Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        # Subject Alternative Names: the hostnames/IPs this certificate is valid for.
        # Modern browsers check this field rather than the Common Name.
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        # 3. Sign with SHA-256 using our own private key
        .sign(private_key, hashes.SHA256())
    )

    # 4. Save to disk in PEM (text) format
    with open(config.KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    try:
        os.chmod(config.KEY_FILE, 0o600)   # owner-only access (limited effect on Windows)
    except OSError:
        pass

    with open(config.CERT_FILE, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    fingerprint = certificate.fingerprint(hashes.SHA256()).hex().upper()
    fingerprint = ":".join(fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2))

    print(f"[OK] Private key saved to: {config.KEY_FILE}")
    print(f"[OK] Certificate saved to: {config.CERT_FILE}")
    print("[OK] Valid for: localhost, 127.0.0.1 (365 days)")
    print(f"[OK] SHA-256 fingerprint: {fingerprint}")

    # 5. Prove the pair is usable by loading it into a TLS server context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(config.CERT_FILE, config.KEY_FILE)
    print("[OK] Certificate and key load correctly into an SSL context.")


if __name__ == "__main__":
    generate_certificate(force="--force" in sys.argv)
