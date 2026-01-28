import ssl, socket
from datetime import datetime
from core.finding import Finding
from core.findings import FindingsManager
from core.ui import banner, section, info, good, warn, bad

def tls_check(host):
    """
    Checks TLS/SSL certificate of a host.
    Flags expired certificates and weak protocols.
    """
    banner()
    section(f"TLS CHECK - {host}")
    findings = FindingsManager()

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, 443))
            cert = s.getpeercert()

            # Check expiration
            exp = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            if exp < datetime.utcnow():
                findings.add(Finding(
                    "Expired SSL Certificate",
                    "High",
                    f"Certificate for {host} expired on {exp}",
                    "Renew certificate with a valid CA"
                ))
            else:
                good(f"Certificate is valid until {exp}")

            # Check protocol version (basic)
            protocol = s.version()
            good(f"TLS Protocol Version: {protocol}")
            if protocol in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                findings.add(Finding(
                    "Weak TLS/SSL Protocol",
                    "Medium",
                    f"{host} supports outdated protocol {protocol}",
                    "Disable weak protocols, enable TLSv1.2+"
                ))

    except ssl.SSLError as e:
        warn(f"SSL error: {e}")
    except socket.timeout:
        warn(f"Connection to {host} timed out")
    except Exception as e:
        bad(f"Unexpected error: {e}")

    # Summary
    section("TLS CHECK SUMMARY")
    summary = findings.summary()
    for sev, count in summary.items():
        print(f"{sev}: {count}")

    return findings

