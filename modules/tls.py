import ssl, socket
from datetime import datetime
from core.finding import Finding
from core.findings import FindingsManager
from core.ui import banner, section, info, good, warn, bad

def tls_check(host=None):
    banner()
    if not host:
        host = input("Enter host to check TLS/SSL: ").strip()

    section(f"TLS CHECK - {host}")
    findings = FindingsManager()

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, 443))
            cert = s.getpeercert()

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

            protocol = s.version()
            good(f"TLS Protocol Version: {protocol}")
            if protocol in ["SSLv2","SSLv3","TLSv1","TLSv1.1"]:
                findings.add(Finding(
                    "Weak TLS/SSL Protocol",
                    "Medium",
                    f"{host} supports outdated protocol {protocol}",
                    "Disable weak protocols, enable TLSv1.2+"
                ))

    except Exception as e:
        bad(f"TLS/SSL check failed: {e}")

    section("TLS CHECK SUMMARY")
    for sev,count in findings.summary().items():
        print(f"{sev}: {count}")

    return findings.findings

