import socket
from core.ui import banner, section, info, good, warn, bad
from core.finding import Finding
from core.findings import FindingsManager

AD_PORTS = {
    88: "Kerberos",
    389: "LDAP",
    445: "SMB",
    636: "LDAPS",
    3268: "Global Catalog LDAP",
    3269: "Global Catalog LDAPS"
}

def ad_scan(target=None):
    banner()
    if not target:
        target = input("Enter Domain Controller IP: ").strip()

    findings = FindingsManager()
    info(f"Target Domain Controller: {target}")
    section("CHECKING AD SERVICE EXPOSURE")

    for port, service in AD_PORTS.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            result = s.connect_ex((target, port))
            if result == 0:
                good(f"{service} (Port {port}) is OPEN")
                if port in [389,445,3268]:
                    findings.add(Finding(
                        f"{service} Service Exposed",
                        "High",
                        f"{service} service is accessible externally on port {port}",
                        "Restrict AD services to internal network only"
                    ))
            else:
                info(f"{service} (Port {port}) is closed")
        except Exception as e:
            warn(f"Error checking {service}: {e}")
        finally:
            s.close()

    section("SMB SIGNING CHECK (basic detection)")
    try:
        s = socket.create_connection((target, 445), timeout=3)
        s.close()
        findings.add(Finding(
            "SMB Service Detected",
            "Medium",
            "SMB is exposed. Ensure SMB signing and security policies are enforced.",
            "Enable SMB signing and restrict SMB access"
        ))
    except:
        info("SMB not reachable")

    section("SUMMARY OF FINDINGS")
    for k,v in findings.summary().items():
        print(f"{k}: {v}")

    return findings.findings

