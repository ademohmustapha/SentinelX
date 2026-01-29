import socket
from core.finding import Finding
from core.findings import FindingsManager
from core.ui import banner, section, info, good, warn, bad

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 5900: "VNC"
}

def port_scan(host=None):
    banner()
    if not host:
        host = input("Enter host to scan ports: ").strip()

    section(f"PORT SCAN - {host}")
    findings = FindingsManager()

    for port, service in COMMON_PORTS.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            result = s.connect_ex((host, port))
            if result == 0:
                good(f"{service} (Port {port}) is OPEN")
                if port in [21,23,25,445,3389]:
                    findings.add(Finding(
                        f"Open {service} Service",
                        "Medium",
                        f"{service} is open on {host}:{port}. Exposed services can be exploited.",
                        "Restrict access to internal network or secure service"
                    ))
            else:
                info(f"{service} (Port {port}) is closed")
        except Exception as e:
            warn(f"Error checking port {port}: {e}")
        finally:
            s.close()

    section("PORT SCAN SUMMARY")
    for sev,count in findings.summary().items():
        print(f"{sev}: {count}")

    return findings.findings

