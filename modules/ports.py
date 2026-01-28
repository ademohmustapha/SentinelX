import socket
from core.finding import Finding
from core.findings import FindingsManager
from core.ui import banner, section, info, good, warn, bad

# Common ports to scan
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC"
}

def port_scan(host):
    """
    Checks if common ports are open on the host.
    Flags commonly exploited open ports.
    """
    banner()
    section(f"PORT SCAN - {host}")
    findings = FindingsManager()

    for port, service in COMMON_PORTS.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            result = s.connect_ex((host, port))
            if result == 0:
                good(f"{service} (Port {port}) is OPEN")
                # Flag commonly risky services
                if port in [21, 23, 25, 445, 3389]:
                    findings.add(Finding(
                        f"Open {service} Service",
                        "Medium",
                        f"{service} is open on {host}:{port}. Exposed services can be exploited.",
                        f"Restrict access to internal network or secure service"
                    ))
            else:
                info(f"{service} (Port {port}) is closed")
        except Exception as e:
            warn(f"Error checking port {port}: {e}")
        finally:
            s.close()

    # Summary
    section("PORT SCAN SUMMARY")
    summary = findings.summary()
    for sev, count in summary.items():
        print(f"{sev}: {count}")

    return findings

