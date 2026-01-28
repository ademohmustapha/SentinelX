import subprocess
import re
from core.ui import banner, section, info, good, warn, bad
from core.finding import Finding
from core.findings import FindingsManager

def wireless_scan():
    """
    Scans for available Wi-Fi networks and detects open/weak networks.
    Safe, non-intrusive scan.
    """
    banner()
    section("WIRELESS SCAN - Detect Available Networks")
    findings = FindingsManager()

    try:
        # List networks using nmcli (Linux)
        result = subprocess.run(
            ["nmcli", "-f", "SSID,SECURITY,SIGNAL", "dev", "wifi"],
            capture_output=True, text=True
        )
        output = result.stdout.strip()
        if not output:
            info("No Wi-Fi networks found")
            return findings

        networks = output.split("\n")[1:]  # Skip header line
        for net in networks:
            parts = re.split(r'\s{2,}', net)
            if len(parts) < 3:
                continue
            ssid, security, signal = parts[0], parts[1], parts[2]
            good(f"Detected Wi-Fi: {ssid} | Security: {security} | Signal: {signal}")

            # Check for open networks
            if security.lower() in ["--", "open"]:
                findings.add(Finding(
                    f"Open Wi-Fi Network: {ssid}",
                    "High",
                    f"Network '{ssid}' is open with no encryption",
                    "Use WPA3/WPA2 encryption and avoid open networks"
                ))

            # Detect weak security (WEP)
            elif "WEP" in security:
                findings.add(Finding(
                    f"Weak Wi-Fi Security: {ssid}",
                    "Medium",
                    f"Network '{ssid}' uses outdated WEP encryption",
                    "Upgrade to WPA2/WPA3"
                ))

    except FileNotFoundError:
        warn("nmcli not found. Ensure NetworkManager is installed.")
    except Exception as e:
        bad(f"Wireless scan failed: {e}")

    # Summary
    section("WIRELESS SCAN SUMMARY")
    summary = findings.summary()
    for sev, count in summary.items():
        print(f"{sev}: {count}")

    return findings

