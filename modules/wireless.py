import subprocess
import re
from core.ui import banner, section, info, good, warn, bad
from core.finding import Finding
from core.findings import FindingsManager

def wireless_scan(interface=None):
    """
    Scans for available Wi-Fi networks and detects open/weak networks.
    Safe, non-intrusive scan.
    Optionally, specify a network interface; otherwise uses default system scan.
    """
    banner()
    section("WIRELESS SCAN - Detect Available Networks")
    findings = FindingsManager()

    try:
        # Build nmcli command
        cmd = ["nmcli", "-f", "SSID,SECURITY,SIGNAL", "dev", "wifi"]
        if interface:
            cmd += ["ifname", interface]

        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout.strip()

        if not output:
            info("No Wi-Fi networks found")
            return []

        networks = output.split("\n")[1:]  # Skip header line
        for net in networks:
            parts = re.split(r'\s{2,}', net)
            if len(parts) < 3:
                continue
            ssid, security, signal = parts[0], parts[1], parts[2]
            good(f"Detected Wi-Fi: {ssid} | Security: {security} | Signal: {signal}")

            # Open network
            if security.lower() in ["--", "open"]:
                findings.add(Finding(
                    f"Open Wi-Fi Network: {ssid}",
                    "High",
                    f"Network '{ssid}' is open with no encryption",
                    "Use WPA3/WPA2 encryption and avoid open networks"
                ))

            # Weak security
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
    for sev, count in findings.summary().items():
        print(f"{sev}: {count}")

    return findings.findings

