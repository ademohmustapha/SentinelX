# main.py - Kryphorix Entry Point with HTML & PDF Reporting

import os
from datetime import datetime

# Module imports
from modules.web import web_scan
from modules.ad import active_directory_scan
from modules.api import api_scan
from modules.tls import tls_check
from modules.ports import port_scan
from modules.wireless import wireless_scan

# Core imports
from core.ui import banner, section
from core.findings import FindingsManager
from core.report import generate_pdf

# ---------------------------
# Menu Function
# ---------------------------
def main_menu():
    print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("       Kryphorix Scanner      ")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
    print("1. Web Application Scan")
    print("2. Active Directory Scan")
    print("3. API Scan")
    print("4. TLS Check")
    print("5. Ports Scan")
    print("6. Wireless Scan")
    print("0. Exit")

# ---------------------------
# HTML Report Generator
# ---------------------------
def generate_html_report(findings, filename=None):
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/Kryphorix_Report_{timestamp}.html"

    os.makedirs("reports", exist_ok=True)

    html_content = f"""
    <html>
    <head>
        <title>Kryphorix Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; background:#f4f4f4; padding:20px; }}
            h1 {{ color:#2E86C1; }}
            table {{ width:100%; border-collapse: collapse; margin-bottom:20px;}}
            th, td {{ border:1px solid #ccc; padding:8px; text-align:left; }}
            th {{ background:#2E86C1; color:white; }}
            .Info {{ color: blue; }}
            .Low {{ color: green; }}
            .Medium {{ color: orange; }}
            .High {{ color: red; }}
            .Critical {{ color: darkred; font-weight:bold; }}
        </style>
    </head>
    <body>
        <h1>Kryphorix Security Assessment Report</h1>
        <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <table>
            <tr>
                <th>Title</th>
                <th>Severity</th>
                <th>Description</th>
                <th>Fix / Recommendation</th>
            </tr>
    """

    for finding in findings.to_list():
        html_content += finding.to_html()

    html_content += """
        </table>
    </body>
    </html>
    """

    with open(filename, "w") as f:
        f.write(html_content)

    print(f"\nHTML report saved to: {filename}")

# ---------------------------
# Main Loop
# ---------------------------
def main():
    banner()
    while True:
        main_menu()
        choice = input("\nSelect a module: ").strip()
        findings = FindingsManager()

        if choice == "1":
            findings = web_scan()
        elif choice == "2":
            findings = active_directory_scan()
        elif choice == "3":
            findings = api_scan()
        elif choice == "4":
            host = input("Enter host for TLS check: ")
            findings = tls_check(host)
        elif choice == "5":
            host = input("Enter host for Ports scan: ")
            findings = port_scan(host)
        elif choice == "6":
            findings = wireless_scan()
        elif choice == "0":
            print("Exiting Kryphorix")
            break
        else:
            print("Invalid choice, try again.")
            continue

        # ---------------------------
        # Console Summary
        # ---------------------------
        section("SCAN COMPLETE")
        summary = findings.summary()
        for sev, count in summary.items():
            print(f"{sev}: {count}")

        # ---------------------------
        # Generate Reports
        # ---------------------------
        generate_html_report(findings)
        generate_pdf(findings)

        input("\nPress Enter to return to main menu...")

# ---------------------------
# Entry Point
# ---------------------------
if __name__ == "__main__":
    main()

