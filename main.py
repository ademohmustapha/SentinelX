from core.report import generate_pdf, export_json
from plugins.plugin_loader import load_plugins
import argparse, sys

from modules.web import web_scan
from modules.api import api_scan
from modules.ad import ad_scan
from modules.ports import port_scan
from modules.tls import tls_check
from modules.wireless import wireless_scan

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TimeRemainingColumn, TextColumn
from rich.live import Live

console = Console()


# =========================
# Banner
# =========================
def banner():
    console.print("\n🛡 [bold cyan]KRYPhorix Cyber Defense Suite[/bold cyan]", justify="center")
    console.print("[bold white]Advanced Security Assessment Framework[/bold white]\n", justify="center")


# =========================
# Tag findings with module
# =========================
def tag_module(findings, module_name):
    for f in findings:
        f.module = module_name
    return findings


# =========================
# Display summary table
# =========================
def display_summary(findings):
    if not findings:
        console.print("[bold green]No vulnerabilities found![/bold green]\n")
        return

    severity_order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
    findings_sorted = sorted(findings, key=lambda f: severity_order.get(f.severity, 0), reverse=True)

    table = Table(title="Scan Summary", show_lines=True)
    table.add_column("Module", style="bold")
    table.add_column("Title", style="bold")
    table.add_column("Severity")
    table.add_column("Description")
    table.add_column("Fix / Recommendation")

    severity_colors = {
        "Info": "blue",
        "Low": "green",
        "Medium": "yellow",
        "High": "red",
        "Critical": "dark_red"
    }

    for f in findings_sorted:
        table.add_row(
            getattr(f, "module", "Unknown"),
            f.title,
            f"[{severity_colors.get(f.severity, 'white')}]{f.severity}[/{severity_colors.get(f.severity, 'white')}]",
            f.desc,
            f.fix
        )

    console.print(table)


# =========================
# Run a module on multiple targets
# =========================
def run_module(module_name, func, targets):
    results = []
    for t in targets:
        try:
            res = func(t)
            results += tag_module(res, module_name)
        except Exception as e:
            console.print(f"[red]Error scanning {t}: {e}[/red]")
    return results


# =========================
# Parse comma-separated targets
# =========================
def parse_targets(value):
    return [v.strip() for v in value.split(",") if v.strip()]


# =========================
# CLI Mode
# =========================
def cli_mode(args):
    findings = []

    if args.web:
        findings += run_module("Web", web_scan, parse_targets(args.web))
    if args.api:
        findings += run_module("API", api_scan, parse_targets(args.api))
    if args.ad:
        findings += run_module("AD", ad_scan, parse_targets(args.ad))
    if args.ports:
        findings += run_module("Ports", port_scan, parse_targets(args.ports))
    if args.tls:
        findings += run_module("TLS", tls_check, parse_targets(args.tls))
    if args.wifi:
        findings += run_module("Wireless", wireless_scan, ["local"])

    # Run plugins
    for plugin in load_plugins():
        plugin_results = plugin()
        findings += tag_module(plugin_results, "Plugin")

    # Display summary & generate reports
    display_summary(findings)
    if findings:
        generate_pdf(findings)
        export_json(findings)


# =========================
# Menu Mode
# =========================
def menu_mode():
    banner()
    console.print(Panel(
        "[bold]Menu Mode[/bold]\n"
        "Select a module to scan:\n"
        "1. Web\n2. API\n3. Active Directory\n"
        "4. Ports\n5. TLS/SSL\n6. Wireless\n0. Exit"
    ))

    choice = input("\nSelect option: ").strip()
    scan_tasks = []

    if choice == "1":
        targets = input("Web URLs (comma-separated): ").split(",")
        scan_tasks.append(("Web", web_scan, parse_targets(",".join(targets))))
    elif choice == "2":
        targets = input("API URLs (comma-separated): ").split(",")
        scan_tasks.append(("API", api_scan, parse_targets(",".join(targets))))
    elif choice == "3":
        targets = input("Domain Controller IPs/Hosts (comma-separated): ").split(",")
        scan_tasks.append(("AD", ad_scan, parse_targets(",".join(targets))))
    elif choice == "4":
        targets = input("Hosts to scan ports (comma-separated): ").split(",")
        scan_tasks.append(("Ports", port_scan, parse_targets(",".join(targets))))
    elif choice == "5":
        targets = input("Hosts to check TLS/SSL (comma-separated): ").split(",")
        scan_tasks.append(("TLS", tls_check, parse_targets(",".join(targets))))
    elif choice == "6":
        scan_tasks.append(("Wireless", wireless_scan, ["local"]))
    elif choice == "0":
        sys.exit()
    else:
        console.print("[red]Invalid choice[/red]")
        return

    findings = []

    # ---------------------
    # Run scan tasks with live dashboard
    # ---------------------
    progress = Progress(
        TextColumn("[bold blue]{task.fields[module]}[/bold blue]"),
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn(),
    )

    with Live(console=console, refresh_per_second=4) as live:
        for name, func, targets in scan_tasks:
            if not targets:
                continue
            task_id = progress.add_task("", total=len(targets), module=name)
            live.update(Panel(f"[bold cyan]Starting {name} scans[/bold cyan]", title="KryPhorix Dashboard"))
            for t in targets:
                try:
                    res = func(t)
                    findings += tag_module(res, name)
                except Exception as e:
                    console.print(f"[red]Error scanning {t}: {e}[/red]")
                progress.advance(task_id)
            live.update(Panel(f"[bold green]{name} scans complete![/bold green]", title="KryPhorix Dashboard"))

    # Run plugins
    for plugin in load_plugins():
        findings += tag_module(plugin(), "Plugin")

    display_summary(findings)
    if findings:
        generate_pdf(findings)
        export_json(findings)


# =========================
# Argument Parser
# =========================
def parse_args():
    parser = argparse.ArgumentParser(description="KryPhorix Security Framework")
    parser.add_argument("--web", help="Scan web URLs (comma-separated)")
    parser.add_argument("--api", help="Scan API endpoints (comma-separated)")
    parser.add_argument("--ad", help="Scan Active Directory hosts (comma-separated)")
    parser.add_argument("--ports", help="Scan open ports (comma-separated)")
    parser.add_argument("--tls", help="Check TLS/SSL hosts (comma-separated)")
    parser.add_argument("--wifi", action="store_true", help="Scan available Wi-Fi networks")
    return parser.parse_args()


# =========================
# ENTRY POINT
# =========================
if __name__ == "__main__":
    args = parse_args()
    banner()
    if len(sys.argv) == 1:
        menu_mode()
    else:
        cli_mode(args)

