from core.engine import run_parallel
from core.report import generate_pdf, export_json
from plugins.plugin_loader import load_plugins

import argparse
import sys

from modules.web import web_scan
from modules.api import api_scan
from modules.ad import ad_scan
from modules.ports import port_scan
from modules.tls import tls_check

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TimeRemainingColumn, TextColumn
from rich.panel import Panel
from rich.live import Live

console = Console()


# =========================
# Banner
# =========================
def banner():
    console.print("\n🛡 [bold cyan]KRYPhorix Cyber Defense Suite[/bold cyan]", justify="center")
    console.print("[bold white]Advanced Security Assessment Framework[/bold white]\n", justify="center")


# =========================
# Add module name to findings
# =========================
def tag_module(findings, module_name):
    for f in findings:
        f.module = module_name
    return findings


# =========================
# Display summary in rich table
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
# Live scan dashboard
# =========================
def live_scan_dashboard(scan_tasks):
    findings = []
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
            live.update(Panel(f"[bold cyan]Starting {name} scans[/bold cyan]", title="Kryphorix Dashboard"))
            for target in targets:
                try:
                    res = func(target)
                    res = tag_module(res, name)  # <-- Tag each finding with its module
                    findings += res
                except Exception as e:
                    console.print(f"[red]Error scanning {target}: {e}[/red]")
                progress.advance(task_id)
            live.update(Panel(f"[bold green]{name} scans complete![/bold green]", title="Kryphorix Dashboard"))

    return findings


# =========================
# MENU MODE
# =========================
def menu_mode():
    banner()
    console.print(Panel("[bold]Menu Mode[/bold]\nSelect a module to scan:\n1. Web\n2. API\n3. Active Directory\n4. Ports\n5. TLS/SSL\n0. Exit"))

    choice = input("\nSelect option: ").strip()
    findings = []

    scan_tasks = []

    if choice == "1":
        targets = input("Web URLs (comma-separated): ").split(",")
        scan_tasks.append(("Web", web_scan, [t.strip() for t in targets]))

    elif choice == "2":
        targets = input("API URLs (comma-separated): ").split(",")
        scan_tasks.append(("API", api_scan, [t.strip() for t in targets]))

    elif choice == "3":
        targets = input("Domain Controller IPs/Hosts (comma-separated): ").split(",")
        scan_tasks.append(("AD", ad_scan, [t.strip() for t in targets]))

    elif choice == "4":
        targets = input("Hosts to scan ports (comma-separated): ").split(",")
        scan_tasks.append(("Ports", port_scan, [t.strip() for t in targets]))

    elif choice == "5":
        targets = input("Hosts to check TLS/SSL (comma-separated): ").split(",")
        scan_tasks.append(("TLS", tls_check, [t.strip() for t in targets]))

    elif choice == "0":
        sys.exit()

    else:
        console.print("[red]Invalid choice[/red]")
        return

    findings = live_scan_dashboard(scan_tasks)

    # Run plugins
    for plugin in load_plugins():
        plugin_results = plugin()
        plugin_results = tag_module(plugin_results, "Plugin")
        findings += plugin_results

    # Display summary & generate reports
    display_summary(findings)
    if findings:
        generate_pdf(findings)
        export_json(findings)


# =========================
# CLI MODE
# =========================
def cli_mode(args):
    findings = []
    scan_tasks = []

    if args.web:
        scan_tasks.append(("Web", web_scan, [args.web]))
    if args.api:
        scan_tasks.append(("API", api_scan, [args.api]))
    if args.ad:
        scan_tasks.append(("AD", ad_scan, [args.ad]))
    if args.ports:
        scan_tasks.append(("Ports", port_scan, [args.ports]))
    if args.tls:
        scan_tasks.append(("TLS", tls_check, [args.tls]))
    if args.fullscan:
        scan_tasks += [
            ("Web", web_scan, [args.fullscan]),
            ("API", api_scan, [args.fullscan]),
            ("Ports", port_scan, [args.fullscan]),
            ("TLS", tls_check, [args.fullscan])
        ]

    if scan_tasks:
        findings = live_scan_dashboard(scan_tasks)

    # Run plugins
    for plugin in load_plugins():
        plugin_results = plugin()
        plugin_results = tag_module(plugin_results, "Plugin")
        findings += plugin_results

    # Display summary & generate reports
    display_summary(findings)
    if findings:
        generate_pdf(findings)
        export_json(findings)
    else:
        console.print("[yellow]No scan option provided.[/yellow]")


# =========================
# Argument Parser
# =========================
def parse_args():
    parser = argparse.ArgumentParser(description="KryPhorix Security Framework")
    parser.add_argument("--web", help="Scan a web application")
    parser.add_argument("--api", help="Scan an API endpoint")
    parser.add_argument("--ad", help="Scan Active Directory")
    parser.add_argument("--ports", help="Scan open ports")
    parser.add_argument("--tls", help="Check TLS/SSL configuration")
    parser.add_argument("--fullscan", help="Run all scans on target")
    return parser.parse_args()


# =========================
# ENTRY POINT
# =========================
if __name__ == "__main__":
    args = parse_args()
    if len(sys.argv) == 1:
        menu_mode()
    else:
        banner()
        cli_mode(args)

