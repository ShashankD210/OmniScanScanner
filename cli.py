#!/usr/bin/env python3
"""OmniScan - Structured CLI interface"""
import argparse
import json
import sys
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from omni_vapt.cve import CVEDatabase
from omni_vapt.db import DBManager
from omni_vapt.exploit import ExploitMatcher, ExploitVerifier
from omni_vapt.report import ReportGenerator
from omni_vapt.core import VaptCore

console = Console()

BANNER = r"""
[bold white]  OmniScan — Multi-Platform Vulnerability Scanner[/bold white]
[bold magenta]  Network  ·  Web  ·  CVE  ·  Exploit Verification[/bold magenta]
"""


def _display_dashboard(report):
    table = Table(title="OmniScan Results", style="bold blue")
    table.add_column("Type", style="cyan")
    table.add_column("Target", style="magenta")
    table.add_column("Detail", style="green")
    table.add_column("Severity", style="red")
    for item in report.get('network', []):
        table.add_row(
            "Network",
            str(item.get('port', '')),
            item.get('service', ''),
            item.get('severity', 'medium'),
        )
    for item in report.get('web', []):
        table.add_row(
            "Web",
            item.get('url', ''),
            item.get('status', item.get('evidence', '')),
            item.get('severity', 'high'),
        )
    console.print(table)


def cmd_scan(args):
    console.print(Panel(BANNER, border_style="cyan", padding=(0, 2)))
    console.print()

    target = args.target
    if not target:
        target = input("Enter target IP, hostname, or URL: ").strip()
    if not target:
        console.print("[red]Target is required.[/red]")
        sys.exit(1)

    console.print(f"[cyan][*][/cyan] Target: [bold]{target}[/bold]")

    cve_db = CVEDatabase(args.cve_db)
    console.print(f"[cyan][*][/cyan] Using CVE database: [bold]{args.cve_db}[/bold]")

    vapt = VaptCore(target, cve_db)
    report = vapt.run_full_audit()

    if args.verify and report.get("web"):
        console.print("[yellow][!] Running live exploit verification on target sites...[/yellow]")
        verifier = ExploitVerifier(report["web"])
        verifier.run_checks()

    if args.exploit_search and report.get("network"):
        matcher = ExploitMatcher()
        for item in report["network"]:
            result = matcher.search_exploits(item["service"], item["version"])
            item["exploit_search"] = result

    if args.db:
        db = DBManager()
        summary = f"{len(report['network'])} network findings, {len(report['web'])} web findings"
        scan_id = db.save_scan(target, summary)
        for item in report["network"]:
            cve_refs = json.dumps(item.get("cves", []))
            db.save_finding(scan_id, item["type"], item.get("severity", "medium"), item.get("vulns", ""), cve_refs)
        for item in report["web"]:
            db.save_finding(scan_id, item["type"], item.get("severity", "high"), item.get("evidence", ""))
        console.print(f"[green][+] Findings saved to database with scan_id {scan_id}[/green]")

    if args.html or args.json or args.odf:
        report_gen = ReportGenerator()
        stamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        if args.html:
            report_gen.generate_html_report(report, cve_db, f"omni_vapt_report_{stamp}.html")
        if args.json:
            report_gen.generate_json_report(report, cve_db, f"omni_vapt_report_{stamp}.json")
        if args.odf:
            report_gen.generate_odf_report(report, cve_db, f"omni_vapt_report_{stamp}.odt")

    _display_dashboard(report)
    console.print("[green]Scan complete.[/green]")


def cmd_cve_stats(args):
    cve_db = CVEDatabase(args.cve_db)
    stats = cve_db.get_db_stats()
    console.print("\n[bold cyan]CVE Database Statistics[/bold cyan]")
    console.print(f"Total CVEs: {stats.get('total_cves', 0)}")
    console.print(f"Unique Products: {stats.get('unique_products', 0)}")
    console.print(f"CVEs from NVD: {stats.get('nvd_count', 0)}")
    console.print(f"CVEs from CIRCL: {stats.get('circl_count', 0)}")


def cmd_cve_search(args):
    cve_db = CVEDatabase(args.cve_db)
    product = args.product
    version = args.version
    console.print(f"\n[bold cyan]Searching CVEs for {product}...[/bold cyan]")
    results = cve_db.search_cves(product, version)

    if results:
        table = Table(title=f"CVE Results for {product}", style="bold blue")
        table.add_column("CVE ID", style="cyan")
        table.add_column("Severity", style="magenta")
        table.add_column("CVSS Score", style="green")
        table.add_column("Source", style="yellow")
        for cve in results[:20]:
            table.add_row(
                cve.get("cve_id", "N/A"),
                cve.get("severity", "UNKNOWN"),
                str(cve.get("cvss_score", "N/A")),
                cve.get("source", "N/A"),
            )
        console.print(table)
    else:
        console.print("[yellow]No CVEs found.[/yellow]")


def build_parser():
    parser = argparse.ArgumentParser(description="OmniScan - Multi-Platform Vulnerability Scanner")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    scan = subparsers.add_parser("scan", help="Run vulnerability scan on URL or IP")
    scan.add_argument("target", nargs="?", help="Target IP, hostname, or URL")
    scan.add_argument("--html", action="store_true", help="Generate HTML report")
    scan.add_argument("--json", action="store_true", help="Generate JSON report")
    scan.add_argument("--odf", action="store_true", help="Generate ODF (OpenDocument) report")
    scan.add_argument("--db", action="store_true", help="Save findings to SQLite database")
    scan.add_argument("--verify", action="store_true", help="Run exploit verification checks")
    scan.add_argument("--exploit-search", action="store_true", help="Search exploits via searchsploit")
    scan.add_argument("--cve-db", default="cve_database.db", help="Path to CVE database")

    cve = subparsers.add_parser("cve", help="CVE database operations")
    cve_sub = cve.add_subparsers(dest="cve_command", help="CVE subcommands")

    cve_stats = cve_sub.add_parser("stats", help="Show CVE database statistics")
    cve_stats.add_argument("--cve-db", default="cve_database.db", help="Path to CVE database")

    cve_search = cve_sub.add_parser("search", help="Search CVEs by product")
    cve_search.add_argument("product", help="Product name")
    cve_search.add_argument("version", nargs="?", help="Product version (optional)")
    cve_search.add_argument("--cve-db", default="cve_database.db", help="Path to CVE database")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "cve":
        if not args.cve_command:
            parser.parse_args([args.command, "--help"])
            sys.exit(1)
        if args.cve_command == "stats":
            cmd_cve_stats(args)
        elif args.cve_command == "search":
            cmd_cve_search(args)


if __name__ == "__main__":
    main()
