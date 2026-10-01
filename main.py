import argparse
import sys
from rich.console import Console
from core.vt_client import VirusTotalClient
from core.abuseipdb_client import AbuseIPDBClient
from core.parsers import ThreatDataParser
from core.reporter import ThreatReporter
from core.utils import calculate_file_hashes
from core.batch import BatchScanner

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threatintel-cli",
        description="A multi-source Threat Intelligence CLI tool (VirusTotal v3 & AbuseIPDB).",
        epilog="Example: python main.py --batch targets.txt --export-cef"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-H", "--hash", type=str, help="Target file hash (MD5, SHA-1, SHA-256).")
    group.add_argument("-u", "--url", type=str, help="Target URL to investigate.")
    group.add_argument("-i", "--ip", type=str, help="Target IPv4 or IPv6 address (AbuseIPDB).")
    group.add_argument("-f", "--file", type=str, help="Path to a local file to automatically hash and analyze.")
    group.add_argument("-b", "--batch", type=str, help="Path to a text file containing multiple mixed IoCs.")

    parser.add_argument(
        "-o", "--export",
        nargs="?",
        const="outputs/threat_report.json",
        default=None,
        help="Export parsed IoC report to a JSON file (default: outputs/threat_report.json)."
    )

    parser.add_argument(
        "--export-cef",
        nargs="?",
        const="outputs/threat_events.cef",
        default=None,
        help="Export parsed IoC report to CEF format for SIEM ingestion."
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    vt_client = VirusTotalClient()
    abuse_client = AbuseIPDBClient()
    threat_parser = ThreatDataParser()
    reporter = ThreatReporter()

    # 1. Batch Execution
    if args.batch:
        scanner = BatchScanner(delay_seconds=15)
        try:
            batch_results = scanner.run_batch(args.batch)
            scanner.display_batch_summary(batch_results)

            if args.export:
                reporter.export_json({"batch_results": batch_results}, output_path=args.export)
            if args.export_cef:
                reporter.export_cef({"batch_results": batch_results}, output_path=args.export_cef)

        except FileNotFoundError as e:
            console.print(f"[bold red][!] {str(e)}[/bold red]")
            sys.exit(1)
        return

    # 2. Single Target Execution
    with console.status("[bold cyan]Querying Threat Intelligence APIs...", spinner="dots"):
        if args.ip:
            raw_response = abuse_client.check_ip(args.ip)
            parsed_report = threat_parser.parse_ip_report(raw_response)
        elif args.file:
            try:
                file_info = calculate_file_hashes(args.file)
                console.print(f"[dim]Calculated SHA-256: {file_info['sha256']}[/dim]")
                raw_response = vt_client.get_file_report(file_info["sha256"])
                parsed_report = threat_parser.parse_file_report(raw_response)
            except FileNotFoundError as e:
                console.print(f"[bold red][!] {str(e)}[/bold red]")
                sys.exit(1)
        elif args.hash:
            raw_response = vt_client.get_file_report(args.hash)
            parsed_report = threat_parser.parse_file_report(raw_response)
        elif args.url:
            raw_response = vt_client.get_url_report(args.url)
            parsed_report = threat_parser.parse_url_report(raw_response)
        else:
            parser.print_help()
            sys.exit(1)

    reporter.display_report(parsed_report)

    if args.export and "error" not in parsed_report:
        reporter.export_json(parsed_report, output_path=args.export)

    if args.export_cef and "error" not in parsed_report:
        reporter.export_cef(parsed_report, output_path=args.export_cef)


if __name__ == "__main__":
    main()