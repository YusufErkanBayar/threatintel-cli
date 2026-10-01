import time
import os
from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from core.vt_client import VirusTotalClient
from core.abuseipdb_client import AbuseIPDBClient
from core.parsers import ThreatDataParser
from core.utils import identify_ioc_type, defang_ioc

console = Console()


class BatchScanner:
    """Processes multiple IoCs sequentially with rate-limit and multi-source routing."""

    def __init__(self, delay_seconds: int = 15) -> None:
        self.delay_seconds = delay_seconds
        self.vt_client = VirusTotalClient()
        self.abuse_client = AbuseIPDBClient()
        self.parser = ThreatDataParser()

    def load_targets(self, file_path: str) -> List[str]:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Batch file not found: {file_path}")

        targets = []
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                cleaned = line.strip()
                if cleaned and not cleaned.startswith("#"):
                    targets.append(cleaned)
        return targets

    def run_batch(self, file_path: str) -> List[Dict[str, Any]]:
        targets = self.load_targets(file_path)
        total = len(targets)
        results = []

        console.print(f"[bold cyan][*] Loaded {total} targets for batch processing.[/bold cyan]")
        if total > 4:
            console.print(f"[yellow][!] Rate limit safety active. {self.delay_seconds}s interval applied.[/yellow]")

        for index, target in enumerate(targets, start=1):
            ioc_type, clean_target = identify_ioc_type(target)
            console.print(f"\n[bold white]({index}/{total}) Processing [{ioc_type.upper()}]:[/bold white] [cyan]{clean_target}[/cyan]")

            if ioc_type == "ip":
                raw_response = self.abuse_client.check_ip(clean_target)
                parsed = self.parser.parse_ip_report(raw_response)
            elif ioc_type == "hash":
                raw_response = self.vt_client.get_file_report(clean_target)
                parsed = self.parser.parse_file_report(raw_response)
            elif ioc_type == "url":
                raw_response = self.vt_client.get_url_report(clean_target)
                parsed = self.parser.parse_url_report(raw_response)
            else:
                parsed = {"error": f"Unrecognized IoC format: {target}", "target_type": "UNKNOWN"}

            parsed["target"] = clean_target
            results.append(parsed)

            if index < total:
                time.sleep(self.delay_seconds)

        return results

    def display_batch_summary(self, results: List[Dict[str, Any]]) -> None:
        table = Table(title="Batch Threat Intelligence Summary", show_lines=True)
        table.add_column("Target (Defanged)", style="cyan", width=35, overflow="ellipsis")
        table.add_column("Type", style="magenta", width=12)
        table.add_column("Score / Ratio", justify="center", width=15)
        table.add_column("Threat Classification", width=25)
        table.add_column("Tier-1 Hits", justify="center", width=12)

        for res in results:
            target_str = defang_ioc(res.get("target", "N/A"))
            if "error" in res:
                table.add_row(target_str, res.get("target_type", "ERROR"), "-", f"[dim]{res['error']}[/dim]", "-")
                continue

            target_type = res.get("target_type", "UNKNOWN")
            threat_level = res["threat_level"]
            tier1_count = str(len(res.get("tier1_flagged", [])))

            # Risk color
            if "CRITICAL" in threat_level:
                risk_style = "bold red"
            elif "HIGH" in threat_level:
                risk_style = "bold dark_orange"
            elif "LOW" in threat_level:
                risk_style = "bold yellow"
            else:
                risk_style = "bold green"

            # Metrics
            if target_type == "IP ADDRESS":
                metric = f"Abuse: {res.get('abuse_score', 0)}%"
                tier1_display = "[dim]N/A[/dim]"
            else:
                stats = res.get("stats", {})
                metric = f"{stats.get('malicious', 0) + stats.get('suspicious', 0)}/{stats.get('total', 0)}"
                tier1_display = f"[bold red]{tier1_count}[/bold red]" if int(tier1_count) > 0 else "[dim]0[/dim]"

            table.add_row(
                target_str,
                target_type,
                metric,
                f"[{risk_style}]{threat_level}[/]",
                tier1_display
            )

        console.print(table)