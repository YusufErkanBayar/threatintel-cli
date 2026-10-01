import json
import os
from typing import Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class ThreatReporter:
    """Renders formatted CLI reports using Rich and exports structured output."""

    @staticmethod
    def _get_threat_color(threat_level: str) -> str:
        if "CLEAN" in threat_level:
            return "bold green"
        elif "LOW" in threat_level:
            return "bold yellow"
        elif "MEDIUM" in threat_level:
            return "bold dark_orange"
        else:
            return "bold red"

    def display_report(self, data: Dict[str, Any]) -> None:
        if "error" in data:
            console.print(Panel(f"[bold red]Error:[/bold red] {data['error']}", title="Threat Intel Alert", expand=False))
            return

        threat_color = self._get_threat_color(data["threat_level"])

        summary_table = Table(title="Target Overview & Metadata", show_lines=True)
        summary_table.add_column("Property", style="bold cyan", width=22)
        summary_table.add_column("Value", style="white")

        summary_table.add_row("Target Type", data.get("target_type", "UNKNOWN"))

        if data["target_type"] == "FILE HASH":
            stats = data.get("stats", {})
            ratio = f"{stats.get('malicious', 0) + stats.get('suspicious', 0)}/{stats.get('total', 0)}"
            summary_table.add_row("Meaningful Name", str(data.get("meaningful_name")))
            summary_table.add_row("File Type", str(data.get("file_type")))
            summary_table.add_row("SHA-256", str(data.get("sha256")))
            summary_table.add_row("MD5", str(data.get("md5")))
            summary_table.add_row("First Submission", str(data.get("first_submission")))
            summary_table.add_row("Last Analysis Date", str(data.get("last_analysis_date")))
            summary_table.add_row("Detection Ratio", f"[{threat_color}]{ratio}[/]")

        elif data["target_type"] == "URL":
            stats = data.get("stats", {})
            ratio = f"{stats.get('malicious', 0) + stats.get('suspicious', 0)}/{stats.get('total', 0)}"
            summary_table.add_row("Queried URL", str(data.get("url")))
            summary_table.add_row("Resolved URL", str(data.get("last_final_url")))
            summary_table.add_row("Reputation Score", str(data.get("reputation")))
            summary_table.add_row("Last Analysis Date", str(data.get("last_analysis_date")))
            summary_table.add_row("Detection Ratio", f"[{threat_color}]{ratio}[/]")

        elif data["target_type"] == "IP ADDRESS":
            summary_table.add_row("IP Address", str(data.get("ip_address")))
            summary_table.add_row("Country / ISP", f"{data.get('country_code')} - {data.get('isp')}")
            summary_table.add_row("Domain / Usage", f"{data.get('domain')} ({data.get('usage_type')})")
            summary_table.add_row("Total Reports", f"{data.get('total_reports')} reports from {data.get('distinct_users')} distinct users")
            summary_table.add_row("Last Reported At", str(data.get("last_reported_at")))
            summary_table.add_row("Abuse Confidence Score", f"[{threat_color}]{data.get('abuse_score')}%[/]")

        summary_table.add_row("Threat Classification", f"[{threat_color}]{data['threat_level']}[/]")
        console.print(summary_table)

        detections = data.get("detections", [])
        if detections:
            det_table = Table(title=f"Flagged Security Engines ({len(detections)})", show_lines=False)
            det_table.add_column("Antivirus Engine", style="bold magenta", width=25)
            det_table.add_column("Verdict", style="yellow", width=15)
            det_table.add_column("Tier", justify="center", width=10)
            det_table.add_column("Threat Classification / Signature", style="red")

            for det in detections[:20]:
                tier_badge = "[bold cyan]TIER-1[/bold cyan]" if det.get("is_tier1") else "[dim]Standard[/dim]"
                det_table.add_row(det["engine"], det["category"], tier_badge, det["result"])

            if len(detections) > 20:
                det_table.add_row("...", "...", "...", f"... and {len(detections) - 20} more engines.")

            console.print(det_table)
        elif data["target_type"] in ("FILE HASH", "URL"):
            console.print("[bold green][✓] No security engines flagged this target as suspicious or malicious.[/bold green]\n")

    def export_json(self, data: Dict[str, Any], output_path: str = "outputs/vt_report.json") -> None:
        """Exports the parsed data to a JSON file."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            console.print(f"[bold green][✓] Threat intelligence report exported to: {output_path}[/bold green]")
        except IOError as e:
            console.print(f"[bold red][!] Failed to export report: {str(e)}[/bold red]")

    def export_cef(self, data: Dict[str, Any], output_path: str = "outputs/threat_events.cef") -> None:
        """Exports parsed events to ArcSight Common Event Format (CEF)."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        severity_map = {
            "CLEAN": 1,
            "LOW RISK": 4,
            "HIGH RISK": 7,
            "CRITICAL RISK (Malicious)": 10
        }

        cef_lines = []
        reports = data.get("batch_results", [data])

        for rep in reports:
            if "error" in rep:
                continue

            target_type = rep.get("target_type", "UNKNOWN")
            severity = severity_map.get(rep.get("threat_level"), 5)
            threat_name = rep.get("threat_level", "Unknown Threat")

            if target_type == "FILE HASH":
                ext = f"fileHash={rep.get('sha256')} fname={rep.get('meaningful_name')} msg=DetectionRatio:{rep.get('stats', {}).get('malicious')}"
                sig_id = "1001"
            elif target_type == "URL":
                ext = f"request={rep.get('url')} msg=URL_Reputation:{rep.get('reputation')}"
                sig_id = "1002"
            elif target_type == "IP ADDRESS":
                ext = f"src={rep.get('ip_address')} cs1={rep.get('isp')} cs1Label=ISP cs2={rep.get('abuse_score')}% cs2Label=AbuseConfidence"
                sig_id = "1003"
            else:
                continue

            cef_entry = f"CEF:0|ThreatIntel-CLI|Scanner|1.0|{sig_id}|{threat_name}|{severity}|{ext}\n"
            cef_lines.append(cef_entry)

        try:
            with open(output_path, "a", encoding="utf-8") as f:
                f.writelines(cef_lines)
            console.print(f"[bold green][✓] CEF security events appended to: {output_path}[/bold green]")
        except IOError as e:
            console.print(f"[bold red][!] Failed to export CEF: {str(e)}[/bold red]")