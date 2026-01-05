from rich.console import Console
from rich.table import Table

console = Console()


def display_results(all_services):
    table = Table(title="[bold blue]Service & Vulnerability Report[/bold blue]")

    table.add_column("Port", style="cyan", no_wrap=True)
    table.add_column("Service", style="white")
    table.add_column("Version / CPE", style="dim")
    table.add_column("CVE", style="yellow")
    table.add_column("Risk (Confidence)", justify="center")
    table.add_column("Exploit", justify="center")

    for svc in all_services:
        vulns = svc.get("vulnerabilities", [])
        service = f"{svc.get('name')} | {svc.get('product')}"
        version = f"{svc.get('version')}\n[dim]{svc.get('cpe')}[/dim]"

        if not vulns:
            table.add_row(
                str(svc.get("port")),
                service,
                version,
                "[green]No CVEs found[/green]",
                "-",
                "-"
            )
            continue

        for v in vulns:
            score = v.get("cvss", {}).get("score", 0.0)
            confidence = v.get("confidence", "LOW")

            if score >= 9.0:
                risk = "[bold red]CRITICAL[/bold red]"
            elif score >= 7.0:
                risk = "[red]HIGH[/red]"
            elif score >= 4.0:
                risk = "[yellow]MEDIUM[/yellow]"
            else:
                risk = "[green]LOW[/green]"

            exploit = "[bold green]YES[/bold green]" if v.get("exploit") else "No"

            table.add_row(
                str(svc.get("port")),
                service,
                version,
                v.get("id"),
                f"{score} {risk} ({confidence})",
                exploit
            )

    console.print(table)
