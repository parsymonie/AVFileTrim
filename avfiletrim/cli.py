from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import box

from .models import ScanResult, TrimJob
from .trimmer import iter_slices, sha256_of
from .scanner import VirusTotalClient, VirusTotalError

console = Console()


def _build_table(results: list[ScanResult]) -> Table:
    table = Table(box=box.ROUNDED, show_lines=False)
    table.add_column("Offset", justify="right", style="cyan")
    table.add_column("Size", justify="right", style="dim")
    table.add_column("Detections", justify="center")
    table.add_column("SHA-256", style="dim", no_wrap=True)

    for r in results:
        det_style = "red bold" if r.detected else "green"
        table.add_row(
            f"{r.offset:,}",
            f"{r.file_size:,}",
            f"[{det_style}]{r.ratio}[/{det_style}]",
            r.sha256[:16] + "…" if r.sha256 else "—",
        )
    return table


@click.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--increment", "-i",
    type=int,
    default=4096,
    show_default=True,
    help="Byte increment between slices.",
)
@click.option(
    "--strategy", "-s",
    type=click.Choice(["linear", "bisect"]),
    default="linear",
    show_default=True,
    help="linear: scan every increment; bisect: binary-search for first detection.",
)
@click.option(
    "--api-key", "-k",
    envvar="VT_API_KEY",
    required=True,
    help="VirusTotal API key (or set VT_API_KEY env var).",
)
@click.option(
    "--delay", "-d",
    type=float,
    default=16.0,
    show_default=True,
    help="Seconds between uploads (free tier: 4 req/min → 16 s).",
)
@click.option(
    "--output", "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write results to a JSON file.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Print slice offsets without uploading anything.",
)
def main(
    file: Path,
    increment: int,
    strategy: str,
    api_key: str,
    delay: float,
    output: Path | None,
    dry_run: bool,
) -> None:
    """Trim FILE at byte increments and scan each slice on VirusTotal.

    Useful for locating AV signature boundaries in binaries.

    \b
    Examples:
      avfiletrim malware.exe --increment 8192
      avfiletrim sample.zip -i 4096 -s bisect -o results.json
      VT_API_KEY=xxx avfiletrim payload.exe -i 1024 --dry-run
    """
    size = file.stat().st_size
    console.print(f"[bold]AVFileTrim[/bold] — [cyan]{file.name}[/cyan] ({size:,} bytes)")
    console.print(f"Strategy: [yellow]{strategy}[/yellow]  Increment: [yellow]{increment:,}[/yellow] bytes\n")

    if dry_run:
        offsets = [o for o, _ in iter_slices(file, increment)]
        console.print(f"[dim]Dry run — {len(offsets)} slices would be uploaded:[/dim]")
        for o in offsets:
            console.print(f"  {o:,} bytes")
        return

    job = TrimJob(source=file, increment=increment, strategy=strategy, api_key=api_key)

    with VirusTotalClient(api_key=api_key, request_delay=delay) as vt:
        if strategy == "linear":
            _run_linear(vt, job, file)
        else:
            _run_bisect(vt, job, file, increment)

    console.print()
    console.print(_build_table(job.results))

    if output:
        _write_json(output, job)
        console.print(f"\n[green]Results saved to {output}[/green]")


def _run_linear(vt: VirusTotalClient, job: TrimJob, file: Path) -> None:
    slices = list(iter_slices(file, job.increment))
    total = len(slices)

    with console.status("") as status:
        for idx, (offset, data) in enumerate(slices, 1):
            status.update(f"[cyan]Scanning slice {idx}/{total}[/cyan] — offset {offset:,}")
            try:
                result = vt.scan_bytes(data, offset, suffix=file.suffix or ".bin")
            except VirusTotalError as exc:
                console.print(f"[red]Error at offset {offset:,}: {exc}[/red]")
                continue
            job.results.append(result)
            det = f"[red]{result.ratio}[/red]" if result.detected else f"[green]{result.ratio}[/green]"
            console.print(f"  offset [cyan]{offset:>10,}[/cyan]  detections {det}")


def _run_bisect(vt: VirusTotalClient, job: TrimJob, file: Path, increment: int) -> None:
    """Binary search: find smallest offset that triggers detection."""
    size = file.stat().st_size
    lo, hi = increment, size

    console.print("[yellow]Bisect mode — scanning full file first…[/yellow]")
    full_data = file.read_bytes()

    with console.status("Scanning full file…"):
        full_result = vt.scan_bytes(full_data, size, suffix=file.suffix or ".bin")
    job.results.append(full_result)

    if not full_result.detected:
        console.print("[green]Full file not detected — nothing to bisect.[/green]")
        return

    console.print(f"[red]Full file detected ({full_result.ratio}). Bisecting…[/red]\n")

    from .trimmer import slice_file

    while lo < hi:
        mid = ((lo + hi) // 2 // increment) * increment or increment
        if mid == lo:
            break

        with console.status(f"Bisect [{lo:,} … {hi:,}] — trying {mid:,}"):
            data = slice_file(file, mid)
            try:
                result = vt.scan_bytes(data, mid, suffix=file.suffix or ".bin")
            except VirusTotalError as exc:
                console.print(f"[red]Error at {mid:,}: {exc}[/red]")
                break
        job.results.append(result)

        det = f"[red]{result.ratio}[/red]" if result.detected else f"[green]{result.ratio}[/green]"
        console.print(f"  bisect [cyan]{mid:>10,}[/cyan]  detections {det}")

        if result.detected:
            hi = mid
        else:
            lo = mid

    console.print(f"\n[bold]Signature boundary ~[cyan]{hi:,}[/cyan] bytes[/bold]")


def _write_json(path: Path, job: TrimJob) -> None:
    data = [
        {
            "offset": r.offset,
            "file_size": r.file_size,
            "sha256": r.sha256,
            "detections": r.detections,
            "total_engines": r.total_engines,
            "permalink": r.permalink,
            "engine_hits": r.engine_hits,
        }
        for r in job.results
    ]
    path.write_text(json.dumps(data, indent=2))
