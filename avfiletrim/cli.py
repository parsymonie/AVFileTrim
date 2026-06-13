from __future__ import annotations

import json
import os
from pathlib import Path

import click
import pyfiglet
from rich.console import Console
from rich.table import Table
from rich import box

from .base import Scanner, ScannerError
from .metadefender import MetaDefenderClient
from .models import ScanResult, TrimJob
from .scanner import VirusTotalClient
from .trimmer import iter_slices, sha256_of

console = Console()

_BANNER_FONT = "slant"
_BANNER_SUBTITLE = "AV signature boundary finder"

# Per-backend settings: env var holding the API key and a safe default upload
# delay (seconds) for the free tier.
_SCANNER_CONFIG = {
    "virustotal": {"env_var": "VT_API_KEY", "default_delay": 16.0},
    "metadefender": {"env_var": "MCL_API_KEY", "default_delay": 6.0},
}


def create_scanner(scanner_name: str, api_key: str, request_delay: float) -> Scanner:
    """Instantiate the scanner backend selected on the command line.

    Args:
        scanner_name: Backend identifier — 'virustotal' or 'metadefender'.
        api_key: API key for the chosen backend.
        request_delay: Seconds to wait between consecutive uploads.

    Returns:
        A ready-to-use scanner client implementing the Scanner protocol.
    """
    if scanner_name == "metadefender":
        return MetaDefenderClient(api_key=api_key, request_delay=request_delay)
    return VirusTotalClient(api_key=api_key, request_delay=request_delay)


def print_banner() -> None:
    """Print the project ASCII art banner to the console."""
    ascii_art = pyfiglet.figlet_format("AVFileTrim", font=_BANNER_FONT)
    console.print(f"[bold #ff69b4]{ascii_art}[/bold #ff69b4]", end="")
    console.print(f"  [#ffb6c1]{_BANNER_SUBTITLE}[/#ffb6c1]\n")


def build_results_table(results: list[ScanResult]) -> Table:
    """Build a Rich table summarising scan results.

    Args:
        results: List of scan results to display.

    Returns:
        Populated Rich Table object ready to render.
    """
    table = Table(box=box.ROUNDED, show_lines=False)
    table.add_column("Offset", justify="right", style="#ff69b4")
    table.add_column("Size", justify="right", style="dim")
    table.add_column("Detections", justify="center")
    table.add_column("SHA-256", style="dim", no_wrap=True)

    for result in results:
        detection_style = "red bold" if result.detected else "green"
        table.add_row(
            f"{result.offset:,}",
            f"{result.file_size:,}",
            f"[{detection_style}]{result.ratio}[/{detection_style}]",
            result.sha256[:16] + "…" if result.sha256 else "—",
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
    help="linear: scan every increment; bisect: binary-search for first detection. Requires --api-key.",
)
@click.option(
    "--scanner", "-S",
    type=click.Choice(["virustotal", "metadefender"]),
    default="virustotal",
    show_default=True,
    help="Online scanner backend to use.",
)
@click.option(
    "--api-key", "-k",
    default=None,
    help="API key for the chosen scanner (or set VT_API_KEY / MCL_API_KEY). "
         "Omit to save slices to disk instead.",
)
@click.option(
    "--delay", "-d",
    type=float,
    default=None,
    help="Seconds between uploads (default: 16 for virustotal, 6 for metadefender).",
)
@click.option(
    "--output", "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write scan results to a JSON file (scan mode only).",
)
@click.option(
    "--output-dir", "-O",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("out"),
    show_default=True,
    help="Directory to write slices when no API key is provided.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Print slice offsets without uploading or writing anything.",
)
def main(
    file: Path,
    increment: int,
    strategy: str,
    scanner: str,
    api_key: str | None,
    delay: float | None,
    output: Path | None,
    output_dir: Path,
    dry_run: bool,
) -> None:
    """Trim FILE at byte increments and scan each slice with an online scanner.

    Supports VirusTotal and MetaDefender. Without --api-key the slices are
    written to disk for manual upload.

    \b
    Examples:
      avfiletrim malware.exe -i 8192
      avfiletrim malware.exe -i 4096 -O ./slices
      avfiletrim malware.exe -s bisect -k $VT_API_KEY -o results.json
      avfiletrim malware.exe -S metadefender -k $MCL_API_KEY
      avfiletrim malware.exe -i 1024 --dry-run
    """
    print_banner()

    config = _SCANNER_CONFIG[scanner]
    if not api_key:
        api_key = os.environ.get(config["env_var"])
    if delay is None:
        delay = config["default_delay"]

    file_size = file.stat().st_size
    console.print(f"[bold]Target:[/bold] [#ff69b4]{file.name}[/#ff69b4] ({file_size:,} bytes)")
    console.print(
        f"[bold]Scanner:[/bold] [#ffb6c1]{scanner}[/#ffb6c1]   "
        f"[bold]Strategy:[/bold] [#ffb6c1]{strategy}[/#ffb6c1]   "
        f"[bold]Increment:[/bold] [#ffb6c1]{increment:,}[/#ffb6c1] bytes\n"
    )

    if dry_run:
        slice_offsets = [offset for offset, _ in iter_slices(file, increment)]
        console.print(f"[dim]Dry run — {len(slice_offsets)} slices:[/dim]")
        for offset in slice_offsets:
            console.print(f"  {offset:,} bytes")
        return

    if not api_key:
        run_offline(file, increment, output_dir)
        return

    job = TrimJob(source=file, increment=increment, strategy=strategy, api_key=api_key)

    with create_scanner(scanner, api_key, delay) as scanner_client:
        if strategy == "linear":
            run_linear_scan(scanner_client, job, file)
        else:
            run_bisect_scan(scanner_client, job, file, increment)

    console.print()
    console.print(build_results_table(job.results))

    if output:
        write_json_results(output, job)
        console.print(f"\n[green]Results saved to {output}[/green]")


def run_offline(source: Path, increment: int, output_dir: Path) -> None:
    """Write file slices to disk for manual upload — no API key required.

    Args:
        source: Path to the binary file to slice.
        increment: Byte step between consecutive slices.
        output_dir: Directory where slice files are written.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    slices = list(iter_slices(source, increment))
    console.print(f"[#ffb6c1]No API key — saving {len(slices)} slices to[/#ffb6c1] [#ff69b4]{output_dir}/[/#ff69b4]\n")

    for offset, data in slices:
        digest = sha256_of(data)
        slice_name = f"{source.stem}_{offset:010d}{source.suffix or '.bin'}"
        slice_path = output_dir / slice_name
        slice_path.write_bytes(data)
        console.print(
            f"  [#ff69b4]{offset:>10,}[/#ff69b4] bytes  "
            f"sha256 [dim]{digest[:16]}…[/dim]  → {slice_path.name}"
        )

    console.print(f"\n[#ff69b4]Done — {len(slices)} slices written to {output_dir}/[/#ff69b4]")


def run_linear_scan(scanner_client: Scanner, job: TrimJob, source: Path) -> None:
    """Upload every slice sequentially and record results.

    Args:
        scanner_client: Authenticated scanner backend.
        job: TrimJob holding configuration; results are appended in-place.
        source: Path to the source binary.
    """
    slices = list(iter_slices(source, job.increment))
    total_slices = len(slices)

    with console.status("") as status:
        for idx, (offset, data) in enumerate(slices, 1):
            status.update(f"[cyan]Scanning slice {idx}/{total_slices}[/cyan] — offset {offset:,}")
            try:
                result = scanner_client.scan_bytes(data, offset, suffix=source.suffix or ".bin")
            except ScannerError as error:
                console.print(f"[red]Error at offset {offset:,}: {error}[/red]")
                continue
            job.results.append(result)
            detection_text = (
                f"[red]{result.ratio}[/red]" if result.detected
                else f"[green]{result.ratio}[/green]"
            )
            console.print(f"  offset [#ff69b4]{offset:>10,}[/#ff69b4]  detections {detection_text}")


def run_bisect_scan(
    scanner_client: Scanner,
    job: TrimJob,
    source: Path,
    increment: int,
) -> None:
    """Binary-search for the smallest offset that triggers AV detection.

    Scans the full file first; if detected, bisects to narrow down the
    boundary at *increment* granularity.

    Args:
        scanner_client: Authenticated scanner backend.
        job: TrimJob holding configuration; results are appended in-place.
        source: Path to the source binary.
        increment: Granularity of the bisect (snapped to nearest multiple).
    """
    from .trimmer import slice_file

    file_size = source.stat().st_size
    low, high = increment, file_size

    console.print("[yellow]Bisect mode — scanning full file first…[/yellow]")
    full_data = source.read_bytes()

    with console.status("Scanning full file…"):
        full_result = scanner_client.scan_bytes(full_data, file_size, suffix=source.suffix or ".bin")
    job.results.append(full_result)

    if not full_result.detected:
        console.print("[green]Full file not detected — nothing to bisect.[/green]")
        return

    console.print(f"[red]Full file detected ({full_result.ratio}). Bisecting…[/red]\n")

    while low < high:
        mid = ((low + high) // 2 // increment) * increment or increment
        if mid == low:
            break

        with console.status(f"Bisect [{low:,} … {high:,}] — trying {mid:,}"):
            data = slice_file(source, mid)
            try:
                result = scanner_client.scan_bytes(data, mid, suffix=source.suffix or ".bin")
            except ScannerError as error:
                console.print(f"[red]Error at {mid:,}: {error}[/red]")
                break
        job.results.append(result)

        detection_text = (
            f"[red]{result.ratio}[/red]" if result.detected
            else f"[green]{result.ratio}[/green]"
        )
        console.print(f"  bisect [#ff69b4]{mid:>10,}[/#ff69b4]  detections {detection_text}")

        if result.detected:
            high = mid
        else:
            low = mid

    console.print(f"\n[bold]Signature boundary ~[#ff69b4]{high:,}[/#ff69b4] bytes[/bold]")


def write_json_results(output_path: Path, job: TrimJob) -> None:
    """Serialize all scan results to a JSON file.

    Args:
        output_path: Destination file path.
        job: Completed TrimJob whose results are serialized.
    """
    records = [
        {
            "offset": result.offset,
            "file_size": result.file_size,
            "sha256": result.sha256,
            "detections": result.detections,
            "total_engines": result.total_engines,
            "permalink": result.permalink,
            "engine_hits": result.engine_hits,
        }
        for result in job.results
    ]
    output_path.write_text(json.dumps(records, indent=2))
