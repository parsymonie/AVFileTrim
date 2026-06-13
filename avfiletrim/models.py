from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanResult:
    """Result of a single VirusTotal scan for one file slice.

    Attributes:
        offset: Byte offset at which the source file was trimmed.
        file_size: Size of the uploaded slice in bytes.
        sha256: SHA-256 digest returned by VirusTotal.
        analysis_id: VirusTotal analysis identifier.
        detections: Number of engines that flagged the slice.
        total_engines: Total number of engines that participated.
        permalink: VirusTotal GUI URL for the file report.
        engine_hits: Mapping of engine name to reported threat name.
    """

    offset: int
    file_size: int
    sha256: str
    analysis_id: str
    detections: int
    total_engines: int
    permalink: str
    engine_hits: dict[str, str] = field(default_factory=dict)

    @property
    def ratio(self) -> str:
        """Detection ratio as a human-readable string, e.g. '3/72'."""
        return f"{self.detections}/{self.total_engines}"

    @property
    def detected(self) -> bool:
        """True if at least one engine flagged this slice."""
        return self.detections > 0


@dataclass
class TrimJob:
    """Configuration and accumulated results for a single trim-and-scan run.

    Attributes:
        source: Path to the original binary file.
        increment: Byte step between consecutive slices.
        strategy: Scan strategy — 'linear' or 'bisect'.
        api_key: VirusTotal API key.
        results: Scan results collected during the run.
    """

    source: Path
    increment: int
    strategy: str
    api_key: str
    results: list[ScanResult] = field(default_factory=list)

    @property
    def file_size(self) -> int:
        """Size of the source file in bytes."""
        return self.source.stat().st_size

    def offsets_linear(self) -> list[int]:
        """Return all slice offsets for a linear scan.

        Returns:
            Sorted list of byte offsets ending with the full file size.
        """
        size = self.file_size
        return list(range(self.increment, size, self.increment)) + [size]
