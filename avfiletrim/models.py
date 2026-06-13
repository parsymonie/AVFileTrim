from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanResult:
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
        return f"{self.detections}/{self.total_engines}"

    @property
    def detected(self) -> bool:
        return self.detections > 0


@dataclass
class TrimJob:
    source: Path
    increment: int
    strategy: str          # "linear" | "bisect"
    api_key: str
    results: list[ScanResult] = field(default_factory=list)

    @property
    def file_size(self) -> int:
        return self.source.stat().st_size

    def offsets_linear(self) -> list[int]:
        size = self.file_size
        return list(range(self.increment, size, self.increment)) + [size]
