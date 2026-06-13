from __future__ import annotations

from typing import Protocol, runtime_checkable

from .models import ScanResult


class ScannerError(Exception):
    """Base exception for all multi-engine scanner backends."""


@runtime_checkable
class Scanner(Protocol):
    """Common interface implemented by every scanner backend.

    A scanner uploads a byte slice to a multi-engine service and returns a
    populated :class:`~avfiletrim.models.ScanResult`. Implementations are
    used as context managers so network connections are closed cleanly.

    Attributes:
        request_delay: Seconds to wait between consecutive uploads to
            respect the backend's rate limit.
    """

    request_delay: float

    def scan_bytes(self, data: bytes, offset: int, suffix: str = ".bin") -> ScanResult:
        """Upload *data* and return a populated ScanResult."""
        ...

    def close(self) -> None:
        """Close the underlying HTTP connection."""
        ...

    def __enter__(self) -> "Scanner":
        ...

    def __exit__(self, *args: object) -> None:
        ...
