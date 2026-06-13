from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from typing import Iterator


def slice_file(source: Path, offset: int) -> bytes:
    """Return the first `offset` bytes of `source`."""
    with source.open("rb") as fh:
        return fh.read(offset)


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def iter_slices(source: Path, increment: int) -> Iterator[tuple[int, bytes]]:
    """Yield (offset, data) pairs from `increment` up to full file size."""
    size = source.stat().st_size
    offsets = list(range(increment, size, increment))
    if not offsets or offsets[-1] != size:
        offsets.append(size)
    for offset in offsets:
        yield offset, slice_file(source, offset)


def write_temp_slice(data: bytes, suffix: str = ".bin") -> Path:
    """Write `data` to a named temp file and return its path."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    tmp.write(data)
    tmp.flush()
    return Path(tmp.name)
