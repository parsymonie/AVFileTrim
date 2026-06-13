from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from typing import Iterator


def slice_file(source: Path, offset: int) -> bytes:
    """Return the first *offset* bytes of *source*.

    Args:
        source: Path to the binary file to read.
        offset: Number of bytes to read from the start of the file.

    Returns:
        Raw bytes of the requested slice.
    """
    with source.open("rb") as file_handle:
        return file_handle.read(offset)


def sha256_of(data: bytes) -> str:
    """Compute the hex-encoded SHA-256 digest of *data*.

    Args:
        data: Arbitrary byte sequence to hash.

    Returns:
        Lowercase hexadecimal SHA-256 string.
    """
    return hashlib.sha256(data).hexdigest()


def iter_slices(source: Path, increment: int) -> Iterator[tuple[int, bytes]]:
    """Yield ``(offset, data)`` pairs from *increment* up to the full file size.

    Args:
        source: Path to the binary file to slice.
        increment: Byte step between consecutive slices.

    Yields:
        Tuples of ``(offset, raw_bytes)`` where *offset* is the exclusive
        upper bound of the slice (i.e. the slice is ``file[:offset]``).
    """
    file_size = source.stat().st_size
    offsets = list(range(increment, file_size, increment))
    if not offsets or offsets[-1] != file_size:
        offsets.append(file_size)
    for offset in offsets:
        yield offset, slice_file(source, offset)


def write_temp_slice(data: bytes, suffix: str = ".bin") -> Path:
    """Write *data* to a named temporary file and return its path.

    Args:
        data: Bytes to write.
        suffix: File extension for the temporary file.

    Returns:
        Path to the newly created temporary file.
    """
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    tmp.write(data)
    tmp.flush()
    return Path(tmp.name)
