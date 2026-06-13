from __future__ import annotations

import time

import httpx

from .base import ScannerError
from .models import ScanResult

_MD_API_BASE_URL = "https://api.metadefender.com/v4"
# Free tier allows ~10 requests/min; 6 s between uploads stays safely under that.
_DEFAULT_REQUEST_DELAY = 6.0
# MetaDefender per-engine scan_result_i codes that count as a detection.
_INFECTED = 1
_SUSPICIOUS = 2


class MetaDefenderError(ScannerError):
    """Raised when the MetaDefender API returns an unexpected response."""


class MetaDefenderClient:
    """HTTP client for the OPSWAT MetaDefender Cloud v4 API.

    Args:
        api_key: MetaDefender Cloud API key for authentication.
        request_delay: Seconds to wait between consecutive uploads to
            respect the free-tier rate limit.
    """

    def __init__(self, api_key: str, request_delay: float = _DEFAULT_REQUEST_DELAY) -> None:
        self._headers = {"apikey": api_key}
        self.request_delay = request_delay
        self._http = httpx.Client(headers=self._headers, timeout=60)

    def close(self) -> None:
        """Close the underlying HTTP connection."""
        self._http.close()

    def __enter__(self) -> "MetaDefenderClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def upload(self, data: bytes, filename: str) -> str:
        """Upload raw bytes to MetaDefender and return its data ID.

        Args:
            data: Raw bytes of the file slice to upload.
            filename: Suggested file name reported to the scanner.

        Returns:
            MetaDefender ``data_id`` string.

        Raises:
            MetaDefenderError: If the API returns a non-2xx status.
        """
        response = self._http.post(
            f"{_MD_API_BASE_URL}/file",
            content=data,
            headers={
                "content-type": "application/octet-stream",
                "filename": filename,
            },
        )
        _raise_for_status(response)
        return response.json()["data_id"]

    def get_analysis(self, data_id: str) -> dict:
        """Fetch the current state of a MetaDefender analysis.

        Args:
            data_id: MetaDefender data ID.

        Returns:
            Raw JSON response dict from the API.

        Raises:
            MetaDefenderError: If the API returns a non-2xx status.
        """
        response = self._http.get(f"{_MD_API_BASE_URL}/file/{data_id}")
        _raise_for_status(response)
        return response.json()

    def wait_for_completion(self, data_id: str, poll_interval: float = 5.0) -> dict:
        """Poll until the analysis is complete and return the final result.

        Args:
            data_id: MetaDefender data ID to poll.
            poll_interval: Seconds between poll attempts.

        Returns:
            Completed analysis response dict.
        """
        while True:
            data = self.get_analysis(data_id)
            progress = data.get("scan_results", {}).get("progress_percentage", 0)
            if progress == 100:
                return data
            time.sleep(poll_interval)

    def scan_bytes(self, data: bytes, offset: int, suffix: str = ".bin") -> ScanResult:
        """Upload a byte slice and return a populated ScanResult.

        Args:
            data: Raw bytes of the file slice to upload.
            offset: Byte offset this slice represents (used for labelling).
            suffix: File extension hint for the uploaded slice name.

        Returns:
            Populated ScanResult for this slice.
        """
        data_id = self.upload(data, filename=f"slice_{offset:010d}{suffix}")
        time.sleep(self.request_delay)
        result = self.wait_for_completion(data_id)
        return _parse_result(result, offset, len(data), data_id)


def _raise_for_status(response: httpx.Response) -> None:
    """Raise MetaDefenderError for non-2xx responses.

    Args:
        response: httpx response to inspect.

    Raises:
        MetaDefenderError: On rate-limit (429) or any other error status.
    """
    if response.status_code == 429:
        raise MetaDefenderError("Rate limit exceeded — reduce request frequency")
    if response.is_error:
        raise MetaDefenderError(f"HTTP {response.status_code}: {response.text[:200]}")


def _parse_result(
    data: dict,
    offset: int,
    file_size: int,
    data_id: str,
) -> ScanResult:
    """Convert a raw MetaDefender analysis response into a ScanResult.

    Args:
        data: Raw JSON response from the MetaDefender file endpoint.
        offset: Byte offset the slice was trimmed at.
        file_size: Size of the uploaded slice in bytes.
        data_id: MetaDefender data ID.

    Returns:
        Populated ScanResult.
    """
    scan_results = data.get("scan_results", {})
    file_info = data.get("file_info", {})
    scan_details = scan_results.get("scan_details", {})

    engine_hits = {
        engine: info["threat_found"]
        for engine, info in scan_details.items()
        if info.get("scan_result_i") in (_INFECTED, _SUSPICIOUS) and info.get("threat_found")
    }

    detections = scan_results.get("total_detected_avs", len(engine_hits))
    total_engines = scan_results.get("total_avs", len(scan_details))

    sha256 = file_info.get("sha256", "")
    permalink = (
        f"https://metadefender.opswat.com/results/file/{data_id}/regular/overview"
        if data_id
        else ""
    )

    return ScanResult(
        offset=offset,
        file_size=file_size,
        sha256=sha256,
        analysis_id=data_id,
        detections=detections,
        total_engines=total_engines,
        permalink=permalink,
        engine_hits=engine_hits,
    )
