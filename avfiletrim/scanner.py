from __future__ import annotations

import time
from pathlib import Path

import httpx

from .base import ScannerError
from .models import ScanResult

_VT_API_BASE_URL = "https://www.virustotal.com/api/v3"
# Free tier allows 4 requests/min; 16 s between uploads stays safely under that.
_DEFAULT_REQUEST_DELAY = 16.0


class VirusTotalError(ScannerError):
    """Raised when the VirusTotal API returns an unexpected response."""


class VirusTotalClient:
    """HTTP client for the VirusTotal v3 API.

    Args:
        api_key: VirusTotal API key for authentication.
        request_delay: Seconds to wait between consecutive uploads to
            respect the free-tier rate limit.
    """

    def __init__(self, api_key: str, request_delay: float = _DEFAULT_REQUEST_DELAY) -> None:
        self._headers = {"x-apikey": api_key}
        self.request_delay = request_delay
        self._http = httpx.Client(headers=self._headers, timeout=60)

    def close(self) -> None:
        """Close the underlying HTTP connection."""
        self._http.close()

    def __enter__(self) -> "VirusTotalClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def upload(self, path: Path) -> str:
        """Upload a file to VirusTotal and return its analysis ID.

        Args:
            path: Local file to upload.

        Returns:
            VirusTotal analysis ID string.

        Raises:
            VirusTotalError: If the API returns a non-2xx status.
        """
        with path.open("rb") as file_handle:
            response = self._http.post(
                f"{_VT_API_BASE_URL}/files",
                files={"file": file_handle},
            )
        _raise_for_status(response)
        return response.json()["data"]["id"]

    def get_analysis(self, analysis_id: str) -> dict:
        """Fetch the current state of a VirusTotal analysis.

        Args:
            analysis_id: VirusTotal analysis ID.

        Returns:
            Raw JSON response dict from the API.

        Raises:
            VirusTotalError: If the API returns a non-2xx status.
        """
        response = self._http.get(f"{_VT_API_BASE_URL}/analyses/{analysis_id}")
        _raise_for_status(response)
        return response.json()

    def wait_for_completion(self, analysis_id: str, poll_interval: float = 10.0) -> dict:
        """Poll until the analysis is complete and return the final result.

        Args:
            analysis_id: VirusTotal analysis ID to poll.
            poll_interval: Seconds between poll attempts.

        Returns:
            Completed analysis response dict.
        """
        while True:
            data = self.get_analysis(analysis_id)
            if data["data"]["attributes"]["status"] == "completed":
                return data
            time.sleep(poll_interval)

    def scan_bytes(self, data: bytes, offset: int, suffix: str = ".bin") -> ScanResult:
        """Upload a byte slice and return a populated ScanResult.

        Args:
            data: Raw bytes of the file slice to upload.
            offset: Byte offset this slice represents (used for labelling).
            suffix: File extension hint for the temporary upload file.

        Returns:
            Populated ScanResult for this slice.
        """
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as tmp:
            tmp.write(data)
            tmp.flush()
            analysis_id = self.upload(Path(tmp.name))

        time.sleep(self.request_delay)
        result = self.wait_for_completion(analysis_id)
        return _parse_result(result, offset, len(data), analysis_id)


def _raise_for_status(response: httpx.Response) -> None:
    """Raise VirusTotalError for non-2xx responses.

    Args:
        response: httpx response to inspect.

    Raises:
        VirusTotalError: On rate-limit (429) or any other error status.
    """
    if response.status_code == 429:
        raise VirusTotalError("Rate limit exceeded — reduce request frequency")
    if response.is_error:
        raise VirusTotalError(f"HTTP {response.status_code}: {response.text[:200]}")


def _parse_result(
    data: dict,
    offset: int,
    file_size: int,
    analysis_id: str,
) -> ScanResult:
    """Convert a raw VirusTotal analysis response into a ScanResult.

    Args:
        data: Raw JSON response from the VirusTotal analyses endpoint.
        offset: Byte offset the slice was trimmed at.
        file_size: Size of the uploaded slice in bytes.
        analysis_id: VirusTotal analysis ID.

    Returns:
        Populated ScanResult.
    """
    attrs = data["data"]["attributes"]
    stats = attrs.get("stats", {})
    engine_results = attrs.get("results", {})

    engine_hits = {
        engine: info["result"]
        for engine, info in engine_results.items()
        if info.get("category") == "malicious" and info.get("result")
    }

    sha256 = attrs.get("sha256", "")
    permalink = f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else ""

    return ScanResult(
        offset=offset,
        file_size=file_size,
        sha256=sha256,
        analysis_id=analysis_id,
        detections=stats.get("malicious", 0),
        total_engines=sum(stats.values()),
        permalink=permalink,
        engine_hits=engine_hits,
    )
