from __future__ import annotations

import time
from pathlib import Path

import httpx

from .models import ScanResult

_BASE = "https://www.virustotal.com/api/v3"
# Free tier: 4 req/min
_DEFAULT_DELAY = 16.0


class VirusTotalError(Exception):
    pass


class VirusTotalClient:
    def __init__(self, api_key: str, request_delay: float = _DEFAULT_DELAY) -> None:
        self._headers = {"x-apikey": api_key}
        self.request_delay = request_delay
        self._http = httpx.Client(headers=self._headers, timeout=60)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "VirusTotalClient":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def upload(self, path: Path) -> str:
        """Upload a file and return its analysis ID."""
        with path.open("rb") as fh:
            resp = self._http.post(f"{_BASE}/files", files={"file": fh})
        self._raise_for_status(resp)
        return resp.json()["data"]["id"]

    def get_analysis(self, analysis_id: str) -> dict:
        resp = self._http.get(f"{_BASE}/analyses/{analysis_id}")
        self._raise_for_status(resp)
        return resp.json()

    def wait_for_completion(self, analysis_id: str, poll_interval: float = 10.0) -> dict:
        while True:
            data = self.get_analysis(analysis_id)
            if data["data"]["attributes"]["status"] == "completed":
                return data
            time.sleep(poll_interval)

    def scan_bytes(self, data: bytes, offset: int, suffix: str = ".bin") -> ScanResult:
        """Upload `data` as a trimmed slice and return a populated ScanResult."""
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as tmp:
            tmp.write(data)
            tmp.flush()
            analysis_id = self.upload(Path(tmp.name))

        time.sleep(self.request_delay)
        result = self.wait_for_completion(analysis_id)
        return _parse_result(result, offset, len(data), analysis_id)

    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        if resp.status_code == 429:
            raise VirusTotalError("Rate limit exceeded — reduce request frequency")
        if resp.is_error:
            raise VirusTotalError(f"HTTP {resp.status_code}: {resp.text[:200]}")


def _parse_result(data: dict, offset: int, size: int, analysis_id: str) -> ScanResult:
    attrs = data["data"]["attributes"]
    stats = attrs.get("stats", {})
    results = attrs.get("results", {})

    engine_hits = {
        engine: info["result"]
        for engine, info in results.items()
        if info.get("category") == "malicious" and info.get("result")
    }

    sha256 = attrs.get("sha256", "")
    permalink = f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else ""

    return ScanResult(
        offset=offset,
        file_size=size,
        sha256=sha256,
        analysis_id=analysis_id,
        detections=stats.get("malicious", 0),
        total_engines=sum(stats.values()),
        permalink=permalink,
        engine_hits=engine_hits,
    )
