# AVFileTrim

```text
    ___ _    _________ __   ______     _         
   /   | |  / / ____(_) /__/_  __/____(_)___ ___ 
  / /| | | / / /_  / / / _ \/ / / ___/ / __ `__ \
 / ___ | |/ / __/ / / /  __/ / / /  / / / / / / /
/_/  |_|___/_/   /_/_/\___/_/ /_/  /_/_/ /_/ /_/ 

  AV signature boundary finder
```

```text
   / \       / \
  /   \_____/   \        oink oink — sniffing out signatures
 |  0           0 |      one byte at a time...
 |       __       |
  \     (__) ___ /
   `\_________.-'
       | | | |
      (_) (_)
```

Trim a binary file at regular byte increments and upload each slice to
[VirusTotal](https://www.virustotal.com) to pinpoint exactly where an antivirus
signature starts. Useful for security research, malware analysis, and
understanding detection heuristics.

---

## Features

- **Linear scan** — upload every slice and record detections at each offset
- **Bisect scan** — binary-search for the first detected offset, minimising API calls
- **Offline mode** — no API key needed; slices are written to disk for manual upload
- **Dry run** — preview slice offsets without touching the network or disk
- **JSON export** — machine-readable results with per-engine hits and VT permalinks
- **Configurable output directory** — defaults to `./out/`

---

## Installation

Requires Python 3.11+.

```bash
# recommended: isolated install via pipx
pipx install .

# or inside a virtual environment
python -m venv .venv
source .venv/bin/activate
pip install .
```

---

## Usage

```text
avfiletrim [OPTIONS] FILE
```

| Option | Short | Default | Description |
| --- | --- | --- | --- |
| `--increment` | `-i` | `4096` | Byte step between slices |
| `--strategy` | `-s` | `linear` | `linear` or `bisect` |
| `--api-key` | `-k` | `$VT_API_KEY` | VirusTotal API key (optional) |
| `--delay` | `-d` | `16.0` | Seconds between uploads |
| `--output` | `-o` | — | Save scan results as JSON |
| `--output-dir` | `-O` | `out/` | Directory for offline slices |
| `--dry-run` | | | Preview offsets only |

### Examples

```bash
# Slice every 8 KB and scan — API key from environment variable
VT_API_KEY=xxxx avfiletrim malware.exe -i 8192

# Binary-search with explicit key, save results
avfiletrim sample.exe -s bisect -k $VT_API_KEY -o results.json

# No API key: write slices to ./out/ for manual upload
avfiletrim payload.exe -i 4096

# Write slices to a custom directory
avfiletrim payload.exe -i 4096 -O /tmp/slices

# Preview what would be uploaded without touching anything
avfiletrim payload.exe -i 1024 --dry-run
```

### Offline slice output

Without an API key, slices are saved as:

```text
out/
  payload_0000004096.exe
  payload_0000008192.exe
  payload_0000012288.exe
  ...
```

Each filename encodes the trim offset, making it easy to sort and correlate
results after manual upload.

---

## VirusTotal API key

Sign up at <https://www.virustotal.com> for a free API key (4 requests/minute,
500 requests/day). Set it as an environment variable or pass it via `--api-key`:

```bash
export VT_API_KEY=your_key_here
```

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
