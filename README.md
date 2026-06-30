# OmniScan Scanner

All-in-one vulnerability assessment scanner with CVE lookup, reporting, and standalone Linux build.

## Project Structure

```
├── cli.py                  # Main CLI interface
├── install.sh              # Environment setup
├── omni_vapt/              # Core Python package
├── scripts/                # Build and tool installation
├── pyproject.toml          # Package config and entry points
├── requirements.txt        # Python dependencies
├── requirements-build.txt  # Build dependencies
└── README.md               # This file
```

## Installation

### Prerequisites

- OS: Debian / Ubuntu / Parrot (x86_64)
- Privileges: `sudo` access
- Disk: >= 6 GB free
- Network: outbound HTTPS (NVD/CIRCL lookups)

### Quick Setup

```bash
# Install system tools
./scripts/tools_install.sh

# Create Python environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies and register CLI
python -m pip install -r requirements.txt
python -m pip install -e .
```

## Usage

### Vulnerability Scan

Scan a target IP, hostname, or URL:

```bash
omni-vapt scan 127.0.0.1
omni-vapt scan 192.168.1.100 --html --db --verify
omni-vapt scan https://example.com --html --db --verify
```

Alternative (without installing the package):

```bash
python cli.py scan 127.0.0.1 --html --db --verify
```

### CVE Database

```bash
omni-vapt cve stats
omni-vapt cve search nginx 1.18.0
```

### Options

| Flag | Purpose |
|------|---------|
| `scan <target>` | Run vulnerability scan on URL or IP |
| `--html` | Generate HTML report |
| `--json` | Generate JSON report |
| `--odf` | Generate ODF (OpenDocument) report |
| `--db` | Save findings to SQLite database |
| `--verify` | Run exploit verification checks |
| `--exploit-search` | Query ExploitDB via searchsploit |
| `cve stats` | Show CVE database statistics |
| `cve search <product> [version]` | Search CVEs by product |
| `--cve-db PATH` | Custom CVE database path |

## Outputs

- `vapt_vault.db` — scan findings
- `cve_database.db` — CVE cache
- `omni_vapt_report_YYYYMMDD_HHMMSS.html` — HTML report

## Build Standalone Linux Binary

```bash
./scripts/build_linux.sh
```

Output: `dist/linux/omni_scan`
