# terrain

**macOS system inventory and security audit tool.**

Terrain scans your Mac, saves a timestamped snapshot of everything installed, and flags security issues - leaked secrets
in dotfiles, dangerous file permissions, unmanaged binaries.
Run it again later and `terrain diff` shows exactly what changed.

```
$ terrain scan
✓ Scan complete (snapshot #3)
  Items found: 412
  Audit flags: [!] 2 critical  [~] 5 warnings  [i] 3 info

$ terrain diff
[+] Added (2)      [-] Removed (1)      [~] Updated (8)
```

---

## Features

- **Full inventory** - Homebrew formulae and casks, pip, npm, cargo, gem, Mac App Store, pyenv/nvm/jenv/mise language
  versions, launchd agents/daemons, shell configs, SSH keys, PATH binaries
- **AI tool auditing** - Scans Claude Code, Cursor, GitHub Copilot, Continue, Ollama, and OpenAI CLI configs; flags
  embedded secrets
- **Secrets detection** - Finds API keys, tokens, and credentials in dotfiles before they leak
- **Permission auditing** - Flags world-readable private keys, unsafe SSH directory permissions, and world-writable
  paths
- **Snapshot diffing** - Compare any two scans to see added, removed, and updated items
- **Orphan detection** - Identifies binaries installed via curl or direct download outside any package manager
- **Rich terminal output** - Colored tables, panels, and progress indicators
  via [Rich](https://github.com/Textualize/rich)

---

## Installation

**From source (recommended while in development):**

```bash
git clone https://github.com/kulwant/terrain.git
cd terrain
pip install -e .
```

**Requirements:** Python 3.11+, macOS

---

## Development

Install the dev dependencies (includes ruff, mypy, pytest):

```bash
pip install -e ".[dev]"
```

### Make commands

| Command          | What it does                                                      |
|------------------|-------------------------------------------------------------------|
| `make check`     | Run the full suite: install, lint, typecheck, test                |
| `make install`   | Install the package in editable mode with dev dependencies        |
| `make lint`      | Run ruff on `terrain/` and `tests/`                               |
| `make typecheck` | Run mypy on `terrain/`                                            |
| `make test`      | Run pytest                                                        |
| `make clean`     | Remove `__pycache__`, `.egg-info`, `.pytest_cache`, `.mypy_cache` |

Run `make check` before opening a pull request.

---

## Quick start

```bash
# Take a first snapshot
terrain scan

# View a summary of the last snapshot
terrain status

# Run again and see what changed
terrain scan
terrain diff

# Check for security issues
terrain audit
```

---

## Commands

| Command                | Description                                                                  |
|------------------------|------------------------------------------------------------------------------|
| `terrain scan`         | Scan the system and save a snapshot                                          |
| `terrain status`       | Show a summary of the latest snapshot                                        |
| `terrain list`         | List all items (supports `--type` and `--source` filters)                    |
| `terrain show <name>`  | Show full details for a specific item                                        |
| `terrain diff`         | Compare the two most recent snapshots                                        |
| `terrain audit`        | Show all security and configuration flags                                    |
| `terrain bins`         | List all binaries found in PATH; use `--orphans-only` for unmanaged installs |
| `terrain ai`           | Show all detected AI tool configurations                                     |
| `terrain where <name>` | Find where a tool lives across all items                                     |
| `terrain version`      | Show the installed version                                                   |

### Filtering `list`

```bash
terrain list --type package        # Only packages
terrain list --source brew         # Only Homebrew formulae
terrain list --source pip          # Only pip packages
terrain list --type binary         # Only PATH binaries
```

---

## What gets scanned

| Source                            | Items collected                                            |
|-----------------------------------|------------------------------------------------------------|
| `brew`                            | Formulae with versions, tap info, install paths            |
| `brew_cask`                       | Casks with app locations                                   |
| `pip`                             | User-installed packages                                    |
| `npm`                             | Global npm packages                                        |
| `cargo`                           | Installed Rust crates                                      |
| `gem`                             | Ruby gems                                                  |
| `mas`                             | Mac App Store apps                                         |
| `pyenv` / `nvm` / `jenv` / `mise` | Language version managers and installed versions           |
| `launchd`                         | Launch agents and daemons (user + system)                  |
| `shell`                           | `.zshrc`, `.bashrc`, `.zprofile`, and related configs      |
| `ssh`                             | SSH keys, config, and known hosts                          |
| `bins`                            | All executables found in `$PATH` directories               |
| `ai_configs`                      | Claude Code, Cursor, Copilot, Continue, Ollama, OpenAI CLI |

---

## Audit flags

Terrain categorizes findings into three severities:

| Level        | Icon  | Examples                                                            |
|--------------|-------|---------------------------------------------------------------------|
| **Critical** | `[!]` | API key or token found in a config file, world-readable private key |
| **Warning**  | `[~]` | SSH key with incorrect permissions, world-writable PATH directory   |
| **Info**     | `[i]` | Ollama server is running, informational notes                       |

Secrets are detected by pattern matching against common formats: OpenAI, Anthropic, GitHub, and AWS keys, plus generic
`api_key=`, `token=`, and `password=` assignments.

---

## Data storage

Snapshots are stored in `~/.terrain/terrain.db` (SQLite).
Each snapshot is a single row containing the full serialized item list.
No data leaves your machine.

---

## Architecture

```
terrain/
├── cli.py              # Typer CLI commands
├── models.py           # Pydantic models: Item, Snapshot, AuditFlag
├── scanner.py          # Orchestrates all scanners
├── store.py            # SQLite persistence
├── scanners/           # One file per scanner (brew, pip, npm, ...)
│   └── base.py         # BaseScanner with safe subprocess helpers
├── reporters/          # Rich output renderers (overview, diff, audit, detail)
└── audit/              # Security utilities (secrets, permissions)
```

Scanners are independent and fail gracefully - if `brew` is not installed, the Homebrew scanner returns an empty list
and the rest of the scan continues.
Use `terrain scan --verbose` to surface scanner errors during development.

---

## Contributing

1. Fork the repo and create a feature branch.
2. Install in editable mode: `pip install -e .`
3. Add a scanner in `terrain/scanners/`, inheriting from `BaseScanner`.
4. Add it to `_PRIMARY_SCANNERS` in `terrain/scanner.py`.
5. Open a pull request with a description of what the scanner collects and why it is useful.

---

## License

MIT
