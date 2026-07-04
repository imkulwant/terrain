import re
from pathlib import Path

from terrain.models import AuditFlag, AuditSeverity

# Canonical list of secret patterns used across the codebase.
# Order matters: specific patterns (provider keys) come before generic ones.
SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"sk-[A-Za-z0-9]{48}", "OpenAI API Key"),
    (r"sk-ant-[A-Za-z0-9\-_]{80,}", "Anthropic API Key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Token"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', "API Key"),
    (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', "Secret Key"),
    (r'(?i)(token|access[_-]?token)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})', "Token"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?(\S{8,})', "Password"),
]


def scan_file(path: Path) -> list[AuditFlag]:
    """Scan a single file for secrets. Returns audit flags (no actual values logged)."""
    flags: list[AuditFlag] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError):
        return flags

    lines = text.splitlines()
    for line_num, line in enumerate(lines, 1):
        for pattern, label in SECRET_PATTERNS:
            if re.search(pattern, line):
                flags.append(
                    AuditFlag(
                        severity=AuditSeverity.critical,
                        message=f"Possible {label} on line {line_num}",
                        location=str(path),
                    )
                )
                break  # one flag per line

    return flags


def scan_files(paths: list[str]) -> list[AuditFlag]:
    """Scan a list of file paths for secrets."""
    flags: list[AuditFlag] = []
    for path_str in paths:
        p = Path(path_str)
        if p.exists() and p.is_file():
            flags.extend(scan_file(p))
    return flags


def scan_common_dotfiles() -> list[AuditFlag]:
    """Scan common dotfiles that aren't covered by other scanners."""
    common = [
        "~/.env",
        "~/.envrc",
        "~/.bash_history",
        "~/.zsh_history",
        "~/.netrc",
        "~/.npmrc",
        "~/.pypirc",
        "~/.aws/credentials",
        "~/.aws/config",
        "~/.config/gcloud/application_default_credentials.json",
    ]
    flags: list[AuditFlag] = []
    for path_str in common:
        p = Path(path_str).expanduser()
        if p.exists() and p.is_file():
            flags.extend(scan_file(p))
    return flags
