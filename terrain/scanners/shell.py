import re
from pathlib import Path
from typing import Any

from terrain.models import AuditFlag, AuditSeverity, Item, ItemType
from terrain.scanners.base import BaseScanner

SHELL_FILES = [
    "~/.zshrc",
    "~/.zprofile",
    "~/.zshenv",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.profile",
    "~/.config/fish/config.fish",
]

# Patterns that look like secrets in shell configs
SECRET_VALUE_PATTERN = re.compile(
    r'export\s+(?:'
    r'(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|ACCESS_KEY|PRIVATE_KEY)'
    r'[A-Z_]*'
    r')\s*=\s*["\']?([A-Za-z0-9/_\-\.]{10,})',
    re.IGNORECASE,
)

PATH_EXPORT_PATTERN = re.compile(r'(?:export\s+)?PATH=(.+)', re.IGNORECASE)
ALIAS_PATTERN = re.compile(r"^alias\s+(\w+)=['\"](.*)['\"]", re.MULTILINE)
EXPORT_PATTERN = re.compile(r"^export\s+([A-Z_][A-Z0-9_]*)=", re.MULTILINE | re.IGNORECASE)
SOURCE_PATTERN = re.compile(r"^(?:source|\\.)\s+(.+)", re.MULTILINE)
FUNCTION_PATTERN = re.compile(r"^(\w+)\s*\(\)\s*\{", re.MULTILINE)
VERSION_MANAGER_PATTERN = re.compile(
    r"(pyenv|nvm|jenv|mise|rbenv|asdf)\s+(?:init|shell|load)",
    re.IGNORECASE,
)

# Interactive shells run on every new tab/subshell; login shells run once at session start.
# PATH exports in interactive configs re-set PATH on every subshell, causing ordering issues.
# They belong in the login-shell counterpart instead.
INTERACTIVE_FILES = {".zshrc": ".zprofile", ".bashrc": ".bash_profile"}

SYSTEM_COMMANDS = {
    "ls", "cat", "grep", "find", "sed", "awk", "git", "python", "python3",
    "node", "npm", "ruby", "java", "go", "curl", "wget", "cp", "mv", "rm",
    "mkdir", "chmod", "chown", "ssh", "scp", "rsync", "tar", "zip", "make",
    "cmake", "brew", "pip", "gem", "cargo",
}


class ShellScanner(BaseScanner):
    name = "shell"

    def scan(self) -> list[Item]:
        items: list[Item] = []

        for shell_file_str in SHELL_FILES:
            shell_path = Path(shell_file_str).expanduser()
            if not shell_path.exists():
                continue

            try:
                text = shell_path.read_text(encoding="utf-8", errors="replace")
            except (PermissionError, OSError):
                continue

            item = self._analyze_shell_file(shell_path, text)
            if item:
                items.append(item)

        return items

    def _analyze_shell_file(self, path: Path, text: str) -> Item:
        audit_flags: list[AuditFlag] = []
        metadata: dict[str, Any] = {}

        # PATH modifications
        path_additions: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            if "PATH=" in stripped or "path=" in stripped.lower():
                # Extract the path entries
                path_parts = re.findall(r"[\$\{]?(?:HOME|home)?[/~][^\s:\"']+", stripped)
                for p in path_parts:
                    expanded = p.replace("$HOME", str(Path.home())).replace("~", str(Path.home()))
                    path_additions.append(expanded)
        if path_additions:
            metadata["path_additions"] = path_additions

        # Flag export PATH= in interactive shell files - these belong in the login-shell counterpart.
        # .zshrc runs on every new tab/subshell, so PATH is rebuilt each time and may get stale or
        # doubled entries. The login file (.zprofile) runs once per session.
        if path.name in INTERACTIVE_FILES:
            login_file = INTERACTIVE_FILES[path.name]
            for line_num, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if re.match(r"export\s+PATH=", stripped):
                    audit_flags.append(
                        AuditFlag(
                            severity=AuditSeverity.info,
                            message=(
                                f"export PATH in {path.name} (line {line_num}): "
                                f"move to ~/{login_file} so it runs once at login, "
                                f"not on every new shell"
                            ),
                            location=str(path),
                        )
                    )

        # Exported env vars (names only, redact values that look like secrets)
        exported_vars: list[str] = []
        secret_exports: list[str] = []
        for match in EXPORT_PATTERN.finditer(text):
            var_name = match.group(1)
            exported_vars.append(var_name)

        # Check for secret-looking exports
        for match in SECRET_VALUE_PATTERN.finditer(text):
            var_name = match.group(0).split("=")[0].replace("export", "").strip()
            secret_exports.append(var_name)
            # Find line number
            line_num = text[: match.start()].count("\n") + 1
            audit_flags.append(
                AuditFlag(
                    severity=AuditSeverity.warning,
                    message=f"Possible secret exported: {var_name} (line {line_num})",
                    location=str(path),
                )
            )

        if exported_vars:
            metadata["exported_vars"] = exported_vars

        # Aliases
        aliases: dict[str, str] = {}
        for match in ALIAS_PATTERN.finditer(text):
            alias_name = match.group(1)
            alias_cmd = match.group(2)
            aliases[alias_name] = alias_cmd

            # Check if alias shadows a system command
            if alias_name in SYSTEM_COMMANDS:
                audit_flags.append(
                    AuditFlag(
                        severity=AuditSeverity.info,
                        message=f"Alias '{alias_name}' shadows system command -> '{alias_cmd}'",
                        location=str(path),
                    )
                )
        if aliases:
            metadata["aliases"] = aliases

        # Functions defined
        functions = FUNCTION_PATTERN.findall(text)
        if functions:
            metadata["functions"] = functions

        # Source calls
        sourced_files: list[str] = []
        for match in SOURCE_PATTERN.finditer(text):
            source_arg = match.group(1).strip().strip('"\'')
            sourced_files.append(source_arg)
            # Check if sourced file exists
            expanded = Path(source_arg).expanduser()
            if not expanded.exists() and not source_arg.startswith("$"):
                audit_flags.append(
                    AuditFlag(
                        severity=AuditSeverity.warning,
                        message=f"Sourced file does not exist: {source_arg}",
                        location=str(path),
                    )
                )
        if sourced_files:
            metadata["sourced_files"] = sourced_files

        # Version manager initializations
        version_managers: list[str] = []
        for match in VERSION_MANAGER_PATTERN.finditer(text):
            vm = match.group(1).lower()
            if vm not in version_managers:
                version_managers.append(vm)
        if version_managers:
            metadata["version_manager_inits"] = version_managers

        # PATH entries that don't exist or are world-writable
        for path_dir_str in path_additions:
            dir_path = Path(path_dir_str)
            if not dir_path.exists():
                audit_flags.append(
                    AuditFlag(
                        severity=AuditSeverity.warning,
                        message=f"PATH entry does not exist: {path_dir_str}",
                        location=str(path),
                    )
                )
            else:
                try:
                    stat = dir_path.stat()
                    # World-writable: others write bit (0o002)
                    if stat.st_mode & 0o002:
                        audit_flags.append(
                            AuditFlag(
                                severity=AuditSeverity.warning,
                                message=f"PATH entry is world-writable: {path_dir_str}",
                                location=str(path),
                            )
                        )
                except OSError:
                    pass

        return Item(
            name=path.name,
            item_type=ItemType.shell_config,
            source="shell",
            config_paths=[str(path)],
            metadata=metadata,
            audit_flags=audit_flags,
        )
