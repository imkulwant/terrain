import hashlib
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from terrain.models import AuditFlag, AuditSeverity, Item, ItemType
from terrain.scanners.base import BaseScanner

SCAN_DIRS = [
    "/usr/local/bin",
    "/opt/homebrew/bin",
    str(Path.home() / ".local" / "bin"),
    str(Path.home() / "bin"),
    str(Path.home() / ".cargo" / "bin"),
    str(Path.home() / ".npm-global" / "bin"),
    "/usr/bin",
    "/usr/sbin",
]

SYSTEM_DIRS = {"/usr/bin", "/usr/sbin"}


class BinsScanner(BaseScanner):
    name = "bins"

    def __init__(self) -> None:
        self._known_items: list[Item] = []

    def set_known_items(self, items: list[Item]) -> None:
        self._known_items = items

    def scan(self) -> list[Item]:
        items: list[Item] = []
        brew_prefix_out, _ = self._run(["brew", "--prefix"])
        brew_prefix = brew_prefix_out.strip() if brew_prefix_out else "/opt/homebrew"
        brew_cellar = f"{brew_prefix}/Cellar"
        brew_opt = f"{brew_prefix}/opt"

        cargo_bin = str(Path.home() / ".cargo" / "bin")
        pipx_base = str(Path.home() / ".local" / "share" / "pipx")
        npm_prefix_out, _ = self._run(["npm", "config", "get", "prefix"])
        npm_prefix = npm_prefix_out.strip() if npm_prefix_out else ""

        current_user = os.getlogin() if hasattr(os, "getlogin") else os.environ.get("USER", "")

        for dir_path in SCAN_DIRS:
            d = Path(dir_path)
            if not d.exists():
                continue

            try:
                entries = list(d.iterdir())
            except PermissionError:
                continue

            for entry in entries:
                if not entry.is_file() and not entry.is_symlink():
                    continue

                try:
                    real_path = entry.resolve()
                    is_symlink = entry.is_symlink()
                    symlink_target = str(os.readlink(entry)) if is_symlink else None

                    # Determine permissions
                    stat_out, _ = self._run(
                        ["stat", "-f", "%Sp %Su %Sg", str(entry)]
                    )
                    perms = stat_out.strip() if stat_out else ""

                    # Determine modification date
                    try:
                        mtime = datetime.fromtimestamp(entry.stat().st_mtime)
                    except OSError:
                        mtime = None

                    # Detect source
                    source = self._detect_source(
                        entry, real_path, brew_cellar, brew_opt,
                        cargo_bin, pipx_base, npm_prefix, dir_path,
                    )

                    # Get version for direct installs
                    version: str | None = None
                    file_type = ""
                    file_hash = ""
                    metadata: dict[str, Any] = {}

                    if source == "direct_install":
                        version = self._get_version(entry)
                        file_type = self._get_file_type(entry)
                        file_hash = self._compute_hash(entry)
                        metadata["file_type"] = file_type
                        metadata["sha256"] = file_hash

                    if symlink_target:
                        metadata["symlink_target"] = symlink_target
                    if mtime:
                        metadata["modified"] = mtime.isoformat()

                    audit_flags: list[AuditFlag] = []
                    is_system = dir_path in SYSTEM_DIRS

                    if not is_system:
                        # Check ownership
                        if perms:
                            parts = perms.split()
                            owner = parts[1] if len(parts) > 1 else ""
                            perm_str = parts[0] if parts else ""

                            if owner not in ("root", current_user) and owner:
                                audit_flags.append(
                                    AuditFlag(
                                        severity=AuditSeverity.warning,
                                        message=f"Binary owned by unexpected user '{owner}'",
                                        location=str(entry),
                                    )
                                )

                            # World-writable check (last 'w' in others section)
                            if len(perm_str) >= 10 and perm_str[8] == "w":
                                audit_flags.append(
                                    AuditFlag(
                                        severity=AuditSeverity.warning,
                                        message="Binary is world-writable",
                                        location=str(entry),
                                    )
                                )

                        if source == "direct_install":
                            audit_flags.append(
                                AuditFlag(
                                    severity=AuditSeverity.info,
                                    message="Direct install (curl/manual) - review origin",
                                    location=str(entry),
                                )
                            )

                    items.append(
                        Item(
                            name=entry.name,
                            version=version,
                            item_type=ItemType.binary,
                            source=source,
                            installed_at=mtime,
                            locations=[str(entry)],
                            permissions={str(entry): perms} if perms else {},
                            metadata=metadata,
                            audit_flags=audit_flags,
                        )
                    )

                except (PermissionError, OSError):
                    continue

        return items

    def _detect_source(
        self,
        entry: Path,
        real_path: Path,
        brew_cellar: str,
        brew_opt: str,
        cargo_bin: str,
        pipx_base: str,
        npm_prefix: str,
        dir_path: str,
    ) -> str:
        real_str = str(real_path)

        if brew_cellar and real_str.startswith(brew_cellar):
            return "brew_formula"
        if brew_opt and real_str.startswith(brew_opt):
            return "brew_formula"
        if dir_path == cargo_bin or real_str.startswith(cargo_bin):
            return "cargo"
        if pipx_base and real_str.startswith(pipx_base):
            return "pipx"
        if npm_prefix and real_str.startswith(npm_prefix):
            return "npm_global"
        if dir_path in SYSTEM_DIRS:
            return "system"

        # Check pkgutil
        pkgutil_out, pkgutil_rc = self._run(["pkgutil", "--file-info", str(entry)])
        if pkgutil_rc == 0 and pkgutil_out:
            return "system"

        return "direct_install"

    def _get_version(self, entry: Path) -> str | None:
        for flag in ("--version", "version", "-v", "-V"):
            try:
                result = subprocess.run(
                    [str(entry), flag],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                output = (result.stdout + result.stderr).strip()
                # Try to find a version pattern
                match = re.search(r"[\d]+\.[\d]+(?:\.[\d]+)?", output)
                if match:
                    return match.group(0)
            except Exception:
                pass
        return None

    def _get_file_type(self, entry: Path) -> str:
        out, _ = self._run(["file", str(entry)])
        return out.strip() if out else ""

    def _compute_hash(self, entry: Path) -> str:
        try:
            h = hashlib.sha256()
            with open(entry, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()[:16]
        except (PermissionError, OSError):
            return ""
