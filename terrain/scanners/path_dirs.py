import os
from pathlib import Path

from terrain.models import AuditFlag, AuditSeverity, Item, ItemType
from terrain.scanners.base import BaseScanner


class PathDirsScanner(BaseScanner):
    name = "path_dirs"

    def scan(self) -> list[Item]:
        path_env = os.environ.get("PATH", "")
        if not path_env:
            return []

        entries = [e.strip() for e in path_env.split(":") if e.strip()]
        if not entries:
            return []

        audit_flags: list[AuditFlag] = []
        metadata: dict = {
            "path_entries": entries,
            "entry_count": len(entries),
        }

        dir_details: list[dict] = []
        for entry in entries:
            d = Path(entry)
            detail: dict = {"path": entry, "exists": d.exists()}

            if not d.exists():
                audit_flags.append(
                    AuditFlag(
                        severity=AuditSeverity.info,
                        message=f"PATH entry does not exist: {entry}",
                        location=entry,
                    )
                )
                dir_details.append(detail)
                continue

            # Count binaries
            try:
                bin_count = sum(1 for f in d.iterdir() if f.is_file())
            except PermissionError:
                bin_count = -1

            detail["binary_count"] = bin_count

            # Check if writable by user
            writable = os.access(entry, os.W_OK)
            detail["user_writable"] = writable

            if writable:
                # Check if it's not a user-owned dir (suspicious if system dir is writable)
                try:
                    stat = d.stat()
                    is_system_dir = entry.startswith("/usr/") or entry.startswith("/bin") or entry.startswith("/sbin")
                    if is_system_dir:
                        audit_flags.append(
                            AuditFlag(
                                severity=AuditSeverity.critical,
                                message=f"System PATH entry is user-writable: {entry}",
                                location=entry,
                            )
                        )
                    else:
                        # Check world-writable (others write bit)
                        if stat.st_mode & 0o002:
                            audit_flags.append(
                                AuditFlag(
                                    severity=AuditSeverity.warning,
                                    message=f"PATH entry is world-writable: {entry}",
                                    location=entry,
                                )
                            )
                except OSError:
                    pass

            dir_details.append(detail)

        metadata["directories"] = dir_details

        return [
            Item(
                name="PATH",
                item_type=ItemType.shell_config,
                source="path_dirs",
                metadata=metadata,
                audit_flags=audit_flags,
            )
        ]
