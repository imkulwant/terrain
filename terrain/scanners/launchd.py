import plistlib
from pathlib import Path

from terrain.models import AuditFlag, AuditSeverity, Item, ItemType
from terrain.scanners.base import BaseScanner

SCAN_LOCATIONS = [
    (Path.home() / "Library" / "LaunchAgents", ItemType.launch_agent, "launchd_user"),
    (Path("/Library/LaunchAgents"), ItemType.launch_agent, "launchd_system"),
    (Path("/Library/LaunchDaemons"), ItemType.launch_daemon, "launchd_daemon"),
]


class LaunchdScanner(BaseScanner):
    name = "launchd"

    def scan(self) -> list[Item]:
        items: list[Item] = []

        for scan_dir, item_type, source in SCAN_LOCATIONS:
            if not scan_dir.exists():
                continue

            try:
                plist_files = list(scan_dir.glob("*.plist"))
            except PermissionError:
                continue

            for plist_path in plist_files:
                try:
                    item = self._parse_plist(plist_path, item_type, source)
                    if item:
                        items.append(item)
                except Exception:
                    continue

        return items

    def _parse_plist(
        self, plist_path: Path, item_type: ItemType, source: str
    ) -> Item | None:
        try:
            with open(plist_path, "rb") as f:
                data = plistlib.load(f)
        except (plistlib.InvalidFileException, OSError, PermissionError):
            try:
                # Try reading as text (XML plist)
                text = plist_path.read_text(errors="replace")
                data = plistlib.loads(text.encode())
            except Exception:
                return None

        label = data.get("Label", plist_path.stem)
        program_args = data.get("ProgramArguments", [])
        program = data.get("Program", "")

        if not program and program_args:
            program = program_args[0] if program_args else ""

        run_at_load = data.get("RunAtLoad", False)
        start_interval = data.get("StartInterval")
        keep_alive = data.get("KeepAlive", False)
        start_calendar = data.get("StartCalendarInterval")
        has_sockets = "Sockets" in data or "QueueDirectories" in data

        metadata = {
            "label": label,
            "program_arguments": program_args,
            "program": program,
            "run_at_load": run_at_load,
            "keep_alive": keep_alive,
            "has_network": has_sockets,
        }
        if start_interval is not None:
            metadata["start_interval_seconds"] = start_interval
        if start_calendar:
            metadata["start_calendar_interval"] = str(start_calendar)

        audit_flags: list[AuditFlag] = []

        # Check if binary exists
        if program and not Path(program).exists():
            audit_flags.append(
                AuditFlag(
                    severity=AuditSeverity.warning,
                    message=f"Program does not exist: {program}",
                    location=str(plist_path),
                )
            )

        # Unknown source heuristic: label doesn't match known prefixes
        known_prefixes = (
            "com.apple.", "com.google.", "com.microsoft.", "com.adobe.",
            "com.dropbox.", "com.spotify.", "com.zoom.", "com.github.",
            "homebrew.", "io.brew.", "com.brew.",
        )
        if source == "launchd_daemon" and not any(label.startswith(p) for p in known_prefixes):
            audit_flags.append(
                AuditFlag(
                    severity=AuditSeverity.info,
                    message=f"Daemon from unknown source (label: {label})",
                    location=str(plist_path),
                )
            )

        return Item(
            name=label,
            item_type=item_type,
            source=source,
            locations=[str(plist_path)],
            config_paths=[str(plist_path)],
            metadata=metadata,
            audit_flags=audit_flags,
        )
