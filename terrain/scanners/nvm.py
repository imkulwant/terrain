import re
from pathlib import Path

from terrain.models import Item, ItemType
from terrain.scanners.base import BaseScanner


class NvmScanner(BaseScanner):
    name = "nvm"

    def scan(self) -> list[Item]:
        nvm_dir = Path.home() / ".nvm"
        if not nvm_dir.exists():
            return []

        nvm_sh = nvm_dir / "nvm.sh"
        if not nvm_sh.exists():
            return []

        # Get all versions
        out, rc = self._run_shell(
            f"source {nvm_sh} 2>/dev/null && nvm ls --no-alias 2>/dev/null",
            timeout=15,
        )
        if rc != 0 or not out:
            return []

        # Get current version
        current_out, _ = self._run_shell(
            f"source {nvm_sh} 2>/dev/null && nvm current 2>/dev/null",
            timeout=10,
        )
        current_version = current_out.strip() if current_out else None

        items: list[Item] = []
        for line in out.splitlines():
            # Strip ANSI escape codes and control chars
            line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
            if not line:
                continue

            # Lines like: "->     v18.17.0         (default)"
            # Or: "        v20.0.0"
            is_active = line.startswith("->") or line.startswith("*")
            line_clean = line.lstrip("->* ").strip()

            # Extract version
            version_match = re.match(r"v?([\d.]+)", line_clean)
            if not version_match:
                continue
            version = version_match.group(1)
            full_version = f"v{version}"

            location = str(nvm_dir / "versions" / "node" / full_version / "bin" / "node")
            locations = [location] if Path(location).exists() else []

            metadata = {
                "is_active": is_active or (full_version == current_version),
                "current_version": current_version or "",
            }

            items.append(
                Item(
                    name=f"node-{version}",
                    version=version,
                    item_type=ItemType.language_version,
                    source="nvm",
                    locations=locations,
                    metadata=metadata,
                )
            )

        return items
