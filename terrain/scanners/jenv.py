import os
from pathlib import Path

from terrain.models import Item, ItemType
from terrain.scanners.base import BaseScanner


class JenvScanner(BaseScanner):
    name = "jenv"

    def scan(self) -> list[Item]:
        jenv_root = Path.home() / ".jenv"
        jenv_bin = self._which("jenv")

        if not jenv_bin and not jenv_root.exists():
            return []

        out, rc = self._run(["jenv", "versions"])
        if rc != 0 or not out:
            return []

        current_out, _ = self._run(["jenv", "version"])
        current_version = current_out.strip().split()[0] if current_out else None

        java_home = os.environ.get("JAVA_HOME", "")

        items: list[Item] = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue

            # Lines look like "  1.8" or "* 11.0.2 (set by...)"
            is_active = line.startswith("*")
            version = line.lstrip("* ").split()[0] if line else None
            if not version or version == "system":
                continue

            location_out, loc_rc = self._run(["jenv", "which", "java"])
            locations: list[str] = []
            if loc_rc == 0 and location_out:
                locations.append(location_out.strip())

            metadata = {
                "is_active": is_active,
                "current_version": current_version or "",
            }
            if java_home:
                metadata["JAVA_HOME"] = java_home

            items.append(
                Item(
                    name=f"java-{version}",
                    version=version,
                    item_type=ItemType.language_version,
                    source="jenv",
                    locations=locations,
                    metadata=metadata,
                )
            )

        return items
