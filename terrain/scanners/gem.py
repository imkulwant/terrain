import re

from terrain.models import Item, ItemType
from terrain.scanners.base import BaseScanner


class GemScanner(BaseScanner):
    name = "gem"

    def scan(self) -> list[Item]:
        gem = self._which("gem")
        if not gem:
            return []

        out, rc = self._run(["gem", "list", "--no-verbose"])
        if rc != 0 or not out:
            return []

        items: list[Item] = []
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("***"):
                continue

            # Format: "name (version1, version2)"
            match = re.match(r"^(\S+)\s+\(([^)]+)\)$", line)
            if match:
                name = match.group(1)
                versions_str = match.group(2)
                # Take the first (latest) version
                version = versions_str.split(",")[0].strip()
                # Remove any default suffix
                version = version.replace("default: ", "").strip()
                items.append(
                    Item(
                        name=name,
                        version=version,
                        item_type=ItemType.package,
                        source="gem",
                    )
                )
            else:
                # Just a name, no version info
                name = line.split()[0] if line.split() else line
                if name:
                    items.append(
                        Item(
                            name=name,
                            item_type=ItemType.package,
                            source="gem",
                        )
                    )

        return items
