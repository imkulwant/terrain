import re
from pathlib import Path

from terrain.models import Item, ItemType
from terrain.scanners.base import BaseScanner


class MasScanner(BaseScanner):
    name = "mas"

    def scan(self) -> list[Item]:
        mas = self._which("mas")
        if not mas:
            return []

        out, rc = self._run(["mas", "list"])
        if rc != 0 or not out:
            return []

        items: list[Item] = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue

            # Format: "id name (version)"
            match = re.match(r"^(\d+)\s+(.+?)\s+\(([^)]+)\)\s*$", line)
            if match:
                app_id = match.group(1)
                name = match.group(2).strip()
                version = match.group(3).strip()

                # Try to find app location
                app_path = f"/Applications/{name}.app"
                locations = [app_path] if Path(app_path).exists() else []

                items.append(
                    Item(
                        name=name,
                        version=version,
                        item_type=ItemType.app_store,
                        source="mas",
                        locations=locations,
                        metadata={"app_store_id": app_id},
                    )
                )

        return items
