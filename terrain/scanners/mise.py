import json

from terrain.models import Item, ItemType
from terrain.scanners.base import BaseScanner


class MiseScanner(BaseScanner):
    name = "mise"

    def scan(self) -> list[Item]:
        items: list[Item] = []
        items.extend(self._scan_mise())
        items.extend(self._scan_asdf())
        return items

    def _scan_mise(self) -> list[Item]:
        mise = self._which("mise")
        if not mise:
            return []

        out, rc = self._run(["mise", "ls", "--json"])
        if rc != 0 or not out:
            return []

        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []

        items: list[Item] = []
        # mise ls --json returns dict of tool -> list of version info
        for tool_name, versions in data.items():
            if not isinstance(versions, list):
                continue
            for v_info in versions:
                if not isinstance(v_info, dict):
                    continue
                version = v_info.get("version", "")
                is_active = v_info.get("requested_version") is not None or v_info.get("active", False)
                install_path = v_info.get("install_path", "")
                locations = [install_path] if install_path else []

                items.append(
                    Item(
                        name=f"{tool_name}-{version}",
                        version=version,
                        item_type=ItemType.language_version,
                        source="mise",
                        locations=locations,
                        metadata={
                            "tool": tool_name,
                            "is_active": is_active,
                            "source": v_info.get("source", ""),
                        },
                    )
                )

        return items

    def _scan_asdf(self) -> list[Item]:
        mise = self._which("mise")
        if mise:
            # If mise is available, it handles asdf too; skip
            return []

        asdf = self._which("asdf")
        if not asdf:
            return []

        out, rc = self._run(["asdf", "list"])
        if rc != 0 or not out:
            return []

        items: list[Item] = []
        current_tool: str | None = None

        for line in out.splitlines():
            # Tool header: "nodejs"
            # Version line: "  18.17.0"
            if not line.startswith(" ") and not line.startswith("\t"):
                current_tool = line.strip()
            elif current_tool:
                version = line.strip().lstrip("*").strip()
                is_active = line.strip().startswith("*")
                if version:
                    items.append(
                        Item(
                            name=f"{current_tool}-{version}",
                            version=version,
                            item_type=ItemType.language_version,
                            source="asdf",
                            metadata={
                                "tool": current_tool,
                                "is_active": is_active,
                            },
                        )
                    )

        return items
