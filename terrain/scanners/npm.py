import json

from terrain.models import Item, ItemType
from terrain.scanners.base import BaseScanner


class NpmScanner(BaseScanner):
    name = "npm"

    def scan(self) -> list[Item]:
        items: list[Item] = []
        items.extend(self._scan_npm())
        items.extend(self._scan_pnpm())
        items.extend(self._scan_yarn())
        return items

    def _scan_npm(self) -> list[Item]:
        npm = self._which("npm")
        if not npm:
            return []

        out, rc = self._run(["npm", "list", "-g", "--depth=0", "--json"])
        if rc not in (0, 1) or not out:
            return []

        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []

        items: list[Item] = []
        deps = data.get("dependencies", {})
        prefix = data.get("path", "")

        for pkg_name, pkg_info in deps.items():
            version = pkg_info.get("version") if isinstance(pkg_info, dict) else None
            location = f"{prefix}/node_modules/{pkg_name}" if prefix else ""
            items.append(
                Item(
                    name=pkg_name,
                    version=version,
                    item_type=ItemType.package,
                    source="npm_global",
                    locations=[location] if location else [],
                    metadata={"npm_prefix": prefix},
                )
            )

        return items

    def _scan_pnpm(self) -> list[Item]:
        pnpm = self._which("pnpm")
        if not pnpm:
            return []

        out, rc = self._run(["pnpm", "list", "-g", "--json"])
        if rc not in (0, 1) or not out:
            return []

        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []

        items: list[Item] = []
        # pnpm returns a list
        if isinstance(data, list) and data:
            deps = data[0].get("dependencies", {}) if isinstance(data[0], dict) else {}
        elif isinstance(data, dict):
            deps = data.get("dependencies", {})
        else:
            deps = {}

        for pkg_name, pkg_info in deps.items():
            version = pkg_info.get("version") if isinstance(pkg_info, dict) else None
            items.append(
                Item(
                    name=pkg_name,
                    version=version,
                    item_type=ItemType.package,
                    source="pnpm_global",
                )
            )

        return items

    def _scan_yarn(self) -> list[Item]:
        yarn = self._which("yarn")
        if not yarn:
            return []

        out, rc = self._run(["yarn", "global", "list", "--json"])
        if rc not in (0, 1) or not out:
            return []

        items: list[Item] = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if entry.get("type") == "info":
                    # yarn outputs something like: {"type":"info","data":"<pkg>@<version>"}
                    data_str = entry.get("data", "")
                    if "@" in data_str:
                        parts = data_str.rsplit("@", 1)
                        pkg_name = parts[0].strip('"')
                        version = parts[1].strip('"') if len(parts) > 1 else None
                        items.append(
                            Item(
                                name=pkg_name,
                                version=version,
                                item_type=ItemType.package,
                                source="yarn_global",
                            )
                        )
            except json.JSONDecodeError:
                continue

        return items
