import json

from terrain.models import Item, ItemType
from terrain.scanners.base import BaseScanner


class PipScanner(BaseScanner):
    name = "pip"

    def scan(self) -> list[Item]:
        items: list[Item] = []
        items.extend(self._scan_pip3())
        items.extend(self._scan_pipx())
        return items

    def _scan_pip3(self) -> list[Item]:
        pip = self._which("pip3") or self._which("pip")
        if not pip:
            return []

        out, rc = self._run([pip, "list", "--format=json"])
        if rc != 0 or not out:
            return []

        try:
            packages = json.loads(out)
        except json.JSONDecodeError:
            return []

        items: list[Item] = []
        for pkg in packages:
            name = pkg.get("name", "")
            version = pkg.get("version")
            if not name:
                continue

            # get location via pip show
            show_out, show_rc = self._run([pip, "show", name])
            location = ""
            if show_rc == 0 and show_out:
                for line in show_out.splitlines():
                    if line.startswith("Location:"):
                        location = line.split(":", 1)[1].strip()
                        break

            items.append(
                Item(
                    name=name,
                    version=version,
                    item_type=ItemType.package,
                    source="pip3",
                    locations=[location] if location else [],
                )
            )

        return items

    def _scan_pipx(self) -> list[Item]:
        pipx = self._which("pipx")
        if not pipx:
            return []

        out, rc = self._run([pipx, "list", "--json"])
        if rc != 0 or not out:
            return []

        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []

        items: list[Item] = []
        venvs = data.get("venvs", {})
        for pkg_name, pkg_info in venvs.items():
            metadata = pkg_info.get("metadata", {})
            version = None
            main_pkg = metadata.get("main_package", {})
            if main_pkg:
                version = main_pkg.get("package_version")

            # gather binary locations
            locations: list[str] = []
            apps = main_pkg.get("apps", [])
            for app in apps:
                if isinstance(app, str):
                    locations.append(app)

            items.append(
                Item(
                    name=pkg_name,
                    version=version,
                    item_type=ItemType.package,
                    source="pipx",
                    locations=locations,
                    metadata={"pipx_venv": str(metadata.get("venv", ""))},
                )
            )

        return items
