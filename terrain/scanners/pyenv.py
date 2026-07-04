from pathlib import Path

from terrain.models import Item, ItemType
from terrain.scanners.base import BaseScanner


class PyenvScanner(BaseScanner):
    name = "pyenv"

    def scan(self) -> list[Item]:
        pyenv_root = Path.home() / ".pyenv"
        pyenv_bin = self._which("pyenv")

        if not pyenv_bin and not pyenv_root.exists():
            return []

        out, rc = self._run(["pyenv", "versions", "--bare"])
        if rc != 0 or not out:
            return []

        current_out, _ = self._run(["pyenv", "version-name"])
        current_version = current_out.strip() if current_out else None

        items: list[Item] = []
        for version in out.splitlines():
            version = version.strip()
            if not version:
                continue

            is_active = version == current_version

            # Get binary location
            location_out, loc_rc = self._run(
                ["pyenv", "which", "python"],
                env={**__import__("os").environ, "PYENV_VERSION": version},
            )
            locations: list[str] = []
            if loc_rc == 0 and location_out:
                locations.append(location_out.strip())

            items.append(
                Item(
                    name=f"python-{version}",
                    version=version,
                    item_type=ItemType.language_version,
                    source="pyenv",
                    locations=locations,
                    metadata={
                        "is_active": is_active,
                        "global_version": current_version or "",
                    },
                )
            )

        return items
