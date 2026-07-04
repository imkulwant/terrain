import re
from pathlib import Path

from terrain.models import Item, ItemType
from terrain.scanners.base import BaseScanner


class CargoScanner(BaseScanner):
    name = "cargo"

    def scan(self) -> list[Item]:
        cargo = self._which("cargo")
        if not cargo:
            return []

        out, rc = self._run(["cargo", "install", "--list"])
        if rc != 0 or not out:
            return []

        cargo_bin = str(Path.home() / ".cargo" / "bin")
        items: list[Item] = []

        # Format:
        # pkg v1.2.3:
        #     binary-name
        #     other-binary
        current_name: str | None = None
        current_version: str | None = None
        current_bins: list[str] = []

        for line in out.splitlines():
            # Package header line: "name v1.2.3 (optional url):"
            header_match = re.match(r"^(\S+)\s+v([\d.\w-]+)", line)
            if header_match and line.rstrip().endswith(":"):
                # Save previous
                if current_name:
                    items.append(
                        Item(
                            name=current_name,
                            version=current_version,
                            item_type=ItemType.package,
                            source="cargo",
                            locations=[f"{cargo_bin}/{b}" for b in current_bins],
                            metadata={"binaries": current_bins},
                        )
                    )
                current_name = header_match.group(1)
                current_version = header_match.group(2)
                current_bins = []
            elif line.startswith("    ") and current_name:
                # Binary name line
                bin_name = line.strip()
                if bin_name:
                    current_bins.append(bin_name)

        # Save last
        if current_name:
            items.append(
                Item(
                    name=current_name,
                    version=current_version,
                    item_type=ItemType.package,
                    source="cargo",
                    locations=[f"{cargo_bin}/{b}" for b in current_bins],
                    metadata={"binaries": current_bins},
                )
            )

        return items
