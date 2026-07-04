import json

from terrain.models import AuditFlag, AuditSeverity, Item, ItemType
from terrain.scanners.base import BaseScanner


class BrewScanner(BaseScanner):
    name = "brew"

    def scan(self) -> list[Item]:
        brew = self._which("brew")
        if not brew:
            return []

        prefix_out, _ = self._run(["brew", "--prefix"])
        brew_prefix = prefix_out.strip() if prefix_out else "/opt/homebrew"

        items: list[Item] = []
        items.extend(self._scan_formulae(brew_prefix))
        items.extend(self._scan_casks(brew_prefix))
        return items

    def _scan_formulae(self, brew_prefix: str) -> list[Item]:
        out, rc = self._run(["brew", "list", "--formula", "-1"])
        if rc != 0 or not out:
            return []

        formulae = [f.strip() for f in out.splitlines() if f.strip()]
        items: list[Item] = []

        # get tap info once
        tap_out, _ = self._run(["brew", "tap"])
        taps = [t.strip() for t in tap_out.splitlines() if t.strip()] if tap_out else []

        for formula in formulae:
            info_out, info_rc = self._run(["brew", "info", "--json=v2", formula])
            version = None
            metadata: dict = {"taps": taps}
            locations: list[str] = []

            if info_rc == 0 and info_out:
                try:
                    info = json.loads(info_out)
                    formulae_info = info.get("formulae", [])
                    if formulae_info:
                        f = formulae_info[0]
                        installed = f.get("installed", [])
                        if installed:
                            version = installed[0].get("version")
                        metadata["on_request"] = f.get("installed_on_request", False)
                        metadata["desc"] = f.get("desc", "")
                        metadata["homepage"] = f.get("homepage", "")
                        opt_path = f"{brew_prefix}/opt/{formula}/bin"
                        locations.append(opt_path)
                except (json.JSONDecodeError, KeyError):
                    pass

            items.append(
                Item(
                    name=formula,
                    version=version,
                    item_type=ItemType.package,
                    source="brew_formula",
                    locations=locations,
                    metadata=metadata,
                )
            )

        return items

    def _scan_casks(self, brew_prefix: str) -> list[Item]:
        out, rc = self._run(["brew", "list", "--cask", "-1"])
        if rc != 0 or not out:
            return []

        casks = [c.strip() for c in out.splitlines() if c.strip()]
        items: list[Item] = []

        for cask in casks:
            info_out, info_rc = self._run(["brew", "info", "--json=v2", "--cask", cask])
            version = None
            metadata: dict = {}
            locations: list[str] = []

            if info_rc == 0 and info_out:
                try:
                    info = json.loads(info_out)
                    casks_info = info.get("casks", [])
                    if casks_info:
                        c_info = casks_info[0]
                        version = c_info.get("version")
                        metadata["desc"] = c_info.get("desc", "")
                        metadata["homepage"] = c_info.get("homepage", "")
                        # App locations
                        artifacts = c_info.get("artifacts", [])
                        for artifact in artifacts:
                            if isinstance(artifact, dict) and "app" in artifact:
                                for app in artifact["app"]:
                                    if isinstance(app, str):
                                        locations.append(f"/Applications/{app}")
                except (json.JSONDecodeError, KeyError):
                    pass

            items.append(
                Item(
                    name=cask,
                    version=version,
                    item_type=ItemType.cask,
                    source="brew_cask",
                    locations=locations,
                    metadata=metadata,
                )
            )

        return items
