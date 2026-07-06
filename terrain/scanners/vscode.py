from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from terrain.audit.secrets import SECRET_PATTERNS
from terrain.models import AuditFlag, AuditSeverity, Item, ItemType
from terrain.scanners.base import BaseScanner


def _parse_jsonc(text: str) -> Any:
    """Parse JSONC (JSON with comments and trailing commas)."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return json.loads(text)


def _scan_for_secrets(text: str, location: str) -> list[AuditFlag]:
    flags: list[AuditFlag] = []
    for pattern, label in SECRET_PATTERNS:
        if re.search(pattern, text):
            flags.append(
                AuditFlag(
                    severity=AuditSeverity.critical,
                    message=f"Possible {label} found",
                    location=location,
                )
            )
    return flags


class VscodeScanner(BaseScanner):
    name = "vscode"

    def scan(self) -> list[Item]:
        items: list[Item] = []
        items.extend(self._scan_extensions())
        items.extend(self._scan_user_config())
        return items

    # ------------------------------------------------------------------
    # Extensions
    # ------------------------------------------------------------------

    def _scan_extensions(self) -> list[Item]:
        ext_dir = Path.home() / ".vscode" / "extensions"
        if not ext_dir.exists():
            return []

        # Deduplicate by extension ID: last dir wins (dirs are sorted, so
        # later entries are typically newer versions or platform variants).
        seen: dict[str, Item] = {}
        try:
            entries = sorted(ext_dir.iterdir())
        except PermissionError:
            return []

        for entry in entries:
            if not entry.is_dir():
                continue
            pkg_path = entry / "package.json"
            if not pkg_path.exists():
                continue
            item = self._parse_extension(pkg_path)
            if item:
                seen[item.name] = item  # overwrite older version

        return list(seen.values())

    def _parse_extension(self, pkg_path: Path) -> Item | None:
        try:
            data = json.loads(pkg_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return None

        if not isinstance(data, dict):
            return None

        publisher = data.get("publisher", "")
        name = data.get("name", "")
        if not name:
            return None

        ext_id = f"{publisher.lower()}.{name.lower()}" if publisher else name.lower()
        display_name = self._resolve_nls(str(data.get("displayName") or name), pkg_path.parent)
        version = data.get("version") or None
        description = data.get("description", "")
        categories = data.get("categories", [])
        engines = data.get("engines", {})

        metadata: dict[str, Any] = {
            "extension_id": ext_id,
            "publisher": publisher,
            "display_name": display_name,
        }
        if description:
            metadata["description"] = description[:200]
        if categories:
            metadata["categories"] = [str(c) for c in categories]
        if engines:
            metadata["vscode_engine"] = engines.get("vscode", "")

        return Item(
            name=ext_id,
            version=version,
            item_type=ItemType.vscode_extension,
            source="vscode",
            locations=[str(pkg_path.parent)],
            metadata=metadata,
        )

    def _resolve_nls(self, value: str, ext_dir: Path) -> str:
        """Resolve %key% NLS placeholders using package.nls.json."""
        if not (value.startswith("%") and value.endswith("%") and len(value) > 2):
            return value
        key = value[1:-1]
        nls_path = ext_dir / "package.nls.json"
        try:
            nls = json.loads(nls_path.read_text(encoding="utf-8", errors="replace"))
            if isinstance(nls, dict) and key in nls:
                return str(nls[key])
        except Exception:
            pass
        return key  # fall back to the bare key name

    # ------------------------------------------------------------------
    # User config (settings, keybindings, MCP, snippets)
    # ------------------------------------------------------------------

    def _scan_user_config(self) -> list[Item]:
        user_dir = Path.home() / "Library" / "Application Support" / "Code" / "User"
        if not user_dir.exists():
            return []

        audit_flags: list[AuditFlag] = []
        config_paths: list[str] = []
        metadata: dict[str, Any] = {}

        # settings.json (JSONC)
        settings_path = user_dir / "settings.json"
        if settings_path.exists():
            config_paths.append(str(settings_path))
            try:
                raw = settings_path.read_text(encoding="utf-8", errors="replace")
                audit_flags.extend(_scan_for_secrets(raw, str(settings_path)))
                try:
                    settings = _parse_jsonc(raw)
                    if isinstance(settings, dict):
                        ext_keys = [k for k in settings if "." in k and not k.startswith("[")]
                        metadata["extension_settings_count"] = len(ext_keys)
                except (json.JSONDecodeError, Exception):
                    pass
            except (PermissionError, OSError):
                pass

        # keybindings.json (JSONC)
        kb_path = user_dir / "keybindings.json"
        if kb_path.exists():
            config_paths.append(str(kb_path))
            try:
                raw = kb_path.read_text(encoding="utf-8", errors="replace")
                parsed = _parse_jsonc(raw)
                if isinstance(parsed, list):
                    metadata["custom_keybindings"] = len(parsed)
            except Exception:
                pass

        # mcp.json - VS Code's own MCP server registry
        mcp_path = user_dir / "mcp.json"
        if mcp_path.exists():
            config_paths.append(str(mcp_path))
            try:
                raw = mcp_path.read_text(encoding="utf-8", errors="replace")
                audit_flags.extend(_scan_for_secrets(raw, str(mcp_path)))
                data = json.loads(raw)
                if isinstance(data, dict):
                    servers = data.get("servers", {})
                    if servers:
                        metadata["mcp_servers"] = list(servers.keys())
            except Exception:
                pass

        # profiles - named config profiles
        profiles_dir = user_dir / "profiles"
        if profiles_dir.exists():
            try:
                profile_count = sum(1 for p in profiles_dir.iterdir() if p.is_dir())
                if profile_count:
                    metadata["profiles"] = profile_count
            except (PermissionError, OSError):
                pass

        # snippets
        snippets_dir = user_dir / "snippets"
        if snippets_dir.exists():
            try:
                snippet_files = [
                    f for f in snippets_dir.iterdir()
                    if f.suffix in {".json", ".code-snippets"}
                ]
                if snippet_files:
                    metadata["snippet_files"] = len(snippet_files)
            except (PermissionError, OSError):
                pass

        if not config_paths:
            return []

        return [
            Item(
                name="vscode-user-settings",
                item_type=ItemType.shell_config,
                source="vscode",
                config_paths=config_paths,
                metadata=metadata,
                audit_flags=audit_flags,
            )
        ]
