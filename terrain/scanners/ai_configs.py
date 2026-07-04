import json
import re
from pathlib import Path
from typing import Any

from terrain.audit.secrets import SECRET_PATTERNS
from terrain.models import AuditFlag, AuditSeverity, Item, ItemType
from terrain.scanners.base import BaseScanner


def _find_secrets_in_text(text: str, location: str) -> list[AuditFlag]:
    flags: list[AuditFlag] = []
    for pattern, label in SECRET_PATTERNS:
        if re.search(pattern, text):
            flags.append(
                AuditFlag(
                    severity=AuditSeverity.critical,
                    message=f"Possible {label} found in config",
                    location=location,
                )
            )
    return flags


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


class AIConfigsScanner(BaseScanner):
    name = "ai_configs"

    def scan(self) -> list[Item]:
        items: list[Item] = []
        items.extend(self._scan_claude_code())
        items.extend(self._scan_cursor())
        items.extend(self._scan_copilot())
        items.extend(self._scan_continue())
        items.extend(self._scan_ollama())
        items.extend(self._scan_openai_cli())
        return items

    # -----------------------------------------------------------------
    # Claude Code
    # -----------------------------------------------------------------
    def _scan_claude_code(self) -> list[Item]:
        claude_dir = Path.home() / ".claude"
        if not claude_dir.exists():
            return []

        audit_flags: list[AuditFlag] = []
        config_paths: list[str] = []
        metadata: dict[str, Any] = {}

        # Gather all relevant files
        for fname in [
            "settings.json", "settings.local.json",
            "CLAUDE.md", "RTK.md", "AGENTS.md", "MEMORY.md",
            "keybindings.json",
        ]:
            fpath = claude_dir / fname
            if fpath.exists():
                config_paths.append(str(fpath))

        # Check for memory dir
        memory_dir = claude_dir / "memory"
        if memory_dir.exists():
            for f in memory_dir.glob("*.md"):
                config_paths.append(str(f))

        # Check for projects dir
        projects_dir = claude_dir / "projects"
        if projects_dir.exists():
            for proj in projects_dir.iterdir():
                if proj.is_dir():
                    for f in proj.glob("*.md"):
                        config_paths.append(str(f))

        # Also check ~/.config/ for CLAUDE.md and AGENTS.md
        config_dir = Path.home() / ".config"
        for fname in ["CLAUDE.md", "AGENTS.md"]:
            fpath = config_dir / fname
            if fpath.exists():
                config_paths.append(str(fpath))

        # Parse settings.json
        settings_path = claude_dir / "settings.json"
        if settings_path.exists():
            settings = _read_json(settings_path)
            if settings:
                metadata["model"] = settings.get("model", "")
                # MCP servers
                mcp_servers = settings.get("mcpServers", {})
                metadata["mcp_servers"] = list(mcp_servers.keys()) if mcp_servers else []
                mcp_details = {}
                for srv_name, srv_conf in mcp_servers.items():
                    if isinstance(srv_conf, dict):
                        mcp_details[srv_name] = {
                            "command": srv_conf.get("command", ""),
                            "args": srv_conf.get("args", []),
                        }
                if mcp_details:
                    metadata["mcp_details"] = mcp_details

                # Hooks
                hooks = settings.get("hooks", {})
                if hooks:
                    metadata["hooks"] = hooks

                # Permissions
                permissions_conf = settings.get("permissions", {})
                if permissions_conf:
                    metadata["permissions"] = permissions_conf

            # Scan for secrets
            text = _read_text(settings_path)
            if text:
                audit_flags.extend(_find_secrets_in_text(text, str(settings_path)))

        # Claude Desktop app
        desktop_dir = (
            Path.home() / "Library" / "Application Support" / "Claude"
        )
        if desktop_dir.exists():
            metadata["claude_desktop_present"] = True
            desktop_config = desktop_dir / "claude_desktop_config.json"
            if desktop_config.exists():
                config_paths.append(str(desktop_config))
                d_settings = _read_json(desktop_config)
                if d_settings:
                    desktop_mcp = d_settings.get("mcpServers", {})
                    existing = metadata.get("mcp_servers", [])
                    all_mcp = list(set(existing + list(desktop_mcp.keys())))
                    metadata["mcp_servers"] = all_mcp

        return [
            Item(
                name="claude-code",
                item_type=ItemType.ai_config,
                source="claude_code",
                config_paths=config_paths,
                metadata=metadata,
                audit_flags=audit_flags,
            )
        ]

    # -----------------------------------------------------------------
    # Cursor
    # -----------------------------------------------------------------
    def _scan_cursor(self) -> list[Item]:
        candidates = [
            Path.home() / ".cursor",
            Path.home() / "Library" / "Application Support" / "Cursor",
        ]

        found_dir: Path | None = None
        for c in candidates:
            if c.exists():
                found_dir = c
                break

        if not found_dir:
            return []

        config_paths: list[str] = []
        metadata: dict[str, Any] = {}
        audit_flags: list[AuditFlag] = []

        # Look for settings files
        for rel in [
            "settings.json",
            "User/settings.json",
            "User/globalStorage/settings.json",
        ]:
            sp = found_dir / rel
            if sp.exists():
                config_paths.append(str(sp))
                settings = _read_json(sp)
                if settings:
                    model = settings.get("cursor.general.customGptModel", "")
                    if model:
                        metadata["model"] = model

        # Check for .cursorrules
        cursorrules = Path.home() / ".cursorrules"
        if cursorrules.exists():
            config_paths.append(str(cursorrules))

        return [
            Item(
                name="cursor",
                item_type=ItemType.ai_config,
                source="cursor",
                config_paths=config_paths,
                metadata=metadata,
                audit_flags=audit_flags,
            )
        ]

    # -----------------------------------------------------------------
    # GitHub Copilot
    # -----------------------------------------------------------------
    def _scan_copilot(self) -> list[Item]:
        candidates = [
            Path.home() / ".config" / "github-copilot" / "hosts.json",
            Path.home() / "Library" / "Application Support" / "GitHub Copilot",
        ]

        found_any = any(c.exists() for c in candidates)
        if not found_any:
            return []

        config_paths: list[str] = []
        metadata: dict[str, Any] = {}
        audit_flags: list[AuditFlag] = []

        hosts_json = Path.home() / ".config" / "github-copilot" / "hosts.json"
        if hosts_json.exists():
            config_paths.append(str(hosts_json))
            data = _read_json(hosts_json)
            if data:
                metadata["hosts"] = list(data.keys())
            text = _read_text(hosts_json)
            if text:
                audit_flags.extend(_find_secrets_in_text(text, str(hosts_json)))

        app_support = Path.home() / "Library" / "Application Support" / "GitHub Copilot"
        if app_support.exists():
            metadata["app_data_present"] = True

        return [
            Item(
                name="github-copilot",
                item_type=ItemType.ai_config,
                source="copilot",
                config_paths=config_paths,
                metadata=metadata,
                audit_flags=audit_flags,
            )
        ]

    # -----------------------------------------------------------------
    # Continue
    # -----------------------------------------------------------------
    def _scan_continue(self) -> list[Item]:
        config_path = Path.home() / ".continue" / "config.json"
        if not config_path.exists():
            return []

        config_paths = [str(config_path)]
        metadata: dict[str, Any] = {}
        audit_flags: list[AuditFlag] = []

        data = _read_json(config_path)
        if data:
            models = data.get("models", [])
            model_names = [m.get("model", m.get("title", "")) for m in models if isinstance(m, dict)]
            metadata["models"] = [m for m in model_names if m]

            context_providers = data.get("contextProviders", [])
            metadata["context_providers"] = [
                p.get("name", "") for p in context_providers if isinstance(p, dict)
            ]

        text = _read_text(config_path)
        if text:
            audit_flags.extend(_find_secrets_in_text(text, str(config_path)))

        return [
            Item(
                name="continue",
                item_type=ItemType.ai_config,
                source="continue",
                config_paths=config_paths,
                metadata=metadata,
                audit_flags=audit_flags,
            )
        ]

    # -----------------------------------------------------------------
    # Ollama
    # -----------------------------------------------------------------
    def _scan_ollama(self) -> list[Item]:
        ollama = self._which("ollama")
        models_dir = Path.home() / ".ollama" / "models"

        if not ollama and not models_dir.exists():
            return []

        metadata: dict[str, Any] = {}
        audit_flags: list[AuditFlag] = []
        locations: list[str] = []

        if ollama:
            locations.append(ollama)

        # List models
        out, rc = self._run(["ollama", "list"])
        if rc == 0 and out:
            model_names = []
            for line in out.splitlines()[1:]:  # skip header
                parts = line.split()
                if parts:
                    model_names.append(parts[0])
            metadata["models"] = model_names
        elif models_dir.exists():
            # Fallback: read directory names
            try:
                model_names = [d.name for d in models_dir.iterdir() if d.is_dir()]
                metadata["models"] = model_names
            except PermissionError:
                pass

        # Check if server is running
        pgrep_out, pgrep_rc = self._run(["pgrep", "-x", "ollama"])
        if pgrep_rc == 0:
            metadata["server_running"] = True
            audit_flags.append(
                AuditFlag(
                    severity=AuditSeverity.info,
                    message="Ollama server is currently running (port 11434)",
                    location="localhost:11434",
                )
            )
        else:
            metadata["server_running"] = False

        return [
            Item(
                name="ollama",
                item_type=ItemType.ai_config,
                source="ollama",
                locations=locations,
                metadata=metadata,
                audit_flags=audit_flags,
            )
        ]

    # -----------------------------------------------------------------
    # OpenAI CLI
    # -----------------------------------------------------------------
    def _scan_openai_cli(self) -> list[Item]:
        candidates = [
            Path.home() / ".openai",
            Path.home() / ".config" / "openai",
        ]

        found_any = any(c.exists() for c in candidates)
        openai_bin = self._which("openai")

        if not found_any and not openai_bin:
            return []

        config_paths: list[str] = []
        audit_flags: list[AuditFlag] = []
        locations: list[str] = []

        if openai_bin:
            locations.append(openai_bin)

        for d in candidates:
            if d.exists():
                for f in d.glob("*"):
                    if f.is_file():
                        config_paths.append(str(f))
                        text = _read_text(f)
                        if text:
                            audit_flags.extend(_find_secrets_in_text(text, str(f)))

        return [
            Item(
                name="openai-cli",
                item_type=ItemType.ai_config,
                source="openai_cli",
                locations=locations,
                config_paths=config_paths,
                audit_flags=audit_flags,
            )
        ]
