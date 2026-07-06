from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from terrain.models import AuditFlag, AuditSeverity, Item, ItemType
from terrain.scanners.base import BaseScanner


@dataclass
class _DotfileInfo:
    owner: str
    purpose: str
    binaries: list[str] = field(default_factory=list)
    app_names: list[str] = field(default_factory=list)
    # VS Code extension IDs (publisher.name) that create or actively use this dotfile
    vscode_extensions: list[str] = field(default_factory=list)
    sensitive: bool = False
    always_active: bool = False
    skip: bool = False


# Known dotfiles/dirs in ~/ and the tool that owns them.
_KB: dict[str, _DotfileInfo] = {
    # Shell & terminal
    ".zshrc": _DotfileInfo("Zsh", "Main Zsh configuration", always_active=True),
    ".zprofile": _DotfileInfo("Zsh", "Zsh login profile", always_active=True),
    ".zsh_history": _DotfileInfo("Zsh", "Interactive shell command history", always_active=True),
    ".zsh_sessions": _DotfileInfo("Zsh", "Zsh session restore files", always_active=True),
    ".zshrc.pre-oh-my-zsh": _DotfileInfo(
        "Oh My Zsh", "Original .zshrc backed up before OMZ install", always_active=True
    ),
    ".oh-my-zsh": _DotfileInfo("Oh My Zsh", "Oh My Zsh framework", always_active=True),
    ".p10k.zsh": _DotfileInfo("Powerlevel10k", "Powerlevel10k prompt theme config", always_active=True),
    ".aliases.zsh": _DotfileInfo("User", "Custom shell aliases", always_active=True),
    ".viminfo": _DotfileInfo("Vim", "Vim editor state and command history", binaries=["vim", "nvim"]),
    ".lesshst": _DotfileInfo("less", "less pager command history", always_active=True),
    ".python_history": _DotfileInfo("Python", "Python REPL command history", binaries=["python3", "python"]),
    ".mysql_history": _DotfileInfo("MySQL", "MySQL CLI command history", binaries=["mysql"]),

    # XDG base dirs - shared by many tools
    ".config": _DotfileInfo("XDG", "XDG user config directory (shared by many tools)", always_active=True),
    ".cache": _DotfileInfo("XDG", "XDG user cache directory (shared by many tools)", always_active=True),
    ".local": _DotfileInfo("XDG", "XDG local data directory (shared by many tools)", always_active=True),

    # Version control & SSH
    ".gitconfig": _DotfileInfo("Git", "Global Git configuration", binaries=["git"]),
    ".ssh": _DotfileInfo(
        "OpenSSH", "SSH keys, config, and known hosts",
        binaries=["ssh"], sensitive=True, always_active=True,
    ),

    # Package managers & build tools
    ".homebrew": _DotfileInfo("Homebrew", "Homebrew installation prefix", binaries=["brew"]),
    ".npm": _DotfileInfo("npm", "npm global config and cache", binaries=["npm", "node"]),
    ".gradle": _DotfileInfo(
        "Gradle", "Gradle build cache and wrapper jars",
        binaries=["gradle"],
        vscode_extensions=[
            "vscjava.vscode-gradle",
            "vscjava.vscode-java-pack",
            "redhat.java",
        ],
    ),
    ".m2": _DotfileInfo(
        "Apache Maven", "Maven local repository cache",
        binaries=["mvn"],
        vscode_extensions=[
            "vscjava.vscode-maven",
            "vscjava.vscode-java-pack",
            "redhat.java",
        ],
    ),
    ".cargo": _DotfileInfo("Rust / Cargo", "Rust crate registry and installed binaries", binaries=["cargo", "rustc"]),

    # Language version managers
    ".jenv": _DotfileInfo("jenv", "Java version manager", binaries=["jenv"]),
    ".pyenv": _DotfileInfo("pyenv", "Python version manager", binaries=["pyenv"]),
    ".nvm": _DotfileInfo("nvm", "Node.js version manager"),  # sourced via shell, no standalone binary
    ".rbenv": _DotfileInfo("rbenv", "Ruby version manager", binaries=["rbenv"]),

    # AI tools
    ".claude": _DotfileInfo("Claude Code", "Claude Code CLI config, memory, and projects", binaries=["claude"]),
    ".claude.json": _DotfileInfo(
        "Claude Code", "Claude Code authentication config (legacy format)", binaries=["claude"]
    ),
    ".claude.json.backup": _DotfileInfo(
        "Claude Code", "Backup of Claude Code authentication config", binaries=["claude"]
    ),
    ".codex": _DotfileInfo("OpenAI Codex CLI", "OpenAI Codex CLI config", binaries=["codex"]),
    ".ollama": _DotfileInfo("Ollama", "Ollama local LLM models and config", binaries=["ollama"]),
    ".copilot": _DotfileInfo("GitHub Copilot", "GitHub Copilot CLI config", binaries=["gh"]),
    ".agents": _DotfileInfo("AI Agents", "Agent configuration files"),
    ".ghcp-appmod": _DotfileInfo(
        "GitHub Copilot App Modernization", "Copilot app modernization workspace",
        vscode_extensions=["vscjava.migrate-java-to-azure"],
    ),
    ".ghcp-appmod-java": _DotfileInfo(
        "GitHub Copilot App Modernization", "Copilot Java app modernization workspace",
        vscode_extensions=["vscjava.migrate-java-to-azure"],
    ),

    # Infrastructure & DevOps
    ".docker": _DotfileInfo(
        "Docker", "Docker CLI config and credentials",
        binaries=["docker"], app_names=["Docker"], sensitive=True,
    ),
    ".kube": _DotfileInfo(
        "Kubernetes", "kubectl config and cluster credentials",
        binaries=["kubectl"], sensitive=True,
    ),
    ".terraform": _DotfileInfo("Terraform", "Terraform plugin cache", binaries=["terraform"]),

    # IDEs & editors
    ".vscode": _DotfileInfo(
        "VS Code", "VS Code user settings and extensions",
        binaries=["code"], app_names=["Visual Studio Code"],
    ),
    ".vscode-shared": _DotfileInfo(
        "VS Code", "VS Code shared workspace settings",
        binaries=["code"], app_names=["Visual Studio Code"],
    ),
    ".sts4": _DotfileInfo(
        "Spring Tool Suite 4", "Spring Tool Suite / VS Code Spring Boot language server data",
        app_names=["SpringToolSuite4"],
        vscode_extensions=[
            "vmware.vscode-spring-boot",
            "vmware.vscode-boot-dev-pack",
        ],
    ),
    ".sonarlint": _DotfileInfo(
        "SonarLint", "SonarLint IDE plugin config and analysis cache",
        vscode_extensions=["sonarsource.sonarlint-vscode"],
    ),

    # Databases
    ".mongodb": _DotfileInfo("MongoDB", "MongoDB CLI config and shell history", binaries=["mongosh", "mongo"]),

    # Other tools
    ".anydesk": _DotfileInfo("AnyDesk", "AnyDesk remote desktop config", app_names=["AnyDesk"]),
    ".net": _DotfileInfo(".NET SDK", ".NET SDK config and tools", binaries=["dotnet"]),
    ".matplotlib": _DotfileInfo("Matplotlib", "Matplotlib font and style cache", binaries=["python3"]),
    ".testcontainers.properties": _DotfileInfo(
        "Testcontainers", "Testcontainers Java library config",
        vscode_extensions=[
            "vscjava.vscode-java-test",
            "vscjava.vscode-java-pack",
        ],
    ),
    ".treehouse": _DotfileInfo("Treehouse", "Treehouse learning platform config"),
    ".terrain": _DotfileInfo("terrain", "terrain snapshot database", binaries=["terrain"]),

    # macOS system noise - skip
    ".DS_Store": _DotfileInfo("macOS", "Finder folder metadata", always_active=True, skip=True),
    ".Trash": _DotfileInfo("macOS", "macOS Trash folder", always_active=True, skip=True),
}

# Prefixes to skip entirely (auto-generated files)
_SKIP_PREFIXES = (".zcompdump",)

# Dirs where we measure disk usage (these can grow large)
_CACHE_DIRS = {".gradle", ".m2", ".npm", ".cache", ".cargo"}

# 200 MB threshold for "large cache" info flag
_LARGE_CACHE_BYTES = 200 * 1024 * 1024


class DotfilesScanner(BaseScanner):
    name = "dotfiles"

    def __init__(self) -> None:
        self._vscode_extensions_cache: frozenset[str] | None = None

    def scan(self) -> list[Item]:
        home = Path.home()
        shell_configs = self._read_shell_configs(home)
        items: list[Item] = []

        try:
            entries = list(home.iterdir())
        except PermissionError:
            return []

        for entry in sorted(entries, key=lambda p: p.name.lower()):
            if not entry.name.startswith("."):
                continue
            if any(entry.name.startswith(p) for p in _SKIP_PREFIXES):
                continue

            info = _KB.get(entry.name)
            if info and info.skip:
                continue

            item = self._process_entry(entry, info, shell_configs)
            if item:
                items.append(item)

        return items

    # ------------------------------------------------------------------
    # Entry processing
    # ------------------------------------------------------------------

    def _process_entry(
        self,
        path: Path,
        info: _DotfileInfo | None,
        shell_configs: dict[str, str],
    ) -> Item | None:
        audit_flags: list[AuditFlag] = []
        metadata: dict[str, Any] = {}

        metadata["entry_type"] = "dir" if path.is_dir() else "file"

        try:
            stat = os.stat(path)
            metadata["modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()[:10]
        except OSError:
            pass

        # README lookup before branching - used to fill in unknown dotfiles
        readme_meta = self._read_readme(path)

        if info:
            metadata["owner"] = info.owner
            metadata["purpose"] = info.purpose
            if info.sensitive:
                metadata["sensitive"] = True

            if info.always_active:
                metadata["active"] = True
            else:
                refs = self._shell_refs(path.name, info, shell_configs)
                active, active_via = self._resolve_active(info, refs)
                metadata["active"] = active
                if active_via:
                    metadata["active_via"] = active_via
                if refs:
                    metadata["shell_references"] = refs
                if not active:
                    audit_flags.append(
                        AuditFlag(
                            severity=AuditSeverity.warning,
                            message=f"Orphaned config - {info.owner} is not installed and not referenced in shell",
                            location=str(path),
                        )
                    )
        else:
            # Unknown dotfile: use README data when available
            readme_owner = readme_meta.get("owner", "") if readme_meta else ""
            readme_purpose = (
                (readme_meta.get("purpose") or readme_meta.get("summary", ""))
                if readme_meta else ""
            )
            metadata["owner"] = readme_owner or "unknown"
            metadata["purpose"] = readme_purpose[:200] if readme_purpose else "unknown"
            metadata["active"] = None

            if not readme_owner:
                # README exists but didn't declare an owner - still flag it
                msg = (
                    f"Unknown dotfile - README found but no owner declared in {path.name}"
                    if readme_meta
                    else f"Unknown dotfile - origin of {path.name} not recognized"
                )
                audit_flags.append(
                    AuditFlag(severity=AuditSeverity.info, message=msg, location=str(path))
                )

        # Attach README metadata for any dotfile that has one
        if readme_meta:
            readme_path_val = readme_meta.pop("path", "")
            if readme_path_val:
                metadata["readme"] = readme_path_val
            for k, v in readme_meta.items():
                metadata[f"readme_{k}"] = v

        # Large cache check for known heavy dirs
        if path.name in _CACHE_DIRS and path.is_dir():
            size = self._dir_size(path)
            if size is not None:
                metadata["size_bytes"] = size
                if size > _LARGE_CACHE_BYTES:
                    size_mb = size // (1024 * 1024)
                    audit_flags.append(
                        AuditFlag(
                            severity=AuditSeverity.info,
                            message=f"Large cache directory: {size_mb} MB",
                            location=str(path),
                        )
                    )

        return Item(
            name=path.name,
            item_type=ItemType.home_config,
            source="dotfiles",
            locations=[str(path)],
            metadata=metadata,
            audit_flags=audit_flags,
        )

    # ------------------------------------------------------------------
    # Activity resolution
    # ------------------------------------------------------------------

    def _resolve_active(self, info: _DotfileInfo, refs: list[str]) -> tuple[bool, str | None]:
        """Return (active, active_via) where active_via explains what keeps it alive."""
        for binary in info.binaries:
            if self._which(binary):
                return True, f"binary: {binary}"

        for app in info.app_names:
            if (Path("/Applications") / f"{app}.app").exists():
                return True, f"app: {app}"

        if refs:
            return True, f"shell: {refs[0]}"

        if info.vscode_extensions:
            installed = self._get_vscode_extensions()
            for ext in info.vscode_extensions:
                if ext.lower() in installed:
                    return True, f"vscode: {ext}"

        return False, None

    def _get_vscode_extensions(self) -> frozenset[str]:
        """Return the set of installed VS Code extension IDs (lowercased), cached per scan."""
        if self._vscode_extensions_cache is None:
            out, rc = self._run(["code", "--list-extensions"], timeout=10)
            if rc == 0 and out:
                self._vscode_extensions_cache = frozenset(
                    line.strip().lower() for line in out.splitlines() if line.strip()
                )
            else:
                self._vscode_extensions_cache = frozenset()
        return self._vscode_extensions_cache

    def _shell_refs(
        self,
        dotfile_name: str,
        info: _DotfileInfo | None,
        shell_configs: dict[str, str],
    ) -> list[str]:
        """Return shell config filenames that reference this dotfile's tool."""
        terms: set[str] = {dotfile_name, dotfile_name.lstrip(".")}
        if info:
            terms.update(info.binaries)

        refs: list[str] = []
        for fname, content in shell_configs.items():
            for term in terms:
                if term and len(term) > 1 and term in content:
                    refs.append(fname)
                    break
        return refs

    # ------------------------------------------------------------------
    # README parsing
    # ------------------------------------------------------------------

    def _read_readme(self, path: Path) -> dict[str, str] | None:
        """Return parsed README metadata for a dotdir, or None if not found."""
        if not path.is_dir():
            return None
        for name in ("README.md", "README", "README.txt", "readme.md"):
            candidate = path / name
            if candidate.is_file():
                result = self._parse_readme(candidate)
                return result if result else None
        return None

    def _parse_readme(self, readme: Path) -> dict[str, str]:
        """Extract ownership metadata from a README file.

        Handles two formats:
        - YAML frontmatter (--- ... ---): reads owner, purpose, managed_by, etc.
        - Plain markdown: extracts first # heading as title, first paragraph as summary.
        """
        try:
            text = readme.read_text(encoding="utf-8", errors="replace")[:4000]
        except (PermissionError, OSError):
            return {}

        result: dict[str, str] = {"path": str(readme)}
        body = text

        # YAML frontmatter
        if text.startswith("---"):
            end = text.find("\n---", 3)
            if end != -1:
                frontmatter = text[3:end]
                body = text[end + 4 :].lstrip()
                for line in frontmatter.splitlines():
                    if ":" in line:
                        key, _, val = line.partition(":")
                        key = key.strip().lower().replace("-", "_")
                        val = val.strip()
                        if key in (
                            "owner", "purpose", "managed_by",
                            "name", "safe_to_delete", "updated_by",
                        ):
                            result[key] = val

        # Markdown title + first paragraph from body
        title = ""
        para_lines: list[str] = []
        after_title = False
        for line in body.splitlines():
            stripped = line.strip()
            if not title and stripped.startswith("#"):
                title = stripped.lstrip("#").strip()
                after_title = True
            elif after_title:
                if stripped:
                    para_lines.append(stripped)
                elif para_lines:
                    break

        if title:
            result["title"] = title
        if para_lines:
            summary = " ".join(para_lines)
            result["summary"] = summary[:300] + "..." if len(summary) > 300 else summary

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _read_shell_configs(self, home: Path) -> dict[str, str]:
        candidates = [
            home / ".zshrc",
            home / ".zprofile",
            home / ".aliases.zsh",
            home / ".bashrc",
            home / ".bash_profile",
        ]
        result: dict[str, str] = {}
        for f in candidates:
            try:
                if f.exists():
                    result[f.name] = f.read_text(encoding="utf-8", errors="replace")
            except (PermissionError, OSError):
                pass
        return result

    def _dir_size(self, path: Path) -> int | None:
        """Return directory size in bytes via du -sk (1K blocks on macOS)."""
        out, rc = self._run(["du", "-sk", str(path)], timeout=5)
        if rc == 0 and out:
            try:
                blocks = int(out.split()[0])
                return blocks * 1024
            except (ValueError, IndexError):
                pass
        return None
