import re
from pathlib import Path

from terrain.models import AuditFlag, AuditSeverity, Item, ItemType
from terrain.scanners.base import BaseScanner

PRIVATE_KEY_NAMES = {
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    "id_rsa.pem", "id_ed25519.pem",
}


class SSHScanner(BaseScanner):
    name = "ssh"

    def scan(self) -> list[Item]:
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.exists():
            return []

        items: list[Item] = []
        audit_flags: list[AuditFlag] = []
        metadata: dict = {}
        config_paths: list[str] = []

        # SSH config
        ssh_config = ssh_dir / "config"
        if ssh_config.exists():
            config_paths.append(str(ssh_config))
            try:
                config_text = ssh_config.read_text(encoding="utf-8", errors="replace")
                self._analyze_ssh_config(config_text, str(ssh_config), audit_flags, metadata)
            except (PermissionError, OSError):
                pass

        # authorized_keys
        auth_keys = ssh_dir / "authorized_keys"
        if auth_keys.exists():
            config_paths.append(str(auth_keys))
            try:
                content = auth_keys.read_text(encoding="utf-8", errors="replace")
                key_count = sum(
                    1 for line in content.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                )
                metadata["authorized_keys_count"] = key_count
            except (PermissionError, OSError):
                pass

        # known_hosts
        known_hosts = ssh_dir / "known_hosts"
        if known_hosts.exists():
            config_paths.append(str(known_hosts))
            try:
                content = known_hosts.read_text(encoding="utf-8", errors="replace")
                host_count = sum(
                    1 for line in content.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                )
                metadata["known_hosts_count"] = host_count
            except (PermissionError, OSError):
                pass

        # Private key files
        private_keys: list[str] = []
        try:
            for f in ssh_dir.iterdir():
                if f.name in PRIVATE_KEY_NAMES or (
                    not f.name.endswith(".pub") and f.is_file()
                    and not f.name.startswith(".")
                    and f.name not in {"config", "known_hosts", "authorized_keys"}
                ):
                    # Check if it looks like a private key
                    try:
                        first_line = ""
                        with open(f, "r", errors="replace") as fh:
                            first_line = fh.readline().strip()
                        if "PRIVATE KEY" in first_line or "BEGIN OPENSSH" in first_line:
                            private_keys.append(f.name)
                            # Check permissions
                            try:
                                stat = f.stat()
                                perm_oct = oct(stat.st_mode)[-3:]
                                # Should be 600 (rw-------)
                                if stat.st_mode & 0o077:  # any group/other permission
                                    audit_flags.append(
                                        AuditFlag(
                                            severity=AuditSeverity.critical,
                                            message=f"Private key has insecure permissions ({perm_oct}): {f.name}",
                                            location=str(f),
                                        )
                                    )
                            except OSError:
                                pass
                    except (PermissionError, OSError, UnicodeDecodeError):
                        pass
        except PermissionError:
            pass

        if private_keys:
            metadata["private_keys"] = private_keys

        items.append(
            Item(
                name="ssh-config",
                item_type=ItemType.shell_config,
                source="ssh",
                config_paths=config_paths,
                metadata=metadata,
                audit_flags=audit_flags,
            )
        )

        return items

    def _analyze_ssh_config(
        self,
        text: str,
        location: str,
        audit_flags: list[AuditFlag],
        metadata: dict,
    ) -> None:
        host_blocks: list[dict] = []
        current_host: dict = {}
        forward_agent_hosts: list[str] = []
        strict_host_checking_no: list[str] = []

        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            parts = stripped.split(None, 1)
            if len(parts) < 2:
                continue

            key = parts[0].lower()
            value = parts[1]

            if key == "host":
                if current_host:
                    host_blocks.append(current_host)
                current_host = {"host": value}
            elif current_host is not None:
                current_host[key] = value

                if key == "forwardagent" and value.lower() == "yes":
                    forward_agent_hosts.append(current_host.get("host", "?"))
                    audit_flags.append(
                        AuditFlag(
                            severity=AuditSeverity.warning,
                            message=f"ForwardAgent=yes for host '{current_host.get('host', '?')}' - security risk",
                            location=location,
                        )
                    )

                if key == "stricthostkeychecking" and value.lower() == "no":
                    strict_host_checking_no.append(current_host.get("host", "?"))
                    audit_flags.append(
                        AuditFlag(
                            severity=AuditSeverity.warning,
                            message=f"StrictHostKeyChecking=no for host '{current_host.get('host', '?')}' - MITM risk",
                            location=location,
                        )
                    )

        if current_host:
            host_blocks.append(current_host)

        metadata["host_blocks"] = len(host_blocks)
        if forward_agent_hosts:
            metadata["forward_agent_hosts"] = forward_agent_hosts
        if strict_host_checking_no:
            metadata["strict_host_checking_no"] = strict_host_checking_no
