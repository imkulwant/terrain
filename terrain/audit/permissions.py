import stat
from pathlib import Path

from terrain.models import AuditFlag, AuditSeverity


def check_file_permissions(path: Path, expected_mode: int = 0o600) -> list[AuditFlag]:
    """Check if a file has the expected permissions. Returns flags if not."""
    flags: list[AuditFlag] = []
    try:
        st = path.stat()
        actual_mode = stat.S_IMODE(st.st_mode)
        if actual_mode != expected_mode:
            expected_str = oct(expected_mode)[-3:]
            actual_str = oct(actual_mode)[-3:]
            flags.append(
                AuditFlag(
                    severity=AuditSeverity.warning,
                    message=f"File has permissions {actual_str} (expected {expected_str})",
                    location=str(path),
                )
            )
    except (PermissionError, OSError):
        pass
    return flags


def check_world_readable(path: Path) -> list[AuditFlag]:
    """Check if a sensitive file is world-readable."""
    flags: list[AuditFlag] = []
    try:
        st = path.stat()
        if st.st_mode & stat.S_IROTH:
            flags.append(
                AuditFlag(
                    severity=AuditSeverity.critical,
                    message="File is world-readable",
                    location=str(path),
                )
            )
    except (PermissionError, OSError):
        pass
    return flags


def check_world_writable(path: Path) -> list[AuditFlag]:
    """Check if a path is world-writable."""
    flags: list[AuditFlag] = []
    try:
        st = path.stat()
        if st.st_mode & stat.S_IWOTH:
            flags.append(
                AuditFlag(
                    severity=AuditSeverity.warning,
                    message="Path is world-writable",
                    location=str(path),
                )
            )
    except (PermissionError, OSError):
        pass
    return flags


def check_directory_permissions(path: Path) -> list[AuditFlag]:
    """Check if a sensitive directory has safe permissions."""
    flags: list[AuditFlag] = []
    try:
        st = path.stat()
        # Directory should not be world-readable or world-executable for sensitive dirs
        if st.st_mode & (stat.S_IROTH | stat.S_IXOTH):
            flags.append(
                AuditFlag(
                    severity=AuditSeverity.warning,
                    message="Sensitive directory is accessible by others",
                    location=str(path),
                )
            )
    except (PermissionError, OSError):
        pass
    return flags


def audit_ssh_dir() -> list[AuditFlag]:
    """Comprehensive SSH directory permission audit."""
    flags: list[AuditFlag] = []
    ssh_dir = Path.home() / ".ssh"
    if not ssh_dir.exists():
        return flags

    # The directory itself should be 700
    flags.extend(check_directory_permissions(ssh_dir))

    try:
        for f in ssh_dir.iterdir():
            if not f.is_file():
                continue
            if f.suffix == ".pub":
                # Public keys should be readable
                continue
            # Private key or config - should be 600 or 644
            if f.name in {"config", "known_hosts", "authorized_keys"}:
                flags.extend(check_file_permissions(f, expected_mode=0o644))
            else:
                # Likely a private key
                try:
                    first_line = f.read_text(errors="ignore").splitlines()[:1]
                    if first_line and "PRIVATE KEY" in first_line[0]:
                        flags.extend(check_file_permissions(f, expected_mode=0o600))
                except Exception:
                    pass
    except PermissionError:
        pass

    return flags
