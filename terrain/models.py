from enum import Enum
from datetime import datetime
from pydantic import BaseModel


class ItemType(str, Enum):
    package = "package"
    cask = "cask"
    app_store = "app_store"
    language_version = "language_version"
    binary = "binary"
    ai_config = "ai_config"
    launch_agent = "launch_agent"
    launch_daemon = "launch_daemon"
    shell_config = "shell_config"


class AuditSeverity(str, Enum):
    info = "info"
    warning = "warning"
    critical = "critical"


class AuditFlag(BaseModel):
    severity: AuditSeverity
    message: str
    location: str | None = None


class Item(BaseModel):
    name: str
    version: str | None = None
    item_type: ItemType
    source: str
    installed_at: datetime | None = None
    locations: list[str] = []
    config_paths: list[str] = []
    permissions: dict = {}
    env_vars: list[str] = []
    metadata: dict = {}
    audit_flags: list[AuditFlag] = []


class Snapshot(BaseModel):
    id: int | None = None
    scanned_at: datetime
    items: list[Item]
