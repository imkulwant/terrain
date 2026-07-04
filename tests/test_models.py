from datetime import datetime

import pytest

from terrain.models import AuditFlag, AuditSeverity, Item, ItemType, Snapshot


def test_item_minimal():
    item = Item(name="git", item_type=ItemType.package, source="brew")
    assert item.name == "git"
    assert item.version is None
    assert item.audit_flags == []
    assert item.locations == []


def test_item_with_audit_flags():
    flag = AuditFlag(severity=AuditSeverity.critical, message="exposed key", location="/tmp/f")
    item = Item(name="tool", item_type=ItemType.binary, source="direct_install", audit_flags=[flag])
    assert len(item.audit_flags) == 1
    assert item.audit_flags[0].severity == AuditSeverity.critical


def test_audit_flag_optional_location():
    flag = AuditFlag(severity=AuditSeverity.warning, message="no location")
    assert flag.location is None


@pytest.mark.parametrize("severity", list(AuditSeverity))
def test_audit_severity_values(severity):
    flag = AuditFlag(severity=severity, message="test")
    assert flag.severity == severity


def test_snapshot_round_trip():
    now = datetime(2024, 1, 1, 12, 0, 0)
    items = [
        Item(
            name="ripgrep",
            version="14.0.0",
            item_type=ItemType.package,
            source="brew",
        )
    ]
    snap = Snapshot(id=42, scanned_at=now, items=items)

    data = snap.model_dump(mode="json")
    snap2 = Snapshot.model_validate(data)

    assert snap2.id == 42
    assert snap2.scanned_at == now
    assert len(snap2.items) == 1
    assert snap2.items[0].name == "ripgrep"
    assert snap2.items[0].version == "14.0.0"


def test_item_type_enum_values():
    assert ItemType.package.value == "package"
    assert ItemType.binary.value == "binary"
    assert ItemType.ai_config.value == "ai_config"


def test_item_metadata_preserved():
    item = Item(
        name="node",
        item_type=ItemType.language_version,
        source="nvm",
        metadata={"active": True, "versions": ["18.0.0", "20.0.0"]},
    )
    dumped = item.model_dump(mode="json")
    restored = Item.model_validate(dumped)
    assert restored.metadata["active"] is True
    assert restored.metadata["versions"] == ["18.0.0", "20.0.0"]
