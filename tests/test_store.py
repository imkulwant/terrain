
import pytest

import terrain.store as store
from terrain.models import AuditFlag, AuditSeverity, Item, ItemType


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_DIR", tmp_path)
    monkeypatch.setattr(store, "DB_PATH", tmp_path / "terrain.db")


def _make_item(name: str = "foo", source: str = "brew") -> Item:
    return Item(name=name, item_type=ItemType.package, source=source, version="1.0.0")


def test_save_and_latest():
    items = [_make_item("git"), _make_item("ripgrep")]
    snap_id = store.save_snapshot(items)
    assert snap_id == 1

    latest = store.latest_snapshot()
    assert latest is not None
    assert latest.id == 1
    assert len(latest.items) == 2
    assert {i.name for i in latest.items} == {"git", "ripgrep"}


def test_latest_returns_none_when_empty():
    assert store.latest_snapshot() is None


def test_previous_snapshot():
    store.save_snapshot([_make_item("a")])
    store.save_snapshot([_make_item("b")])

    latest = store.latest_snapshot()
    previous = store.previous_snapshot()

    assert latest is not None
    assert previous is not None
    assert latest.id != previous.id
    assert latest.items[0].name == "b"
    assert previous.items[0].name == "a"


def test_previous_returns_none_with_one_snapshot():
    store.save_snapshot([_make_item("only")])
    assert store.previous_snapshot() is None


def test_get_snapshot_by_id():
    store.save_snapshot([_make_item("first")])
    store.save_snapshot([_make_item("second")])

    snap = store.get_snapshot(1)
    assert snap.items[0].name == "first"

    snap2 = store.get_snapshot(2)
    assert snap2.items[0].name == "second"


def test_get_snapshot_missing_raises():
    with pytest.raises(ValueError, match="No snapshot with id=99"):
        store.get_snapshot(99)


def test_all_snapshots_returns_empty_items():
    store.save_snapshot([_make_item("x")])
    store.save_snapshot([_make_item("y")])

    snaps = store.all_snapshots()
    assert len(snaps) == 2
    # all_snapshots intentionally omits item data for performance
    for snap in snaps:
        assert snap.items == []


def test_audit_flags_survive_round_trip():
    flag = AuditFlag(
        severity=AuditSeverity.critical,
        message="exposed key",
        location="/home/.env",
    )
    item = Item(
        name="secrets-tool",
        item_type=ItemType.binary,
        source="direct_install",
        audit_flags=[flag],
    )
    store.save_snapshot([item])
    latest = store.latest_snapshot()
    assert latest is not None
    assert len(latest.items[0].audit_flags) == 1
    assert latest.items[0].audit_flags[0].severity == AuditSeverity.critical
    assert latest.items[0].audit_flags[0].location == "/home/.env"
