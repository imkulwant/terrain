import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from terrain.models import Item, Snapshot

DB_DIR = Path.home() / ".terrain"
DB_PATH = DB_DIR / "terrain.db"


@contextmanager
def _connect() -> Generator[sqlite3.Connection, None, None]:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    try:
        yield conn
    finally:
        conn.close()


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL,
            item_count INTEGER NOT NULL,
            data TEXT NOT NULL
        )
        """
    )
    conn.commit()


def _serialize_items(items: list[Item]) -> str:
    return json.dumps([item.model_dump(mode="json") for item in items])


def _deserialize_items(data: str) -> list[Item]:
    raw = json.loads(data)
    return [Item.model_validate(r) for r in raw]


def save_snapshot(items: list[Item]) -> int:
    with _connect() as conn:
        now = datetime.now().isoformat()
        data = _serialize_items(items)
        cur = conn.execute(
            "INSERT INTO snapshots (scanned_at, item_count, data) VALUES (?, ?, ?)",
            (now, len(items), data),
        )
        conn.commit()
        assert cur.lastrowid is not None
        return cur.lastrowid


def latest_snapshot() -> Snapshot | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM snapshots ORDER BY id DESC LIMIT 1"
        ).fetchone()
    if row is None:
        return None
    return Snapshot(
        id=row["id"],
        scanned_at=datetime.fromisoformat(row["scanned_at"]),
        items=_deserialize_items(row["data"]),
    )


def previous_snapshot() -> Snapshot | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM snapshots ORDER BY id DESC LIMIT 1 OFFSET 1"
        ).fetchone()
    if row is None:
        return None
    return Snapshot(
        id=row["id"],
        scanned_at=datetime.fromisoformat(row["scanned_at"]),
        items=_deserialize_items(row["data"]),
    )


def all_snapshots() -> list[Snapshot]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, scanned_at, item_count FROM snapshots ORDER BY id DESC"
        ).fetchall()
    return [
        Snapshot(
            id=row["id"],
            scanned_at=datetime.fromisoformat(row["scanned_at"]),
            items=[],
        )
        for row in rows
    ]


def get_snapshot(snapshot_id: int) -> Snapshot:
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM snapshots WHERE id = ?", (snapshot_id,)
        ).fetchone()
    if row is None:
        raise ValueError(f"No snapshot with id={snapshot_id}")
    return Snapshot(
        id=row["id"],
        scanned_at=datetime.fromisoformat(row["scanned_at"]),
        items=_deserialize_items(row["data"]),
    )
