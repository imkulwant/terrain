import json
import sqlite3
from datetime import datetime
from pathlib import Path

from terrain.models import Item, Snapshot

DB_DIR = Path.home() / ".terrain"
DB_PATH = DB_DIR / "terrain.db"


def _get_connection() -> sqlite3.Connection:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    return conn


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
    conn = _get_connection()
    now = datetime.now().isoformat()
    data = _serialize_items(items)
    cur = conn.execute(
        "INSERT INTO snapshots (scanned_at, item_count, data) VALUES (?, ?, ?)",
        (now, len(items), data),
    )
    conn.commit()
    snapshot_id = cur.lastrowid
    conn.close()
    return snapshot_id


def latest_snapshot() -> Snapshot | None:
    conn = _get_connection()
    row = conn.execute(
        "SELECT * FROM snapshots ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    if row is None:
        return None
    return Snapshot(
        id=row["id"],
        scanned_at=datetime.fromisoformat(row["scanned_at"]),
        items=_deserialize_items(row["data"]),
    )


def previous_snapshot() -> Snapshot | None:
    conn = _get_connection()
    row = conn.execute(
        "SELECT * FROM snapshots ORDER BY id DESC LIMIT 1 OFFSET 1"
    ).fetchone()
    conn.close()
    if row is None:
        return None
    return Snapshot(
        id=row["id"],
        scanned_at=datetime.fromisoformat(row["scanned_at"]),
        items=_deserialize_items(row["data"]),
    )


def all_snapshots() -> list[Snapshot]:
    conn = _get_connection()
    rows = conn.execute(
        "SELECT id, scanned_at, item_count FROM snapshots ORDER BY id DESC"
    ).fetchall()
    conn.close()
    result = []
    for row in rows:
        result.append(
            Snapshot(
                id=row["id"],
                scanned_at=datetime.fromisoformat(row["scanned_at"]),
                items=[],
            )
        )
    return result


def get_snapshot(snapshot_id: int) -> Snapshot:
    conn = _get_connection()
    row = conn.execute(
        "SELECT * FROM snapshots WHERE id = ?", (snapshot_id,)
    ).fetchone()
    conn.close()
    if row is None:
        raise ValueError(f"No snapshot with id={snapshot_id}")
    return Snapshot(
        id=row["id"],
        scanned_at=datetime.fromisoformat(row["scanned_at"]),
        items=_deserialize_items(row["data"]),
    )
