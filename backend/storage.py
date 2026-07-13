"""
SecretNode v2.0 — storage.py
Lightweight SQLite persistence for scan history and findings.
Uses aiosqlite (already a declared dependency, previously unused) so scan
results survive a server restart — needed for agency-grade audit trails.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import aiosqlite

DB_PATH = Path(__file__).parent / "data" / "secretnode.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id             TEXT PRIMARY KEY,
    target_url          TEXT NOT NULL,
    status               TEXT NOT NULL,
    assets_fetched       INTEGER DEFAULT 0,
    raw_findings         INTEGER DEFAULT 0,
    validated_findings   INTEGER DEFAULT 0,
    confirmed_count       INTEGER DEFAULT 0,
    confirmed_findings_json TEXT,
    needs_review_count      INTEGER DEFAULT 0,
    needs_review_findings_json TEXT,
    new_findings_count      INTEGER DEFAULT 0,
    recurring_findings_count INTEGER DEFAULT 0,
    duration_seconds     REAL DEFAULT 0,
    created_at            TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_target_url ON scans (target_url);

CREATE TABLE IF NOT EXISTS false_positives (
    fingerprint  TEXT PRIMARY KEY,
    target_url   TEXT NOT NULL,
    secret_type  TEXT,
    source_url   TEXT,
    note         TEXT,
    marked_at    TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_fp_target ON false_positives (target_url);
"""


async def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(_SCHEMA)
        await db.commit()


async def save_scan(scan_id: str, result: dict[str, Any]) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO scans (
                scan_id, target_url, status, assets_fetched, raw_findings,
                validated_findings, confirmed_count, confirmed_findings_json,
                needs_review_count, needs_review_findings_json,
                new_findings_count, recurring_findings_count, duration_seconds
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                status=excluded.status,
                assets_fetched=excluded.assets_fetched,
                raw_findings=excluded.raw_findings,
                validated_findings=excluded.validated_findings,
                confirmed_count=excluded.confirmed_count,
                confirmed_findings_json=excluded.confirmed_findings_json,
                needs_review_count=excluded.needs_review_count,
                needs_review_findings_json=excluded.needs_review_findings_json,
                new_findings_count=excluded.new_findings_count,
                recurring_findings_count=excluded.recurring_findings_count,
                duration_seconds=excluded.duration_seconds
            """,
            (
                scan_id,
                result.get("target_url", ""),
                result.get("status", "unknown"),
                result.get("assets_fetched", 0),
                result.get("raw_findings", 0),
                result.get("validated_findings", 0),
                len(result.get("confirmed_findings", [])),
                json.dumps(result.get("confirmed_findings", [])),
                len(result.get("needs_review_findings", [])),
                json.dumps(result.get("needs_review_findings", [])),
                result.get("new_findings_count", 0),
                result.get("recurring_findings_count", 0),
                result.get("duration_seconds", 0.0),
            ),
        )
        await db.commit()


def _row_to_dict(row: aiosqlite.Row) -> dict[str, Any]:
    d = dict(row)
    findings_json = d.pop("confirmed_findings_json", None)
    d["confirmed_findings"] = json.loads(findings_json) if findings_json else []
    review_json = d.pop("needs_review_findings_json", None)
    d["needs_review_findings"] = json.loads(review_json) if review_json else []
    return d


async def get_previous_scan_for_target(target_url: str, exclude_scan_id: str) -> dict[str, Any] | None:
    """Most recent *completed* scan of this exact target_url, excluding the
    current in-progress one. Used to diff new vs recurring findings."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """
            SELECT * FROM scans
            WHERE target_url = ? AND scan_id != ? AND status = 'complete'
            ORDER BY created_at DESC LIMIT 1
            """,
            (target_url, exclude_scan_id),
        )
        row = await cursor.fetchone()
        return _row_to_dict(row) if row else None


# ── False-positive suppression ──────────────────────────────────────────────

async def mark_false_positive(
    fingerprint: str, target_url: str, secret_type: str, source_url: str, note: str = "",
) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO false_positives (fingerprint, target_url, secret_type, source_url, note)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint) DO UPDATE SET note=excluded.note
            """,
            (fingerprint, target_url, secret_type, source_url, note),
        )
        await db.commit()


async def unmark_false_positive(fingerprint: str) -> bool:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("DELETE FROM false_positives WHERE fingerprint = ?", (fingerprint,))
        await db.commit()
        return cursor.rowcount > 0


async def get_suppressed_fingerprints(target_url: str) -> frozenset[str]:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT fingerprint FROM false_positives WHERE target_url = ?", (target_url,)
        )
        rows = await cursor.fetchall()
        return frozenset(r[0] for r in rows)


async def list_false_positives(limit: int = 200) -> list[dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM false_positives ORDER BY marked_at DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def load_scans(limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = await cursor.fetchall()
        return [_row_to_dict(r) for r in rows]


async def load_scan(scan_id: str) -> dict[str, Any] | None:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        row = await cursor.fetchone()
        return _row_to_dict(row) if row else None
