"""
SQLite History Service for PhishGuard-AI.
Persists anonymized/truncated scan records locally for audit and review.
"""

import sqlite3
import datetime
from typing import List, Dict, Any, Optional
from backend.app.config import SQLITE_DB_PATH


def get_connection() -> sqlite3.Connection:
    SQLITE_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(SQLITE_DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create scan records table if not already existing."""
    try:
        with get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    input_preview TEXT NOT NULL,
                    probability REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    timestamp TEXT NOT NULL
                )
            """)
            conn.commit()
    except Exception:
        # Non-fatal if filesystem is restricted or read-only
        pass


def log_scan(
    scan_type: str,
    input_text: str,
    probability: float,
    risk_level: str,
    confidence: float
) -> int:
    """Log a scan result to SQLite and return inserted ID."""
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    preview = input_text[:120] + ("..." if len(input_text) > 120 else "")

    try:
        with get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scan_records (scan_type, input_preview, probability, risk_level, confidence, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (scan_type, preview, probability, risk_level, confidence, now_str)
            )
            conn.commit()
            return cursor.lastrowid or 0
    except Exception:
        return 0


def get_recent_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve recent scans ordered by ID descending."""
    try:
        with get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, scan_type, input_preview, probability, risk_level, confidence, timestamp
                FROM scan_records
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,)
            )
            rows = cursor.fetchall()
            return [
                {
                    "id": row["id"],
                    "scan_type": row["scan_type"],
                    "input_preview": row["input_preview"],
                    "probability": round(row["probability"], 4),
                    "risk_level": row["risk_level"],
                    "confidence_percentage": round(row["confidence"], 1),
                    "timestamp": row["timestamp"]
                }
                for row in rows
            ]
    except Exception:
        return []
