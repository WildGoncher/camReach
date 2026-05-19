"""
SQLite database module for camera status history.
"""

import sqlite3
import logging
import pandas as pd

from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

DB_PATH = Path("data") / "camera_history.db"


def init_db():
    """Initialize database and create tables if not exist."""
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS camera_status_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            camera_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_camera_time 
        ON camera_status_history(camera_id, changed_at)
    """)
    conn.commit()
    conn.close()
    logger.info(f"🗄️ Database initialized at {DB_PATH}")


def log_status_change(camera_id: int, status: str):
    try:
        DB_PATH.parent.mkdir(exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO camera_status_history (camera_id, status) VALUES (?, ?)",
            (camera_id, status),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"❌ Failed to log status change: {e}")


def get_camera_history(camera_id: int, days: int = 7) -> List[Dict]:
    try:
        if not DB_PATH.exists():
            return []
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        since = datetime.now() - timedelta(days=days)
        cursor.execute(
            """
            SELECT camera_id, status, changed_at 
            FROM camera_status_history 
            WHERE camera_id = ? AND changed_at >= ?
            ORDER BY changed_at ASC
        """,
            (camera_id, since.isoformat()),
        )
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return results
    except Exception as e:
        logger.error(f"❌ Failed to get history: {e}")
        return []


def get_camera_uptime(camera_id: int, days: int = 7) -> Dict:
    history = get_camera_history(camera_id, days)
    if not history:
        return {
            "uptime_percent": 0,
            "total_changes": 0,
            "period_days": days,
            "online_seconds": 0,
            "offline_seconds": 0,
        }
    total_seconds = days * 24 * 3600
    online_seconds = 0
    for i in range(len(history) - 1):
        curr = history[i]
        next_ = history[i + 1]
        curr_time = datetime.fromisoformat(curr["changed_at"])
        next_time = datetime.fromisoformat(next_["changed_at"])
        duration = (next_time - curr_time).total_seconds()
        if curr["status"] == "online":
            online_seconds += duration
    last = history[-1]
    last_time = datetime.fromisoformat(last["changed_at"])
    remaining = (datetime.now() - last_time).total_seconds()
    if last["status"] == "online":
        online_seconds += remaining
    uptime_percent = (
        round((online_seconds / total_seconds) * 100, 1) if total_seconds > 0 else 0
    )
    return {
        "uptime_percent": uptime_percent,
        "total_changes": len(history),
        "period_days": days,
        "online_seconds": round(online_seconds / 3600, 1),
        "offline_seconds": round((total_seconds - online_seconds) / 3600, 1),
    }


def get_all_cameras_summary(days: int = 7) -> List[Dict]:
    try:
        if not DB_PATH.exists():
            return []
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        since = datetime.now() - timedelta(days=days)
        cursor.execute(
            """
            SELECT DISTINCT camera_id FROM camera_status_history 
            WHERE changed_at >= ?
        """,
            (since.isoformat(),),
        )
        camera_ids = [row[0] for row in cursor.fetchall()]
        conn.close()
        return [
            {"camera_id": cid, **get_camera_uptime(cid, days)} for cid in camera_ids
        ]
    except Exception as e:
        logger.error(f"❌ Failed to get summary: {e}")
        return []


def generate_report_data(cameras: List[Dict], days: int = 7) -> pd.DataFrame:
    rows = []
    for cam in cameras:
        cid = cam.get("id")
        if not cid:
            continue
        stats = get_camera_uptime(cid, days)
        name = cam.get("name", f"Camera {cid}")
        obj = cam.get("object", "N/A")
        loc = cam.get("location", "N/A")
        rows.append(
            {
                "ID": cid,
                "Название": name,
                "Объект": obj,
                "Расположение": loc,
                "Uptime (%)": stats["uptime_percent"],
                "Онлайн (часы)": stats["online_seconds"],
                "Офлайн (часы)": stats["offline_seconds"],
                "Всего смен статуса": stats["total_changes"],
                "Период (дни)": stats["period_days"],
            }
        )
    return pd.DataFrame(rows)
