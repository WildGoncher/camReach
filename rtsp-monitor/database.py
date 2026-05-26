"""
SQLite database module for camera status history.
Hybrid storage: raw events for last 30 days, daily aggregates for older data.
Supports uptime reports up to 1 year.
"""

import sqlite3
import logging
import pandas as pd

from datetime import datetime, timedelta, date
from pathlib import Path
from typing import List, Dict

logger = logging.getLogger(__name__)

DB_PATH = Path("data") / "camera_history.db"

# Сырые события храним 30 дней, агрегаты — бессрочно
RAW_RETENTION_DAYS = 30


# =============================================================================
# INIT
# =============================================================================


def init_db():
    """Initialize database and create all tables."""
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Сырые события (статус изменился)
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

    # Суточные агрегаты (для данных старше RAW_RETENTION_DAYS)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS camera_uptime_daily (
            camera_id  INTEGER NOT NULL,
            date       TEXT    NOT NULL,   -- 'YYYY-MM-DD'
            online_seconds  REAL DEFAULT 0,
            offline_seconds REAL DEFAULT 0,
            total_changes   INTEGER DEFAULT 0,
            PRIMARY KEY (camera_id, date)
        )
    """)

    conn.commit()
    conn.close()
    logger.info(f"🗄️ Database initialized at {DB_PATH}")


# =============================================================================
# WRITE
# =============================================================================


def log_status_change(camera_id: int, status: str):
    try:
        DB_PATH.parent.mkdir(exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO camera_status_history (camera_id, status) VALUES (?, ?)",
            (camera_id, status),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"❌ Failed to log status change: {e}")


# =============================================================================
# AGGREGATION & CLEANUP
# =============================================================================


def _compute_online_seconds_for_events(
    events: list, day_start: datetime, day_end: datetime
) -> float:
    """
    Считает секунды онлайн внутри окна [day_start, day_end]
    по списку событий вида [{'status': ..., 'changed_at': ...}, ...].
    """
    if not events:
        return 0.0

    online_seconds = 0.0

    for i, ev in enumerate(events):
        if ev["status"] != "online":
            continue

        period_start = max(datetime.fromisoformat(ev["changed_at"]), day_start)
        # Конец периода — следующее событие или конец дня
        if i + 1 < len(events):
            period_end = min(
                datetime.fromisoformat(events[i + 1]["changed_at"]), day_end
            )
        else:
            period_end = day_end

        if period_end > period_start:
            online_seconds += (period_end - period_start).total_seconds()

    return online_seconds


def aggregate_and_cleanup():
    """
    Агрегирует сырые события старше RAW_RETENTION_DAYS в суточные срезы,
    затем удаляет их из camera_status_history.
    Вызывать раз в сутки из session_cleanup_loop.
    """
    if not DB_PATH.exists():
        return

    cutoff = datetime.now() - timedelta(days=RAW_RETENTION_DAYS)

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Все камеры с устаревшими сырыми данными
        cursor.execute(
            "SELECT DISTINCT camera_id FROM camera_status_history WHERE changed_at < ?",
            (cutoff.isoformat(),),
        )
        camera_ids = [r[0] for r in cursor.fetchall()]

        total_deleted = 0

        for cam_id in camera_ids:
            # Берём все события до cutoff + одно событие после (чтобы знать статус на границе)
            cursor.execute(
                """
                SELECT status, changed_at FROM camera_status_history
                WHERE camera_id = ? AND changed_at < ?
                ORDER BY changed_at ASC
                """,
                (cam_id, cutoff.isoformat()),
            )
            old_events = [dict(r) for r in cursor.fetchall()]

            if not old_events:
                continue

            # Первое и последнее дни периода
            first_dt = datetime.fromisoformat(old_events[0]["changed_at"])
            last_dt = datetime.fromisoformat(old_events[-1]["changed_at"])

            current_day = first_dt.date()
            end_day = min(last_dt.date(), cutoff.date() - timedelta(days=1))

            while current_day <= end_day:
                day_start = datetime.combine(current_day, datetime.min.time())
                day_end = day_start + timedelta(days=1)

                # События внутри суток (и одно предшествующее для контекста статуса)
                day_events = [
                    e
                    for e in old_events
                    if datetime.fromisoformat(e["changed_at"]) < day_end
                ]

                online_sec = _compute_online_seconds_for_events(
                    day_events, day_start, day_end
                )
                offline_sec = 86400.0 - online_sec

                # Смены статуса именно в этот день
                changes_today = sum(
                    1
                    for e in old_events
                    if day_start <= datetime.fromisoformat(e["changed_at"]) < day_end
                )

                conn.execute(
                    """
                    INSERT INTO camera_uptime_daily
                        (camera_id, date, online_seconds, offline_seconds, total_changes)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(camera_id, date) DO UPDATE SET
                        online_seconds  = excluded.online_seconds,
                        offline_seconds = excluded.offline_seconds,
                        total_changes   = excluded.total_changes
                    """,
                    (
                        cam_id,
                        current_day.isoformat(),
                        online_sec,
                        offline_sec,
                        changes_today,
                    ),
                )

                current_day += timedelta(days=1)

            # Удаляем сырые данные этой камеры старше cutoff
            cursor.execute(
                "DELETE FROM camera_status_history WHERE camera_id = ? AND changed_at < ?",
                (cam_id, cutoff.isoformat()),
            )
            total_deleted += cursor.rowcount

        conn.execute("VACUUM")
        conn.commit()
        conn.close()

        if total_deleted:
            logger.info(
                f"🧹 Aggregation done: removed {total_deleted} raw rows "
                f"for {len(camera_ids)} cameras (kept daily aggregates)"
            )

    except Exception as e:
        logger.error(f"❌ aggregate_and_cleanup failed: {e}")


# =============================================================================
# READ — hybrid (raw + aggregates)
# =============================================================================


def get_camera_history(camera_id: int, days: int = 7) -> List[Dict]:
    """Возвращает сырые события за последние `days` дней (только из raw таблицы)."""
    try:
        if not DB_PATH.exists():
            return []
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        since = datetime.now() - timedelta(days=days)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT camera_id, status, changed_at
            FROM camera_status_history
            WHERE camera_id = ? AND changed_at >= ?
            ORDER BY changed_at ASC
            """,
            (camera_id, since.isoformat()),
        )
        results = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return results
    except Exception as e:
        logger.error(f"❌ Failed to get history: {e}")
        return []


def get_camera_uptime(camera_id: int, days: int = 7) -> Dict:
    """
    Считает uptime за `days` дней.
    Для периода > RAW_RETENTION_DAYS берёт суточные агрегаты + сырые данные,
    склеивая их вместе.
    """
    now = datetime.now()
    since = now - timedelta(days=days)
    total_seconds = days * 86400.0

    online_seconds = 0.0
    total_changes = 0

    try:
        if not DB_PATH.exists():
            return _empty_uptime(days)

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # --- 1. Суточные агрегаты для старой части периода ---
        agg_end = now - timedelta(days=RAW_RETENTION_DAYS)
        if since < agg_end:
            cursor.execute(
                """
                SELECT date, online_seconds, total_changes
                FROM camera_uptime_daily
                WHERE camera_id = ? AND date >= ? AND date < ?
                ORDER BY date ASC
                """,
                (
                    camera_id,
                    since.date().isoformat(),
                    agg_end.date().isoformat(),
                ),
            )
            for row in cursor.fetchall():
                day_start = datetime.combine(
                    date.fromisoformat(row["date"]), datetime.min.time()
                )
                day_end = day_start + timedelta(days=1)

                # Обрезаем по границам запрошенного периода
                effective_start = max(day_start, since)
                effective_end = min(day_end, agg_end)
                day_fraction = (
                    effective_end - effective_start
                ).total_seconds() / 86400.0

                online_seconds += row["online_seconds"] * day_fraction
                total_changes += row["total_changes"]

        # --- 2. Сырые события для свежей части ---
        raw_since = max(since, now - timedelta(days=RAW_RETENTION_DAYS))
        cursor.execute(
            """
            SELECT status, changed_at
            FROM camera_status_history
            WHERE camera_id = ? AND changed_at >= ?
            ORDER BY changed_at ASC
            """,
            (camera_id, raw_since.isoformat()),
        )
        raw_events = [dict(r) for r in cursor.fetchall()]
        conn.close()

        if raw_events:
            total_changes += len(raw_events)
            online_seconds += _compute_online_seconds_for_events(
                raw_events, raw_since, now
            )

    except Exception as e:
        logger.error(f"❌ get_camera_uptime failed: {e}")
        return _empty_uptime(days)

    uptime_percent = (
        round((online_seconds / total_seconds) * 100, 1) if total_seconds > 0 else 0.0
    )
    uptime_percent = max(0.0, min(100.0, uptime_percent))

    return {
        "uptime_percent": uptime_percent,
        "total_changes": total_changes,
        "period_days": days,
        "online_seconds": round(online_seconds / 3600, 1),
        "offline_seconds": round((total_seconds - online_seconds) / 3600, 1),
    }


def _empty_uptime(days: int) -> Dict:
    return {
        "uptime_percent": 0.0,
        "total_changes": 0,
        "period_days": days,
        "online_seconds": 0.0,
        "offline_seconds": round(days * 24, 1),
    }


# =============================================================================
# SUMMARY & REPORTS
# =============================================================================


def get_all_cameras_summary(days: int = 7) -> List[Dict]:
    """Возвращает uptime по всем камерам с данными за период."""
    try:
        if not DB_PATH.exists():
            return []

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        since = datetime.now() - timedelta(days=days)

        # Камеры из сырых событий
        cursor.execute(
            "SELECT DISTINCT camera_id FROM camera_status_history WHERE changed_at >= ?",
            (since.isoformat(),),
        )
        raw_ids = {r[0] for r in cursor.fetchall()}

        # Камеры из агрегатов (для длинных периодов)
        cursor.execute(
            "SELECT DISTINCT camera_id FROM camera_uptime_daily WHERE date >= ?",
            (since.date().isoformat(),),
        )
        agg_ids = {r[0] for r in cursor.fetchall()}

        conn.close()

        camera_ids = raw_ids | agg_ids
        return [
            {"camera_id": cid, **get_camera_uptime(cid, days)}
            for cid in sorted(camera_ids)
        ]

    except Exception as e:
        logger.error(f"❌ get_all_cameras_summary failed: {e}")
        return []


def generate_report_data(cameras: List[Dict], days: int = 7) -> pd.DataFrame:
    rows = []
    for cam in cameras:
        cid = cam.get("id")
        if not cid:
            continue
        stats = get_camera_uptime(cid, days)
        rows.append(
            {
                "ID": cid,
                "Название": cam.get("name", f"Camera {cid}"),
                "Объект": cam.get("object", "N/A"),
                "Расположение": cam.get("location", "N/A"),
                "Uptime (%)": stats["uptime_percent"],
                "Онлайн (часы)": stats["online_seconds"],
                "Офлайн (часы)": stats["offline_seconds"],
                "Всего смен статуса": stats["total_changes"],
                "Период (дни)": stats["period_days"],
            }
        )
    return pd.DataFrame(rows)
