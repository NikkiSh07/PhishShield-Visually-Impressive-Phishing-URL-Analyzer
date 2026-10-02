"""
PhishShield — MySQL Database Layer
===================================
Provides connection management and CRUD helpers for Flask backend.
Uses mysql-connector-python.

Configure via environment variables or hardcode below for development:
  PHISHSHIELD_DB_HOST   (default: localhost)
  PHISHSHIELD_DB_PORT   (default: 3306)
  PHISHSHIELD_DB_USER   (default: root)
  PHISHSHIELD_DB_PASS   (default: password)
  PHISHSHIELD_DB_NAME   (default: phishshield)
"""

import os
import logging
from datetime import datetime, date
from typing import Optional, List, Dict, Any

try:
    import mysql.connector
    from mysql.connector import pooling
    HAS_MYSQL = True
except ImportError:
    HAS_MYSQL = False

logger = logging.getLogger("phishshield.db")

# ── DB config ─────────────────────────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.environ.get("PHISHSHIELD_DB_HOST", "localhost"),
    "port":     int(os.environ.get("PHISHSHIELD_DB_PORT", "3306")),
    "user":     os.environ.get("PHISHSHIELD_DB_USER", "root"),
    "password": os.environ.get("PHISHSHIELD_DB_PASS", "password"),
    "database": os.environ.get("PHISHSHIELD_DB_NAME", "phishshield"),
    "charset":  "utf8mb4",
}

_pool: Optional[Any] = None


def _get_pool():
    """Create connection pool on first call."""
    global _pool
    if _pool is None and HAS_MYSQL:
        try:
            _pool = pooling.MySQLConnectionPool(
                pool_name="phishshield_pool",
                pool_size=5,
                **DB_CONFIG
            )
            logger.info("MySQL connection pool created.")
        except Exception as e:
            logger.error(f"MySQL pool error: {e}")
            _pool = None
    return _pool


def db_available() -> bool:
    """Return True if MySQL is reachable."""
    pool = _get_pool()
    if pool is None:
        return False
    try:
        conn = pool.get_connection()
        conn.close()
        return True
    except Exception:
        return False


def _get_conn():
    pool = _get_pool()
    if pool is None:
        raise RuntimeError("MySQL not available")
    return pool.get_connection()


# ─────────────────────────────────────────────────────────────────────────────
# Write helpers
# ─────────────────────────────────────────────────────────────────────────────

def save_scan(result: Dict[str, Any], client_ip: str = None) -> Optional[int]:
    """
    Persist a full analysis result to MySQL.
    Returns the new scan_logs.id, or None on failure.
    """
    if not db_available():
        return None
    try:
        conn = _get_conn()
        cur = conn.cursor()

        # Extract WHOIS data
        whois = result.get("whois") or {}
        age_days = whois.get("age_days")
        creation_str = whois.get("creation_date")
        created_date = None
        if creation_str:
            try:
                created_date = datetime.fromisoformat(creation_str[:10]).date()
            except Exception:
                pass

        # Extract ML data
        ml = result.get("ml") or {}
        ml_score = ml.get("score")
        ml_label = ml.get("label")
        ml_prob  = ml.get("prob")

        # Extract Java features
        java = result.get("java") or {}
        java_entropy      = java.get("entropy")
        java_digit_ratio  = java.get("digitRatio")
        java_special      = java.get("specialChars")
        java_ngram        = java.get("ngramScore")

        # ── Insert scan_logs ─────────────────────────────────────────────────
        cur.execute("""
            INSERT INTO scan_logs
              (url, hostname, score, level, color, description,
               dns_resolves, whois_age, whois_created,
               ml_score, ml_label, ml_prob,
               java_entropy, java_digit_ratio, java_special_chars, java_ngram_score,
               client_ip, analyzed_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            result.get("raw", ""),
            result.get("hostname", ""),
            int(result.get("score", 0)),
            result.get("level", "LOW RISK"),
            result.get("color", "#00E676"),
            result.get("desc", ""),
            1 if result.get("dns_resolves") else (0 if result.get("dns_resolves") is False else None),
            age_days,
            created_date,
            ml_score,
            ml_label,
            ml_prob,
            java_entropy,
            java_digit_ratio,
            java_special,
            java_ngram,
            client_ip,
            datetime.utcnow()
        ))
        scan_id = cur.lastrowid

        # ── Insert scan_signals ──────────────────────────────────────────────
        reasons = result.get("reasons", [])
        for i, r in enumerate(reasons):
            cur.execute("""
                INSERT INTO scan_signals (scan_id, signal_text, points, type, icon, sort_order)
                VALUES (%s,%s,%s,%s,%s,%s)
            """, (
                scan_id,
                _strip_html(r.get("text", "")),
                int(r.get("points", 0)),
                r.get("type", "neutral"),
                r.get("icon", "—"),
                i
            ))

        # ── Insert scan_breakdown ────────────────────────────────────────────
        breakdown = result.get("breakdown", [])
        for b in breakdown:
            cur.execute("""
                INSERT INTO scan_breakdown (scan_id, name, pts, max_pts)
                VALUES (%s,%s,%s,%s)
            """, (
                scan_id,
                b.get("name", ""),
                int(b.get("pts", 0)),
                int(b.get("max", 0))
            ))

        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"Saved scan #{scan_id} — {result.get('hostname')} score={result.get('score')}")
        return scan_id

    except Exception as e:
        logger.error(f"save_scan error: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Read helpers
# ─────────────────────────────────────────────────────────────────────────────

def get_history(limit: int = 20, offset: int = 0) -> List[Dict]:
    """Return last N scans (most recent first)."""
    if not db_available():
        return []
    try:
        conn = _get_conn()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT id, hostname, score, level, color, analyzed_at,
                   ml_score, java_entropy, java_ngram_score
            FROM scan_logs
            ORDER BY analyzed_at DESC
            LIMIT %s OFFSET %s
        """, (limit, offset))
        rows = cur.fetchall()
        cur.close()
        conn.close()
        # Convert datetime to ISO string for JSON
        for r in rows:
            if isinstance(r.get("analyzed_at"), datetime):
                r["analyzed_at"] = r["analyzed_at"].isoformat()
        return rows
    except Exception as e:
        logger.error(f"get_history error: {e}")
        return []


def get_stats() -> Dict:
    """Return aggregate statistics."""
    if not db_available():
        return {}
    try:
        conn = _get_conn()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT
                COUNT(*)                       AS total_scans,
                ROUND(AVG(score), 1)           AS avg_score,
                SUM(level = 'HIGH RISK')       AS high_risk,
                SUM(level = 'MEDIUM RISK')     AS medium_risk,
                SUM(level = 'LOW RISK')        AS low_risk,
                MAX(analyzed_at)               AS last_scan
            FROM scan_logs
        """)
        row = cur.fetchone()
        cur.close()
        conn.close()
        if row and row.get("last_scan"):
            row["last_scan"] = row["last_scan"].isoformat()
        return row or {}
    except Exception as e:
        logger.error(f"get_stats error: {e}")
        return {}


def get_scan_detail(scan_id: int) -> Optional[Dict]:
    """Return full detail for a single scan including signals and breakdown."""
    if not db_available():
        return None
    try:
        conn = _get_conn()
        cur = conn.cursor(dictionary=True)

        cur.execute("SELECT * FROM scan_logs WHERE id=%s", (scan_id,))
        scan = cur.fetchone()
        if not scan:
            return None

        cur.execute("""
            SELECT signal_text, points, type, icon
            FROM scan_signals WHERE scan_id=%s ORDER BY sort_order
        """, (scan_id,))
        scan["signals"] = cur.fetchall()

        cur.execute("""
            SELECT name, pts, max_pts
            FROM scan_breakdown WHERE scan_id=%s
        """, (scan_id,))
        scan["breakdown"] = cur.fetchall()

        cur.close()
        conn.close()

        if isinstance(scan.get("analyzed_at"), datetime):
            scan["analyzed_at"] = scan["analyzed_at"].isoformat()
        if isinstance(scan.get("whois_created"), date):
            scan["whois_created"] = scan["whois_created"].isoformat()
        return scan
    except Exception as e:
        logger.error(f"get_scan_detail error: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def _strip_html(text: str) -> str:
    """Remove HTML tags for plain-text DB storage."""
    import re
    return re.sub(r"<[^>]+>", "", text)
