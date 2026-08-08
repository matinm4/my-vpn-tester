"""پایگاه داده SQLite برای مقیاس صدها هزار کانفیگ.

جایگزین/مکمل کش JSONL برای کوئری‌های سریع top-N، ردیابی سلامت، و
لیست سیاه کانفیگ‌های خراب. حالت WAL برای همزمانی، ایندکس برای سرعت.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .models import ProxyConfig, TestResult

# سقف امن برای تعداد متغیر در یک دستور SQLite
_CHUNK = 900


class ConfigStore:
    """پایگاه داده مرکزی برای کانفیگ‌ها، نتایج تست، و سلامت."""

    def __init__(self, path: Path, blacklist_after: int = 3,
                 blacklist_hours: float = 24.0) -> None:
        self.path = path
        # چند شکست *متوالی* تا تعلیق، و چند ساعت تعلیق بماند
        self.blacklist_after = max(1, int(blacklist_after))
        self.blacklist_hours = max(0.0, float(blacklist_hours))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        """ساخت جداول و ایندکس‌ها در اولین اتصال."""
        conn = self._get_conn()
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-64000")  # 64MB

        # جدول کانفیگ‌ها: هر کانفیگ یکتا با اثر انگشت
        conn.execute("""
            CREATE TABLE IF NOT EXISTS configs (
                fingerprint TEXT PRIMARY KEY,
                protocol TEXT NOT NULL,
                address TEXT NOT NULL,
                port INTEGER NOT NULL,
                remark TEXT NOT NULL,
                config_data TEXT NOT NULL,
                first_seen_at REAL NOT NULL,
                last_seen_at REAL NOT NULL
            )
        """)

        # جدول نتایج تست: چندین رکورد برای هر کانفیگ (تاریخچه)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS test_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                tested_at REAL NOT NULL,
                ok INTEGER NOT NULL,
                latency_ms REAL,
                handshake_ms REAL,
                jitter_ms REAL,
                error TEXT,
                country_code TEXT,
                country TEXT,
                exit_ip TEXT,
                city TEXT,
                isp TEXT,
                asn TEXT,
                stage TEXT,
                result_data TEXT NOT NULL,
                FOREIGN KEY(fingerprint) REFERENCES configs(fingerprint)
            )
        """)

        # جدول سلامت: ردیابی شکست‌های متوالی و لیست سیاه
        conn.execute("""
            CREATE TABLE IF NOT EXISTS health (
                fingerprint TEXT PRIMARY KEY,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                total_tests INTEGER NOT NULL DEFAULT 0,
                total_successes INTEGER NOT NULL DEFAULT 0,
                last_success_at REAL,
                last_failure_at REAL,
                blacklisted_until REAL,
                FOREIGN KEY(fingerprint) REFERENCES configs(fingerprint)
            )
        """)

        # ایندکس‌ها برای کوئری‌های سریع
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_results_tested_at
            ON test_results(tested_at DESC)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_results_fingerprint_tested
            ON test_results(fingerprint, tested_at DESC)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_results_ok_latency
            ON test_results(ok, latency_ms) WHERE ok=1
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_health_blacklist
            ON health(blacklisted_until) WHERE blacklisted_until IS NOT NULL
        """)

        conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                str(self.path),
                check_same_thread=False,
                timeout=30.0,
            )
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    # ------------------------------------------------------------------
    # ثبت کانفیگ و نتایج
    # ------------------------------------------------------------------

    def upsert_config(self, cfg: ProxyConfig, seen_at: Optional[float] = None) -> None:
        """ثبت یا به‌روزرسانی کانفیگ."""
        if seen_at is None:
            seen_at = time.time()

        fp = cfg.fingerprint()
        conn = self._get_conn()
        with self._lock:
            # اگر موجود باشد فقط last_seen_at را عوض کن
            existing = conn.execute(
                "SELECT fingerprint FROM configs WHERE fingerprint=?", (fp,)
            ).fetchone()

            if existing:
                conn.execute(
                    "UPDATE configs SET last_seen_at=?, remark=?, config_data=? WHERE fingerprint=?",
                    (seen_at, cfg.remark, json.dumps(cfg.to_dict(), ensure_ascii=False), fp),
                )
            else:
                conn.execute(
                    """INSERT INTO configs
                       (fingerprint, protocol, address, port, remark, config_data, first_seen_at, last_seen_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        fp,
                        cfg.protocol,
                        cfg.address,
                        cfg.port,
                        cfg.remark,
                        json.dumps(cfg.to_dict(), ensure_ascii=False),
                        seen_at,
                        seen_at,
                    ),
                )
            conn.commit()

    def upsert_configs_batch(self, configs: List[ProxyConfig],
                             seen_at: Optional[float] = None) -> None:
        """درج دسته‌ای کانفیگ‌ها — سریع‌تر از چرخه‌ی تک‌تایی.

        ورودی خودکار تکه‌تکه می‌شود: SQLite سقف تعداد متغیر در هر دستور دارد،
        پس پاس دادن صدها هزار کانفیگ یکجا وگرنه می‌شکست.
        """
        if not configs:
            return
        if seen_at is None:
            seen_at = time.time()

        for start in range(0, len(configs), _CHUNK):
            self._upsert_chunk(configs[start:start + _CHUNK], seen_at)

    def _upsert_chunk(self, configs: List[ProxyConfig], seen_at: float) -> None:
        conn = self._get_conn()
        with self._lock:
            fps = [c.fingerprint() for c in configs]
            placeholders = ",".join(["?"] * len(fps))
            # remark را هم می‌خوانیم تا بفهمیم کانفیگ واقعاً عوض شده یا نه
            existing = {
                row["fingerprint"]: row["remark"]
                for row in conn.execute(
                    f"SELECT fingerprint, remark FROM configs "
                    f"WHERE fingerprint IN ({placeholders})",
                    fps,
                ).fetchall()
            }

            touches = []    # فقط last_seen_at — ارزان
            updates = []    # نام عوض شده، باید config_data هم بازنویسی شود
            inserts = []
            seen_in_chunk: set = set()

            for cfg in configs:
                fp = cfg.fingerprint()
                # یک کانفیگ ممکن است دو بار در همین تکه باشد؛ درج دوباره
                # به خطای کلید تکراری می‌خورد.
                if fp in seen_in_chunk:
                    continue
                seen_in_chunk.add(fp)

                if fp not in existing:
                    inserts.append((
                        fp, cfg.protocol, cfg.address, cfg.port, cfg.remark,
                        json.dumps(cfg.to_dict(), ensure_ascii=False), seen_at, seen_at,
                    ))
                elif existing[fp] == cfg.remark:
                    # هیچ چیز عوض نشده. سریال‌سازی دوباره‌ی کل دیکشنری اینجا
                    # گران‌ترین بخش کار است و در دورهای بعدی اکثر کانفیگ‌ها
                    # دقیقاً همین حالت را دارند.
                    touches.append((seen_at, fp))
                else:
                    updates.append((
                        seen_at, cfg.remark,
                        json.dumps(cfg.to_dict(), ensure_ascii=False), fp,
                    ))

            if touches:
                conn.executemany(
                    "UPDATE configs SET last_seen_at=? WHERE fingerprint=?", touches
                )
            if updates:
                conn.executemany(
                    "UPDATE configs SET last_seen_at=?, remark=?, config_data=? WHERE fingerprint=?",
                    updates,
                )
            if inserts:
                conn.executemany(
                    """INSERT INTO configs
                       (fingerprint, protocol, address, port, remark, config_data, first_seen_at, last_seen_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    inserts,
                )
            conn.commit()

    def record_test_result(self, result: TestResult) -> None:
        """ثبت یک نتیجه تست و به‌روزرسانی سلامت."""
        conn = self._get_conn()
        fp = result.fingerprint
        with self._lock:
            # درج نتیجه
            conn.execute(
                """INSERT INTO test_results
                   (fingerprint, tested_at, ok, latency_ms, handshake_ms, jitter_ms,
                    error, country_code, country, exit_ip, city, isp, asn, stage, result_data)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    fp,
                    result.tested_at,
                    1 if result.ok else 0,
                    result.latency_ms,
                    result.handshake_ms,
                    result.jitter_ms,
                    result.error,
                    result.country_code,
                    result.country,
                    result.exit_ip,
                    result.city,
                    result.isp,
                    result.asn,
                    result.stage,
                    json.dumps(result.to_dict(), ensure_ascii=False),
                ),
            )

            # به‌روزرسانی سلامت
            health = conn.execute(
                "SELECT * FROM health WHERE fingerprint=?", (fp,)
            ).fetchone()

            if health is None:
                # اولین تست
                conn.execute(
                    """INSERT INTO health
                       (fingerprint, consecutive_failures, total_tests, total_successes,
                        last_success_at, last_failure_at, blacklisted_until)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        fp,
                        0 if result.ok else 1,
                        1,
                        1 if result.ok else 0,
                        result.tested_at if result.ok else None,
                        result.tested_at if not result.ok else None,
                        None,
                    ),
                )
            else:
                total_tests = health["total_tests"] + 1
                total_successes = health["total_successes"] + (1 if result.ok else 0)
                consecutive_failures = 0 if result.ok else health["consecutive_failures"] + 1
                last_success_at = result.tested_at if result.ok else health["last_success_at"]
                last_failure_at = result.tested_at if not result.ok else health["last_failure_at"]

                if result.ok:
                    # یک موفقیت پرونده را پاک می‌کند. بدون این، کانفیگی که
                    # قبلاً تعلیق شده و حالا دوباره کار می‌کند تا انقضای تعلیق
                    # از استخر بیرون می‌ماند — با اینکه همین الان سالم است.
                    blacklisted_until = None
                else:
                    blacklisted_until = health["blacklisted_until"]
                    if consecutive_failures >= self.blacklist_after:
                        blacklisted_until = result.tested_at + self.blacklist_hours * 3600

                conn.execute(
                    """UPDATE health SET
                       consecutive_failures=?, total_tests=?, total_successes=?,
                       last_success_at=?, last_failure_at=?, blacklisted_until=?
                       WHERE fingerprint=?""",
                    (consecutive_failures, total_tests, total_successes,
                     last_success_at, last_failure_at, blacklisted_until, fp),
                )

            conn.commit()

    # ------------------------------------------------------------------
    # کوئری نتایج
    # ------------------------------------------------------------------

    def get_latest_result(self, fingerprint: str) -> Optional[TestResult]:
        """آخرین نتیجه تست یک کانفیگ."""
        conn = self._get_conn()
        row = conn.execute(
            """SELECT r.*, c.config_data
               FROM test_results r
               JOIN configs c ON r.fingerprint=c.fingerprint
               WHERE r.fingerprint=?
               ORDER BY r.tested_at DESC LIMIT 1""",
            (fingerprint,),
        ).fetchone()
        return self._row_to_result(row) if row else None

    def get_top_working(self, limit: int = 20, max_age_hours: float = 24.0) -> List[TestResult]:
        """بهترین کانفیگ‌های سالم (کمترین پینگ) که اخیراً تست شده‌اند.

        زیرکوئری عمداً بدون شرط ok است: باید *آخرین* رکورد هر کانفیگ را بگیرد،
        نه آخرین رکورد موفقش. وگرنه کانفیگی که همین الان افتاده، با نتیجه‌ی
        موفق قدیمی‌اش در استخر می‌ماند و هرگز جایگزین نمی‌شود.
        """
        conn = self._get_conn()
        cutoff = time.time() - (max_age_hours * 3600)
        rows = conn.execute(
            """SELECT r.*, c.config_data
               FROM test_results r
               JOIN configs c ON r.fingerprint=c.fingerprint
               JOIN health h ON r.fingerprint=h.fingerprint
               WHERE r.id IN (
                     SELECT MAX(id) FROM test_results GROUP BY fingerprint
                 )
                 AND r.ok=1
                 AND r.tested_at > ?
                 AND (h.blacklisted_until IS NULL OR h.blacklisted_until < ?)
               ORDER BY r.latency_ms ASC
               LIMIT ?""",
            (cutoff, time.time(), limit),
        ).fetchall()
        return [self._row_to_result(row) for row in rows]

    def get_all_working(self, max_age_hours: float = 24.0) -> List[TestResult]:
        """همه‌ی کانفیگ‌های سالم اخیر، مرتب از سریع‌ترین.

        همان منطق get_top_working — فقط آخرین وضعیت هر کانفیگ ملاک است.
        """
        conn = self._get_conn()
        cutoff = time.time() - (max_age_hours * 3600)
        rows = conn.execute(
            """SELECT r.*, c.config_data
               FROM test_results r
               JOIN configs c ON r.fingerprint=c.fingerprint
               JOIN health h ON r.fingerprint=h.fingerprint
               WHERE r.id IN (
                     SELECT MAX(id) FROM test_results GROUP BY fingerprint
                 )
                 AND r.ok=1
                 AND r.tested_at > ?
                 AND (h.blacklisted_until IS NULL OR h.blacklisted_until < ?)
               ORDER BY r.latency_ms ASC""",
            (cutoff, time.time()),
        ).fetchall()
        return [self._row_to_result(row) for row in rows]

    def get_recent_failures(self, limit: int = 500,
                            max_age_hours: float = 24.0) -> List[TestResult]:
        """آخرین کانفیگ‌های ناموفق — برای اینکه گزارش تصویر کامل بدهد."""
        conn = self._get_conn()
        cutoff = time.time() - (max_age_hours * 3600)
        rows = conn.execute(
            """SELECT r.*, c.config_data
               FROM test_results r
               JOIN configs c ON r.fingerprint=c.fingerprint
               WHERE r.id IN (
                     SELECT MAX(id) FROM test_results GROUP BY fingerprint
                 )
                 AND r.ok=0
                 AND r.tested_at > ?
               ORDER BY r.tested_at DESC
               LIMIT ?""",
            (cutoff, limit),
        ).fetchall()
        return [self._row_to_result(row) for row in rows]

    def is_blacklisted(self, fingerprint: str) -> bool:
        """آیا کانفیگ در لیست سیاه است؟"""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT blacklisted_until FROM health WHERE fingerprint=?",
            (fingerprint,),
        ).fetchone()
        if row is None or row["blacklisted_until"] is None:
            return False
        return row["blacklisted_until"] > time.time()

    def get_untested_configs(self, limit: Optional[int] = None) -> List[ProxyConfig]:
        """کانفیگ‌هایی که هرگز تست نشده‌اند.

        کانفیگ‌های تازه‌تر اول می‌آیند: اگر انبار بزرگ باشد، چیزی که همین
        امروز از تلگرام آمده شانس بیشتری از کانفیگ ماه پیش دارد.
        """
        conn = self._get_conn()
        query = """
            SELECT c.config_data
            FROM configs c
            LEFT JOIN test_results r ON c.fingerprint=r.fingerprint
            LEFT JOIN health h ON c.fingerprint=h.fingerprint
            WHERE r.id IS NULL
              AND (h.blacklisted_until IS NULL OR h.blacklisted_until < ?)
            ORDER BY c.first_seen_at DESC
        """
        params: List[Any] = [time.time()]
        if limit:
            query += " LIMIT ?"
            params.append(int(limit))

        rows = conn.execute(query, params).fetchall()
        return [ProxyConfig.from_dict(json.loads(row["config_data"])) for row in rows]

    def count_untested(self) -> int:
        """تعداد کانفیگ‌های هرگز تست‌نشده."""
        conn = self._get_conn()
        row = conn.execute(
            """SELECT COUNT(*) FROM configs c
               LEFT JOIN test_results r ON c.fingerprint=r.fingerprint
               WHERE r.id IS NULL"""
        ).fetchone()
        return int(row[0]) if row else 0

    def get_stale_configs(self, older_than_hours: float = 24.0, limit: Optional[int] = None) -> List[str]:
        """کانفیگ‌هایی که آخرین تستشان قدیمی است (fingerprint)."""
        conn = self._get_conn()
        cutoff = time.time() - (older_than_hours * 3600)
        query = """
            SELECT fingerprint, MAX(tested_at) AS last_test
            FROM test_results
            GROUP BY fingerprint
            HAVING last_test < ?
        """
        if limit:
            query += f" LIMIT {int(limit)}"

        rows = conn.execute(query, (cutoff,)).fetchall()
        return [row["fingerprint"] for row in rows]

    # ------------------------------------------------------------------
    # غنی‌سازی و نگهداری
    # ------------------------------------------------------------------

    def update_geo(self, result: TestResult) -> bool:
        """اطلاعات جغرافیایی آخرین رکورد یک کانفیگ را به‌روز می‌کند.

        غنی‌سازی بعد از تست انجام می‌شود؛ اگر با record_test_result دوباره ثبت
        شود یک ردیف تکراری می‌سازد. در مقیاس صدها هزار کانفیگ این یعنی دو برابر
        شدن حجم جدول، پس به‌جای درج، همان ردیف UPDATE می‌شود.
        """
        conn = self._get_conn()
        with self._lock:
            row = conn.execute(
                "SELECT MAX(id) AS id FROM test_results WHERE fingerprint=?",
                (result.fingerprint,),
            ).fetchone()
            if row is None or row["id"] is None:
                return False

            conn.execute(
                """UPDATE test_results
                   SET country_code=?, country=?, exit_ip=?, city=?, isp=?, asn=?,
                       result_data=?
                   WHERE id=?""",
                (
                    result.country_code,
                    result.country,
                    result.exit_ip,
                    result.city,
                    result.isp,
                    result.asn,
                    json.dumps(result.to_dict(), ensure_ascii=False),
                    row["id"],
                ),
            )
            conn.commit()
            return True

    def prune(self, keep_per_config: int = 5, older_than_days: float = 30.0) -> Dict[str, int]:
        """هرس جدول نتایج تا در مقیاس بالا از کنترل خارج نشود.

        دو قانون: برای هر کانفیگ فقط N رکورد آخر بماند، و هر رکوردی که از
        older_than_days گذشته حذف شود. آخرین رکورد هر کانفیگ همیشه حفظ می‌شود
        حتی اگر قدیمی باشد — وگرنه تاریخچه‌ی سلامت را از دست می‌دهیم.
        """
        conn = self._get_conn()
        removed_old = 0
        removed_excess = 0

        with self._lock:
            cutoff = time.time() - (older_than_days * 86400)
            cur = conn.execute(
                """DELETE FROM test_results
                   WHERE tested_at < ?
                     AND id NOT IN (SELECT MAX(id) FROM test_results GROUP BY fingerprint)""",
                (cutoff,),
            )
            removed_old = cur.rowcount or 0

            # برای هر کانفیگ فقط N رکورد آخر
            cur = conn.execute(
                """DELETE FROM test_results
                   WHERE id NOT IN (
                       SELECT id FROM (
                           SELECT id,
                                  ROW_NUMBER() OVER (
                                      PARTITION BY fingerprint ORDER BY id DESC
                                  ) AS rn
                           FROM test_results
                       )
                       WHERE rn <= ?
                   )""",
                (max(1, keep_per_config),),
            )
            removed_excess = cur.rowcount or 0

            conn.commit()

        return {"removed_old": removed_old, "removed_excess": removed_excess}

    def vacuum(self) -> None:
        """فشرده‌سازی فایل پایگاه داده بعد از هرس سنگین."""
        with self._lock:
            self._get_conn().execute("VACUUM")

    # ------------------------------------------------------------------
    # مهاجرت از JSONL
    # ------------------------------------------------------------------

    def migrate_from_jsonl(self, jsonl_path: Path) -> Tuple[int, int]:
        """خواندن کش JSONL قدیمی و درج در SQLite. (تعداد_موفق، تعداد_ناموفق)"""
        if not jsonl_path.exists():
            return 0, 0

        imported = 0
        skipped = 0
        conn = self._get_conn()

        with open(jsonl_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    result = TestResult.from_dict(record)
                    if not result.config:
                        skipped += 1
                        continue

                    cfg = ProxyConfig.from_dict(result.config)

                    # ثبت کانفیگ اگر موجود نیست
                    with self._lock:
                        exists = conn.execute(
                            "SELECT 1 FROM configs WHERE fingerprint=?", (result.fingerprint,)
                        ).fetchone()
                        if not exists:
                            conn.execute(
                                """INSERT INTO configs
                                   (fingerprint, protocol, address, port, remark, config_data,
                                    first_seen_at, last_seen_at)
                                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                                (
                                    result.fingerprint,
                                    cfg.protocol,
                                    cfg.address,
                                    cfg.port,
                                    cfg.remark,
                                    json.dumps(cfg.to_dict(), ensure_ascii=False),
                                    result.tested_at,
                                    result.tested_at,
                                ),
                            )

                    self.record_test_result(result)
                    imported += 1

                except (json.JSONDecodeError, KeyError, TypeError):
                    skipped += 1
                    continue

        conn.commit()
        return imported, skipped

    # ------------------------------------------------------------------
    # کمکی
    # ------------------------------------------------------------------

    def _row_to_result(self, row: sqlite3.Row) -> TestResult:
        """بازسازی نتیجه از result_data — همه‌ی فیلدها بدون افت حفظ می‌شوند.

        ستون‌های جداگانه فقط برای ایندکس و کوئری هستند؛ منبع حقیقت همان
        JSON کامل است، پس افزودن فیلد جدید به TestResult اینجا را نمی‌شکند.
        """
        result = TestResult.from_dict(json.loads(row["result_data"]))
        # نام کانفیگ ممکن است در منبع تازه‌تر عوض شده باشد
        result.config = json.loads(row["config_data"])
        return result

    def get_stats(self) -> Dict[str, Any]:
        """آمار کلی پایگاه داده."""
        conn = self._get_conn()
        total_configs = conn.execute("SELECT COUNT(*) FROM configs").fetchone()[0]
        total_results = conn.execute("SELECT COUNT(*) FROM test_results").fetchone()[0]
        blacklisted_now = conn.execute(
            "SELECT COUNT(*) FROM health WHERE blacklisted_until > ?", (time.time(),)
        ).fetchone()[0]
        return {
            "total_configs": total_configs,
            "total_results": total_results,
            "blacklisted": blacklisted_now,
        }
