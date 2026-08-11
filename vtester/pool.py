"""مدیریت استخر بهترین کانفیگ‌ها و خروجی‌های دسته‌ای.

استخر یعنی N کانفیگ برتر که همیشه زنده نگه داشته می‌شوند: هر بار بازبینی،
هرکدام که مرده باشد فوراً با بهترین جایگزین بعدی عوض می‌شود.
"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .models import TestResult
from .sanitize import sanitize_result_link


@dataclass
class PoolChange:
    """یک تغییر در ترکیب استخر — برای تاریخچه."""

    at: float
    action: str          # added | removed | replaced
    fingerprint: str
    name: str
    latency_ms: Optional[float] = None
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "at": self.at,
            "at_human": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.at)),
            "action": self.action,
            "fingerprint": self.fingerprint,
            "name": self.name,
            "latency_ms": self.latency_ms,
            "reason": self.reason,
        }


class PoolManager:
    """استخر N کانفیگ برتر + خروجی‌های دسته‌ای."""

    def __init__(self, settings, logger, store) -> None:
        self.settings = settings
        self.log = logger
        self.store = store

        self.size = max(1, int(settings.get("pool.size", 20)))
        self.batch_size = max(1, int(settings.get("pool.batch_size", 20)))
        self.max_batches = int(settings.get("pool.max_batches", 0))
        self.max_age_hours = float(settings.get("pool.max_age_hours", 24))
        self.history_limit = int(settings.get("pool.history_limit", 2000))

        self.out_dir = settings.path_of("output.dir")
        self.history_path = self.out_dir / str(settings.get("pool.history_file", "pool_history.json"))

        # نام کانفیگ‌ها پیش از خروجی بازنویسی می‌شود تا تبلیغ و آی‌دی تلگرام
        # منبع به کلاینت کاربر نرسد. خاموش‌کردنش نام اصلی منبع را برمی‌گرداند.
        self.clean_names = bool(settings.get("output.clean_names", False))
        self.name_tag = str(settings.get("output.name_tag", "") or "")

        self._current: List[str] = []          # اثر انگشت اعضای فعلی
        self._history: List[PoolChange] = []
        self._load_history()

    # ------------------------------------------------------------------

    def _load_history(self) -> None:
        if not self.history_path.exists():
            return
        try:
            with open(self.history_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self._current = list(data.get("current_fingerprints") or [])
            for entry in (data.get("changes") or [])[-self.history_limit:]:
                self._history.append(PoolChange(
                    at=float(entry.get("at", 0)),
                    action=str(entry.get("action", "")),
                    fingerprint=str(entry.get("fingerprint", "")),
                    name=str(entry.get("name", "")),
                    latency_ms=entry.get("latency_ms"),
                    reason=str(entry.get("reason", "")),
                ))
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            self.log.warn(f"تاریخچه‌ی استخر خوانده نشد ({type(exc).__name__}) — از نو شروع می‌شود")
            self._current = []
            self._history = []

    def _save_history(self, members: Sequence[TestResult]) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": time.time(),
            "updated_at_human": time.strftime("%Y-%m-%d %H:%M:%S"),
            "pool_size": self.size,
            "current_fingerprints": [r.fingerprint for r in members],
            "current": [
                {
                    "rank": i + 1,
                    "name": (r.config or {}).get("name", ""),
                    "fingerprint": r.fingerprint,
                    "latency_ms": r.latency_ms,
                    "country_code": r.country_code,
                    "endpoint": f"{(r.config or {}).get('address','')}:{(r.config or {}).get('port','')}",
                    "tested_at": r.tested_at,
                }
                for i, r in enumerate(members)
            ],
            "changes": [c.to_dict() for c in self._history[-self.history_limit:]],
        }
        self._atomic_write(self.history_path, json.dumps(payload, ensure_ascii=False, indent=2))

    # ------------------------------------------------------------------

    def refresh(self, note: str = "") -> Tuple[List[TestResult], List[PoolChange]]:
        """استخر را از روی تازه‌ترین نتایج بازسازی می‌کند.

        خروجی: (اعضای فعلی، تغییرات این دور)
        """
        candidates = self.store.get_top_working(
            limit=self.size, max_age_hours=self.max_age_hours
        )

        new_fps = [r.fingerprint for r in candidates]
        old_fps = list(self._current)
        changes: List[PoolChange] = []
        now = time.time()

        by_fp = {r.fingerprint: r for r in candidates}

        # کسانی که از استخر خارج شدند
        for fp in old_fps:
            if fp not in new_fps:
                latest = self.store.get_latest_result(fp)
                name = (latest.config or {}).get("name", fp[:12]) if latest else fp[:12]
                reason = "دیگر سالم نیست" if (latest and not latest.ok) else "جای بهتری گرفت"
                changes.append(PoolChange(
                    at=now, action="removed", fingerprint=fp,
                    name=name, reason=reason,
                ))

        # کسانی که وارد شدند
        for fp in new_fps:
            if fp not in old_fps:
                r = by_fp[fp]
                changes.append(PoolChange(
                    at=now, action="added", fingerprint=fp,
                    name=(r.config or {}).get("name", ""),
                    latency_ms=r.latency_ms,
                    reason=note or "وارد بهترین‌ها شد",
                ))

        self._current = new_fps
        self._history.extend(changes)
        if len(self._history) > self.history_limit:
            self._history = self._history[-self.history_limit:]

        self._save_history(candidates)
        return candidates, changes

    # ------------------------------------------------------------------

    def write_outputs(self) -> Dict[str, Path]:
        """نوشتن top-N، نسخه‌ی base64 آن، و دسته‌بندی کامل همه‌ی سالم‌ها."""
        self.out_dir.mkdir(parents=True, exist_ok=True)
        written: Dict[str, Path] = {}

        # ---- استخر برتر ----
        top = self.store.get_top_working(limit=self.size, max_age_hours=self.max_age_hours)
        top_links = self._links_of(top)

        top_name = str(self.settings.get("pool.top_file", "top20.txt"))
        path = self.out_dir / top_name
        self._atomic_write(path, "\n".join(top_links) + ("\n" if top_links else ""))
        written["top"] = path

        sub_name = str(self.settings.get("pool.top_sub_file", "top20_sub.txt"))
        path = self.out_dir / sub_name
        blob = base64.b64encode("\n".join(top_links).encode("utf-8")).decode("ascii")
        self._atomic_write(path, blob)
        written["top_sub"] = path

        # ---- دسته‌بندی کامل ----
        batch_dir = self.out_dir / str(self.settings.get("pool.batch_dir", "batches"))
        written.update(self._write_batches(batch_dir))

        return written

    def _links_of(self, results: Sequence[TestResult], start_rank: int = 1) -> List[str]:
        """لینک‌های آماده‌ی انتشار — با نام بازنویسی‌شده.

        رتبه از ۱ شمرده می‌شود تا نام کانفیگ در فایل خروجی با جای واقعی‌اش
        در لیست بخواند («DE-01» یعنی سریع‌ترین).
        """
        links: List[str] = []
        for offset, r in enumerate(results):
            raw = str((r.config or {}).get("raw", ""))
            if not raw:
                continue
            if self.clean_names:
                raw = sanitize_result_link(r, rank=start_rank + offset, tag=self.name_tag)
            links.append(raw)
        return links

    def _write_batches(self, batch_dir: Path) -> Dict[str, Path]:
        """همه‌ی سالم‌ها را به فایل‌های N‌تایی تقسیم می‌کند."""
        all_working = self.store.get_all_working(max_age_hours=self.max_age_hours)
        links = self._links_of(all_working)

        batch_dir.mkdir(parents=True, exist_ok=True)

        # فایل‌های دسته‌ی قبلی که دیگر لازم نیستند پاک شوند، وگرنه
        # وقتی تعداد سالم‌ها کم شود دسته‌های کهنه گمراه‌کننده می‌مانند.
        for stale in batch_dir.glob("batch_*.txt"):
            try:
                stale.unlink()
            except OSError:
                pass

        written: Dict[str, Path] = {}
        total_batches = (len(links) + self.batch_size - 1) // self.batch_size
        if self.max_batches > 0:
            total_batches = min(total_batches, self.max_batches)

        for index in range(total_batches):
            start = index * self.batch_size
            chunk = links[start:start + self.batch_size]
            if not chunk:
                break
            path = batch_dir / f"batch_{index + 1:02d}.txt"
            header = (f"# رتبه {start + 1} تا {start + len(chunk)} "
                      f"(از {len(links)} کانفیگ سالم)\n")
            self._atomic_write(path, header + "\n".join(chunk) + "\n")
            written[f"batch_{index + 1:02d}"] = path

        # فهرست راهنما تا معلوم باشد چه چیزی نوشته شده و چه چیزی جا مانده
        index_path = batch_dir / "index.json"
        self._atomic_write(index_path, json.dumps({
            "updated_at_human": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_working": len(links),
            "batch_size": self.batch_size,
            "batches_written": total_batches,
            "configs_in_batches": min(len(links), total_batches * self.batch_size),
            "omitted": max(0, len(links) - total_batches * self.batch_size),
        }, ensure_ascii=False, indent=2))
        written["batch_index"] = index_path

        return written

    # ------------------------------------------------------------------

    @staticmethod
    def _atomic_write(path: Path, text: str) -> None:
        """نوشتن اتمی: خواننده هرگز فایل نیمه‌نوشته نمی‌بیند.

        مهم است چون کلاینت ممکن است دقیقاً وسط بازنویسی، فایل را import کند.
        """
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    # ------------------------------------------------------------------

    def describe_changes(self, changes: Sequence[PoolChange]) -> None:
        """چاپ خلاصه‌ی تغییرات استخر."""
        if not changes:
            self.log.info("استخر بدون تغییر — همه‌ی اعضا هنوز سالم‌اند")
            return

        added = [c for c in changes if c.action == "added"]
        removed = [c for c in changes if c.action == "removed"]

        for c in removed:
            self.log.raw(f"  {self.log.paint('− خارج', 'red')}  {c.name[:38]} — {c.reason}")
        for c in added:
            latency = f"{c.latency_ms:.0f} ms" if c.latency_ms is not None else "—"
            self.log.raw(f"  {self.log.paint('+ وارد', 'green')}  {c.name[:38]} — {latency}")
