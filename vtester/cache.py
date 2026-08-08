"""کش نتایج — اگر اجرا نصفه قطع شد، دفعه‌ی بعد از همان‌جا ادامه می‌دهد."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, Iterator, List, Optional

from .models import TestResult


class ResultCache:
    """کش مبتنی بر JSONL.

    هر نتیجه بلافاصله بعد از تست روی دیسک نوشته و flush می‌شود، پس با Ctrl+C
    یا قطع برق حداکثر همان یک کانفیگِ در حال تست از دست می‌رود.
    """

    def __init__(self, path: Path, ttl_hours: float = 24.0,
                 enabled: bool = True, retest_failed: bool = False) -> None:
        self.path = path
        self.ttl_seconds = max(0.0, float(ttl_hours) * 3600.0)
        self.enabled = enabled
        self.retest_failed = retest_failed

        self._entries: Dict[str, TestResult] = {}
        self._lock = threading.Lock()
        self._handle = None

    # ------------------------------------------------------------------

    def load(self) -> int:
        """نتایج قبلی را می‌خواند. خروجی: تعداد رکورد معتبر."""
        if not self.enabled or not self.path.exists():
            return 0

        now = time.time()
        entries: Dict[str, TestResult] = {}
        corrupted = 0

        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    corrupted += 1
                    continue
                fingerprint = record.get("fingerprint")
                if not fingerprint:
                    corrupted += 1
                    continue
                if self.ttl_seconds and (now - record.get("tested_at", 0)) > self.ttl_seconds:
                    continue
                # رکورد جدیدتر رکورد قدیمی‌تر همان کانفیگ را کنار می‌زند
                previous = entries.get(fingerprint)
                if previous is None or record.get("tested_at", 0) >= previous.tested_at:
                    entries[fingerprint] = TestResult.from_dict(record)

        self._entries = entries
        self.corrupted_lines = corrupted
        return len(entries)

    def get(self, fingerprint: str) -> Optional[TestResult]:
        """نتیجه‌ی کش‌شده اگر قابل استفاده باشد."""
        if not self.enabled:
            return None
        result = self._entries.get(fingerprint)
        if result is None:
            return None
        if self.retest_failed and not result.ok:
            return None
        return result

    def has_fresh(self, fingerprint: str) -> bool:
        return self.get(fingerprint) is not None

    # ------------------------------------------------------------------

    def _open(self) -> None:
        if self._handle is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = open(self.path, "a", encoding="utf-8")

    def put(self, result: TestResult) -> None:
        """نتیجه را ثبت و فوراً روی دیسک flush می‌کند."""
        if not self.enabled:
            return
        with self._lock:
            self._entries[result.fingerprint] = result
            self._open()
            assert self._handle is not None
            self._handle.write(json.dumps(result.to_dict(), ensure_ascii=False) + "\n")
            self._handle.flush()
            os.fsync(self._handle.fileno())

    def close(self) -> None:
        with self._lock:
            if self._handle is not None:
                self._handle.close()
                self._handle = None

    # ------------------------------------------------------------------

    def compact(self) -> int:
        """رکوردهای تکراری و منقضی را حذف می‌کند تا فایل کش بزرگ نشود."""
        if not self.enabled or not self.path.exists():
            return 0
        with self._lock:
            if self._handle is not None:
                self._handle.close()
                self._handle = None

            records = [r.to_dict() for r in self._entries.values()]
            fd, tmp_path = tempfile.mkstemp(
                dir=str(self.path.parent), prefix=".cache-", suffix=".tmp"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    for record in records:
                        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp_path, self.path)
            except OSError:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                raise
            return len(records)

    def clear(self) -> None:
        with self._lock:
            if self._handle is not None:
                self._handle.close()
                self._handle = None
            self._entries.clear()
            if self.path.exists():
                self.path.unlink()

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[TestResult]:
        return iter(list(self._entries.values()))
