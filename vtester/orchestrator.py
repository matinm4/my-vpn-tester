"""هماهنگ‌کننده‌ی اجرا: بارگذاری، حذف تکراری، تست موازی و تولید گزارش."""

from __future__ import annotations

import random
import subprocess
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import geo
from .cache import ResultCache
from .models import ProxyConfig, TestResult
from .report import build_payload, write_outputs
from .runner import ConfigTester, PortPool, XrayInstance
from .sources import ConfigLoader


class Orchestrator:
    def __init__(self, settings, logger, extra_entries: Optional[Sequence[str]] = None) -> None:
        self.settings = settings
        self.log = logger
        # لینک‌هایی که از خط فرمان آمده‌اند و باید اول صف باشند
        self.extra_entries: List[str] = list(extra_entries or [])
        self.stop_event = threading.Event()
        self.cache = ResultCache(
            path=settings.path_of("cache.path"),
            ttl_hours=float(settings.get("cache.ttl_hours", 24)),
            enabled=bool(settings.get("cache.enabled", True)),
            retest_failed=bool(settings.get("cache.retest_failed", False)),
        )
        self._counter_lock = threading.Lock()
        self._done = 0
        self._working = 0

    # ------------------------------------------------------------------

    def request_stop(self) -> None:
        self.stop_event.set()

    # ------------------------------------------------------------------

    def deduplicate(self, configs: Sequence[ProxyConfig]) -> Tuple[List[ProxyConfig], int]:
        """کانفیگ‌های تکراری را بر اساس اثر انگشت پارامترهای اتصال حذف می‌کند."""
        if not self.settings.get("dedup.enabled", True):
            return list(configs), 0

        keep = self.settings.get("dedup.keep", "first")
        chosen: Dict[str, ProxyConfig] = {}
        order: List[str] = []

        for cfg in configs:
            fingerprint = cfg.fingerprint()
            existing = chosen.get(fingerprint)
            if existing is None:
                chosen[fingerprint] = cfg
                order.append(fingerprint)
            elif keep == "shortest_name" and len(cfg.remark) < len(existing.remark):
                # نام کوتاه‌تر معمولاً تمیزتر است و برچسب‌های تبلیغاتی ندارد
                chosen[fingerprint] = cfg

        unique = [chosen[f] for f in order]
        return unique, len(configs) - len(unique)

    def filter_configs(self, configs: Sequence[ProxyConfig]) -> List[ProxyConfig]:
        result = list(configs)

        only = [p.strip().lower() for p in (self.settings.get("test.only_protocols") or []) if p.strip()]
        if only:
            before = len(result)
            result = [c for c in result if c.protocol in only]
            self.log.info(f"فیلتر پروتکل: {len(result)} از {before} کانفیگ باقی ماند")

        if self.settings.get("test.shuffle", False):
            random.shuffle(result)

        limit = int(self.settings.get("test.limit", 0) or 0)
        if limit > 0 and len(result) > limit:
            self.log.info(f"محدودیت تست: فقط {limit} کانفیگ اول از {len(result)} تا")
            result = result[:limit]

        return result

    # ------------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        started = time.perf_counter()

        # ---- ۱) بارگذاری منابع ----
        self.log.heading("۱) خواندن منابع")
        loader = ConfigLoader(self.settings, self.log)
        configs, parse_errors = loader.load(self.extra_entries)
        if not configs:
            raise RuntimeError(
                "هیچ کانفیگی پیدا نشد. لینک سابسکریپشن را در subs.txt بگذارید "
                "یا با --link یک کانفیگ مستقیم بدهید."
            )
        self.log.info(f"مجموع کانفیگ استخراج‌شده: {len(configs)}"
                      + (f" ({len(parse_errors)} ناسازگار)" if parse_errors else ""))

        # ---- ۲) حذف تکراری ----
        self.log.heading("۲) حذف کانفیگ‌های تکراری")
        unique, duplicates = self.deduplicate(configs)
        self.log.info(f"{len(unique)} کانفیگ یکتا ({duplicates} تکراری حذف شد)")

        targets = self.filter_configs(unique)
        if not targets:
            raise RuntimeError("بعد از اعمال فیلترها هیچ کانفیگی برای تست نماند.")

        # ---- ۳) کش ----
        cached_count = self.cache.load()
        if cached_count:
            self.log.info(f"{cached_count} نتیجه‌ی معتبر در کش موجود است")

        pending: List[ProxyConfig] = []
        results: List[TestResult] = []
        for cfg in targets:
            hit = self.cache.get(cfg.fingerprint())
            if hit is not None:
                hit.from_cache = True
                # کانفیگ ممکن است در منبع جدید نام تازه گرفته باشد
                hit.config = cfg.to_dict()
                results.append(hit)
            else:
                pending.append(cfg)

        if results:
            self.log.info(f"{len(results)} کانفیگ از کش خوانده شد — دوباره تست نمی‌شوند")

        # ---- ۴) تست ----
        self.log.heading(f"۳) تست پینگ واقعی ({len(pending)} کانفیگ)")
        if pending:
            results.extend(self._test_all(pending))
        else:
            self.log.info("همه‌ی کانفیگ‌ها از کش پوشش داده شدند")

        # ---- ۵) غنی‌سازی جغرافیایی ----
        if not self.stop_event.is_set():
            enriched = geo.enrich(
                results, self.settings, self.log,
                tunnel=lambda: self._best_tunnel(results),
            )
            if enriched:
                self.log.info(f"اطلاعات جغرافیایی {enriched} کانفیگ تکمیل شد")

        # ---- ۶) گزارش ----
        self.log.heading("۴) تولید گزارش")
        stats = {
            "sources_total": len(loader.stats.as_list()),
            "links_extracted": len(configs),
            "parse_failed": len(parse_errors),
            "unique": len(unique),
            "duplicates": duplicates,
            "selected": len(targets),
            "tested_now": len(pending),
            "from_cache": len(targets) - len(pending),
            "aborted": self.stop_event.is_set(),
        }
        payload = build_payload(
            results,
            settings=self.settings,
            stats=stats,
            sources=loader.stats.as_list(),
            parse_errors=parse_errors,
            xray_version=self._xray_version(),
            duration_s=time.perf_counter() - started,
        )
        written = write_outputs(payload, results, self.settings, self.log)

        try:
            self.cache.compact()
        except OSError as exc:
            self.log.warn(f"فشرده‌سازی کش ناموفق بود: {exc}")
        finally:
            self.cache.close()

        return {"payload": payload, "written": written, "results": results}

    # ------------------------------------------------------------------

    @contextmanager
    def _best_tunnel(self, results: Sequence[TestResult]):
        """یک تونل موقت روی سریع‌ترین کانفیگ سالم باز می‌کند.

        برای کارهای جانبی‌ای مثل جست‌وجوی جغرافیایی که سرویس‌شان ممکن است از
        شبکه‌ی محلی در دسترس نباشد.
        """
        candidates = sorted(
            (r for r in results if r.ok and r.latency_ms is not None and r.config),
            key=lambda r: r.latency_ms or float("inf"),
        )
        if not candidates:
            yield None
            return

        pool = PortPool(
            int(self.settings.get("xray.port_start", 21000)),
            int(self.settings.get("xray.port_end", 22000)),
        )
        cfg = ProxyConfig.from_dict(candidates[0].config)
        with XrayInstance(cfg, self.settings, pool) as instance:
            yield instance.proxies

    # ------------------------------------------------------------------

    def _test_all(self, pending: List[ProxyConfig]) -> List[TestResult]:
        concurrency = max(1, int(self.settings.get("test.concurrency", 16)))
        pool = PortPool(
            int(self.settings.get("xray.port_start", 21000)),
            int(self.settings.get("xray.port_end", 22000)),
        )
        tester = ConfigTester(self.settings, pool, self.stop_event)

        total = len(pending)
        self._done = 0
        self._working = 0
        results: List[TestResult] = []

        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="vt") as pool_exec:
            futures: Dict[Future, ProxyConfig] = {
                pool_exec.submit(tester.test, cfg): cfg for cfg in pending
            }
            try:
                for future in _as_completed(futures):
                    result = future.result()
                    # کانفیگی که به خاطر توقف کاربر اصلاً تست نشده نه در نتایج
                    # می‌آید نه در کش — وگرنه اجرای بعدی آن را «ناموفق» می‌بیند
                    # و دیگر هرگز تستش نمی‌کند.
                    if result.stage == "aborted":
                        continue
                    results.append(result)
                    self.cache.put(result)
                    self._report_progress(result, total)
            except KeyboardInterrupt:
                self.stop_event.set()
                self.log.warn("لغو شد — نتایج تاکنون ذخیره می‌شوند...")
                for future in futures:
                    future.cancel()
                raise

        if self.stop_event.is_set():
            skipped = total - len(results)
            if skipped > 0:
                self.log.warn(f"{skipped} کانفیگ تست نشد — در اجرای بعدی ادامه پیدا می‌کند")

        return results

    def _report_progress(self, result: TestResult, total: int) -> None:
        with self._counter_lock:
            self._done += 1
            if result.ok:
                self._working += 1
            done, working = self._done, self._working

        name = (result.config or {}).get("name", "")
        if len(name) > 34:
            name = name[:31] + "..."

        counter = f"[{done:>{len(str(total))}}/{total}]"
        if result.ok:
            country = f" {result.country_code}" if result.country_code else ""
            body = self.log.paint(f"{result.latency_ms:>7.0f} ms", "green")
            self.log.raw(f"  {counter} ✓ {body}  {name}{country}")
        else:
            body = self.log.paint(f"{'ناموفق':>10}", "grey")
            self.log.raw(f"  {counter} ✕ {body}  {name} — {self.log.paint(result.error[:56], 'grey')}")

        if done % 50 == 0 and done < total:
            rate = 100.0 * working / done
            self.log.raw(self.log.paint(
                f"      ── {done}/{total} انجام شد · {working} سالم ({rate:.0f}٪)", "dim"))

    def _xray_version(self) -> str:
        try:
            proc = subprocess.run(
                [str(self.settings.path_of("xray.binary")), "version"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace",
            )
            first = (proc.stdout or "").strip().splitlines()
            return first[0].strip() if first else ""
        except (OSError, subprocess.SubprocessError):
            return ""


def _as_completed(futures):
    """as_completed با امکان وقفه‌ی تمیز با Ctrl+C."""
    from concurrent.futures import as_completed
    return as_completed(futures)
