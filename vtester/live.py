"""سرویس دائمی: چرخه‌ی کشف + چرخه‌ی سلامت استخر.

دو چرخه‌ی مستقل:
  • کشف   — تلگرام + لینک‌های ساب → کانفیگ جدید → تست → ثبت
  • استخر — هر ۳۰ دقیقه ۲۰ تای برتر را دوباره تست و جایگزین می‌کند

اگر تلگرام بیفتد، کشف با لینک‌های ساب ادامه می‌دهد. اگر هر دو منبع
بیفتند، چرخه‌ی استخر همچنان کار می‌کند و کانفیگ‌های موجود را تازه
نگه می‌دارد.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import geo
from .links import parse_link
from .models import ParseError, ProxyConfig, TestResult
from .pool import PoolManager
from .report import build_payload, write_outputs
from .runner import ConfigTester, PortPool, XrayInstance
from .sources import ConfigLoader
from .store import ConfigStore
from .telegram_source import TelegramScraper, import_legacy_output
from .vpngate import NetworkIdentity, VpnGate


@dataclass
class CycleStats:
    """آمار یک دور."""

    discovered: int = 0
    new_configs: int = 0
    backlog_added: int = 0
    backlog_remaining: int = 0
    tested: int = 0
    working: int = 0
    skipped_blacklist: int = 0
    skipped_known: int = 0
    telegram_ok: bool = False
    telegram_error: str = ""
    subs_ok: bool = False
    duration_s: float = 0.0


class LiveService:
    """سرویس دائمی."""

    def __init__(self, settings, logger) -> None:
        self.settings = settings
        self.log = logger
        self.stop_event = threading.Event()

        self.store = ConfigStore(
            settings.path_of("store.path"),
            blacklist_after=int(settings.get("health.blacklist_after_failures", 3)),
            blacklist_hours=float(settings.get("health.blacklist_hours", 24)),
        )
        self.pool = PoolManager(settings, logger, self.store)
        self.telegram = TelegramScraper(settings, logger)
        self.vpn_gate = VpnGate(settings, logger)

        self.discovery_interval = float(settings.get("live.discovery_interval_minutes", 60)) * 60
        self.pool_interval = float(settings.get("live.pool_interval_minutes", 30)) * 60
        self.batch_test_size = int(settings.get("live.batch_test_size", 0))

        self._counter_lock = threading.Lock()
        self._done = 0
        self._working = 0
        self._last_discovery = 0.0
        self._last_pool_check = 0.0
        self._cycle_number = 0

    # ------------------------------------------------------------------

    def request_stop(self) -> None:
        self.stop_event.set()

    def close(self) -> None:
        self.store.close()

    # ------------------------------------------------------------------
    # مهاجرت از داده‌های قبلی
    # ------------------------------------------------------------------

    def migrate_legacy(self) -> None:
        """داده‌های اسکریپت قدیمی و کش JSONL را یک بار وارد می‌کند."""
        # کش JSONL نتایج تست
        jsonl = self.settings.path_of("cache.path")
        marker = self.store.path.parent / ".migrated_jsonl"
        if jsonl.exists() and not marker.exists():
            self.log.info("مهاجرت کش قدیمی نتایج به پایگاه داده...")
            imported, skipped = self.store.migrate_from_jsonl(jsonl)
            self.log.info(f"  {imported} نتیجه وارد شد" + (f" ({skipped} نامعتبر)" if skipped else ""))
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text(str(time.time()), encoding="utf-8")

        # خروجی اسکریپت تلگرام قدیمی
        legacy = self.settings.path_of("telegram.legacy_output")
        marker2 = self.store.path.parent / ".migrated_telegram"
        if legacy.exists() and not marker2.exists():
            links = import_legacy_output(legacy, self.log)
            if links:
                self.log.info(f"مهاجرت {len(links)} کانفیگ از خروجی قدیمی تلگرام...")
                configs = self._parse_links(links, source="telegram-legacy")
                self.store.upsert_configs_batch(configs)
                self.log.info(f"  {len(configs)} کانفیگ معتبر ثبت شد")
            marker2.parent.mkdir(parents=True, exist_ok=True)
            marker2.write_text(str(time.time()), encoding="utf-8")

    # ------------------------------------------------------------------
    # کشف
    # ------------------------------------------------------------------

    def discover(self, skip_telegram: bool = False) -> Tuple[List[ProxyConfig], CycleStats]:
        """جمع‌آوری کانفیگ از تلگرام و لینک‌های ساب.

        شکست یکی از منابع مانع دیگری نمی‌شود.
        """
        stats = CycleStats()
        all_links: List[str] = []

        # ---- تلگرام ----
        if skip_telegram:
            self.log.info("تلگرام در این دور رد می‌شود (نیازمند فیلترشکن روشن)")
        elif self.telegram.configured:
            self.log.heading("دریافت از تلگرام")
            tg = self.telegram.fetch()
            stats.telegram_ok = tg.ok
            stats.telegram_error = tg.error
            if tg.ok:
                all_links.extend(tg.links)
                self.log.info(tg.summary)
            else:
                self.log.warn(f"تلگرام: {tg.error} — با منابع دیگر ادامه می‌دهیم")
        else:
            self.log.info("تلگرام غیرفعال است — رد می‌شود")

        # ---- لینک‌های ساب ----
        self.log.heading("دریافت از لینک‌های ساب")
        try:
            loader = ConfigLoader(self.settings, self.log)
            sub_configs, parse_errors = loader.load()
            stats.subs_ok = True
            self.log.info(f"{len(sub_configs)} کانفیگ از لینک‌های ساب")
        except Exception as exc:  # noqa: BLE001 - ساب هم نباید سرویس را بخواباند
            self.log.warn(f"لینک‌های ساب ناموفق: {type(exc).__name__} — ادامه می‌دهیم")
            sub_configs, parse_errors = [], []

        # ---- ترکیب ----
        tg_configs = self._parse_links(all_links, source="telegram")
        combined = tg_configs + list(sub_configs)
        stats.discovered = len(combined)

        if not combined:
            return [], stats

        # حذف تکراری داخل همین دور
        unique: Dict[str, ProxyConfig] = {}
        for cfg in combined:
            unique.setdefault(cfg.fingerprint(), cfg)
        deduped = list(unique.values())

        self.log.info(f"مجموع {stats.discovered} کانفیگ → {len(deduped)} یکتا")

        # ثبت همه در پایگاه داده (چه تست بشوند چه نشوند)
        self.store.upsert_configs_batch(deduped)

        return deduped, stats

    def _parse_links(self, links: Sequence[str], source: str) -> List[ProxyConfig]:
        """تبدیل لینک خام به ProxyConfig، با رد کردن بی‌سروصدای نامعتبرها."""
        configs: List[ProxyConfig] = []
        for index, link in enumerate(links):
            try:
                configs.append(parse_link(link, source=source, index=index))
            except ParseError:
                continue
            except Exception:  # noqa: BLE001 - لینک خراب نباید دور را بشکند
                continue
        return configs

    # ------------------------------------------------------------------
    # انتخاب کاندیدهای تست
    # ------------------------------------------------------------------

    def select_for_testing(self, configs: Sequence[ProxyConfig],
                           stats: CycleStats) -> List[ProxyConfig]:
        """کانفیگ‌های این دور + کانفیگ‌های تست‌نشده‌ی انبار.

        فقط تکیه بر کشفِ همین دور کافی نیست: کانفیگی که قبلاً ثبت شده ولی
        هرگز تست نشده (از مهاجرت، از دوری که وسطش قطع شد، یا از سقف دور قبل)
        اگر دوباره کشف نشود تا ابد تست‌نشده می‌ماند.
        """
        selected: List[ProxyConfig] = []
        picked: set = set()
        stale_hours = float(self.settings.get("live.retest_after_hours", 12))
        now = time.time()

        # ---- ۱) کانفیگ‌های همین دور ----
        for cfg in configs:
            fp = cfg.fingerprint()
            if fp in picked:
                continue

            if self.store.is_blacklisted(fp):
                stats.skipped_blacklist += 1
                continue

            latest = self.store.get_latest_result(fp)
            if latest is None:
                selected.append(cfg)
                picked.add(fp)
                continue

            age_hours = (now - latest.tested_at) / 3600.0
            if age_hours >= stale_hours:
                selected.append(cfg)
                picked.add(fp)
            else:
                stats.skipped_known += 1

        stats.new_configs = len(selected)

        # ---- ۲) پر کردن از انبار با کانفیگ‌های هرگز تست‌نشده ----
        cap = int(self.settings.get("live.batch_test_size", 0) or 0)
        backlog_cap = int(self.settings.get("live.max_untested_per_cycle", 5000) or 0)
        room = (cap - len(selected)) if cap > 0 else backlog_cap
        if backlog_cap > 0:
            room = min(room, backlog_cap)

        if room > 0:
            backlog = self.store.get_untested_configs(limit=room + len(picked))
            added = 0
            for cfg in backlog:
                if added >= room:
                    break
                fp = cfg.fingerprint()
                if fp in picked or self.store.is_blacklisted(fp):
                    continue
                selected.append(cfg)
                picked.add(fp)
                added += 1

            if added:
                remaining = self.store.count_untested() - added
                note = f"{added} کانفیگ تست‌نشده از انبار اضافه شد"
                if remaining > 0:
                    note += f" ({remaining} تای دیگر در دورهای بعد)"
                self.log.info(note)
                stats.backlog_added = added
                stats.backlog_remaining = max(0, remaining)

        # ---- ۳) سقف نهایی ----
        if cap > 0 and len(selected) > cap:
            dropped = len(selected) - cap
            self.log.info(f"سقف این دور: {cap} کانفیگ — {dropped} تا به دور بعد موکول شد")
            selected = selected[:cap]

        return selected

    # ------------------------------------------------------------------
    # تست
    # ------------------------------------------------------------------

    def test_configs(self, configs: Sequence[ProxyConfig],
                     label: str = "") -> List[TestResult]:
        """تست موازی با ثبت فوری هر نتیجه در پایگاه داده."""
        if not configs:
            return []

        concurrency = max(1, int(self.settings.get("test.concurrency", 16)))
        pool = PortPool(
            int(self.settings.get("xray.port_start", 21000)),
            int(self.settings.get("xray.port_end", 22000)),
        )
        tester = ConfigTester(self.settings, pool, self.stop_event)

        total = len(configs)
        self._done = 0
        self._working = 0
        results: List[TestResult] = []

        heading = f"تست پینگ واقعی ({total} کانفیگ)"
        if label:
            heading = f"{label} — {heading}"
        self.log.heading(heading)

        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="live") as pool_exec:
            futures = {pool_exec.submit(tester.test, cfg): cfg for cfg in configs}
            try:
                for future in as_completed(futures):
                    if self.stop_event.is_set():
                        break
                    result = future.result()
                    if result.stage == "aborted":
                        continue
                    results.append(result)
                    self.store.record_test_result(result)
                    self._report_progress(result, total)
            except KeyboardInterrupt:
                self.stop_event.set()
                for future in futures:
                    future.cancel()
                raise

        return results

    def _report_progress(self, result: TestResult, total: int) -> None:
        with self._counter_lock:
            self._done += 1
            if result.ok:
                self._working += 1
            done, working = self._done, self._working

        name = (result.config or {}).get("name", "")
        if len(name) > 32:
            name = name[:29] + "..."

        counter = f"[{done:>{len(str(total))}}/{total}]"
        if result.ok:
            country = f" {result.country_code}" if result.country_code else ""
            body = self.log.paint(f"{result.latency_ms:>7.0f} ms", "green")
            self.log.raw(f"  {counter} ✓ {body}  {name}{country}")
        elif self.settings.get("live.log_failures", False):
            self.log.raw(f"  {counter} ✕ {'ناموفق':>10}  {name}")

        step = max(25, total // 20)
        if done % step == 0 and done < total:
            rate = 100.0 * working / done
            self.log.raw(self.log.paint(
                f"      ── {done}/{total} · {working} سالم ({rate:.0f}٪)", "dim"))

    # ------------------------------------------------------------------
    # چرخه‌ها
    # ------------------------------------------------------------------

    def run_discovery_cycle(self, skip_gate: bool = False,
                            skip_telegram: bool = False) -> CycleStats:
        """یک دور کامل کشف: دریافت → دروازه‌ی VPN → تست → خروجی."""
        started = time.perf_counter()
        self._cycle_number += 1
        self.log.heading(f"═══ دور کشف #{self._cycle_number} ═══")

        # دروازه فقط وقتی معنا دارد که واقعاً از تلگرام گرفته باشیم
        gate_needed = (not skip_gate and not skip_telegram
                       and self.vpn_gate.enabled and self.telegram.configured)

        # IP مبنا قبل از دریافت (فیلترشکن روشن است)
        baseline = NetworkIdentity()
        if gate_needed:
            baseline = self.vpn_gate.capture_baseline()

        configs, stats = self.discover(skip_telegram=skip_telegram)

        if not configs:
            self.log.warn("هیچ کانفیگی جمع نشد — این دور تمام")
            stats.duration_s = time.perf_counter() - started
            return stats

        candidates = self.select_for_testing(configs, stats)
        self.log.info(
            f"برای تست: {len(candidates)} · "
            f"از قبل معلوم: {stats.skipped_known} · "
            f"لیست سیاه: {stats.skipped_blacklist}"
        )

        if not candidates:
            self.log.info("کانفیگ جدیدی برای تست نیست")
            self._finalize_outputs("بدون تست جدید")
            stats.duration_s = time.perf_counter() - started
            return stats

        # ---- دروازه‌ی VPN ----
        if gate_needed:
            allowed, reason = self.vpn_gate.wait_for_direct_connection(baseline)
            if not allowed:
                self.log.error(reason)
                self.log.raw("")
                self.log.raw("  کانفیگ‌های دریافت‌شده در پایگاه داده ذخیره شدند.")
                self.log.raw("  فیلترشکن را خاموش کنید و سرویس را دوباره اجرا کنید؛")
                self.log.raw("  مستقیم می‌رود سراغ تست همین کانفیگ‌ها.")
                self.stop_event.set()
                stats.duration_s = time.perf_counter() - started
                return stats
            self.log.info(reason)

        # ---- تست ----
        results = self.test_configs(candidates, label=f"دور #{self._cycle_number}")
        stats.tested = len(results)
        stats.working = sum(1 for r in results if r.ok)

        if results and not self.stop_event.is_set():
            enriched = geo.enrich(results, self.settings, self.log,
                                  tunnel=lambda: self._best_tunnel())
            if enriched:
                self.log.info(f"اطلاعات جغرافیایی {enriched} کانفیگ تکمیل شد")
                # به‌روزرسانی ردیف موجود، نه درج ردیف تازه
                for r in results:
                    if r.ok and r.exit_ip:
                        self.store.update_geo(r)

        self._finalize_outputs(f"دور کشف #{self._cycle_number}")
        self._prune_store()
        stats.duration_s = time.perf_counter() - started

        if stats.tested:
            rate = 100.0 * stats.working / stats.tested
            self.log.info(f"دور تمام: {stats.tested} تست · "
                          f"{stats.working} سالم ({rate:.0f}٪)")
        else:
            self.log.info("دور تمام")
        return stats

    def run_pool_cycle(self) -> None:
        """بازبینی استخر: اعضای فعلی را دوباره تست و مرده‌ها را جایگزین می‌کند."""
        self.log.heading("═══ بازبینی استخر ═══")

        members = self.store.get_top_working(
            limit=self.pool.size, max_age_hours=self.pool.max_age_hours
        )
        if not members:
            self.log.warn("استخر خالی است — چیزی برای بازبینی نیست")
            return

        configs: List[ProxyConfig] = []
        for r in members:
            try:
                configs.append(ProxyConfig.from_dict(r.config))
            except (TypeError, ValueError):
                continue

        results = self.test_configs(configs, label="بازبینی استخر")
        alive = sum(1 for r in results if r.ok)
        self.log.info(f"از {len(results)} عضو استخر، {alive} هنوز سالم‌اند")

        # جایگزین‌ها خودکار از کوئری top می‌آیند، چون عضو افتاده دیگر
        # آخرین نتیجه‌اش ناموفق است و از کوئری خارج می‌شود.
        self._finalize_outputs("بازبینی دوره‌ای")

    # ------------------------------------------------------------------

    def _finalize_outputs(self, note: str) -> None:
        """به‌روزرسانی استخر، فایل‌های دسته‌ای، و گزارش کامل."""
        _, changes = self.pool.refresh(note=note)
        if changes:
            self.pool.describe_changes(changes)

        written = self.pool.write_outputs()
        report_paths = self._write_full_report()
        written.update(report_paths)

        self.log.info(f"خروجی‌ها به‌روز شد ({len(written)} فایل)")

    def _write_full_report(self) -> Dict[str, Path]:
        """گزارش HTML و JSON کامل از همه‌ی نتایج اخیر."""
        try:
            all_results = self.store.get_all_working(max_age_hours=self.pool.max_age_hours)
            recent_failed = self._recent_failures()
            combined = all_results + recent_failed

            if not combined:
                return {}

            db_stats = self.store.get_stats()
            stats = {
                "sources_total": 0,
                "links_extracted": db_stats["total_configs"],
                "parse_failed": 0,
                "unique": db_stats["total_configs"],
                "duplicates": 0,
                "selected": len(combined),
                "tested_now": 0,
                "from_cache": 0,
                "aborted": False,
                "blacklisted": db_stats["blacklisted"],
            }

            payload = build_payload(
                combined,
                settings=self.settings,
                stats=stats,
                sources=[],
                parse_errors=[],
                xray_version="",
                duration_s=0.0,
            )
            return write_outputs(payload, combined, self.settings, self.log)
        except Exception as exc:  # noqa: BLE001 - گزارش نباید سرویس را بخواباند
            self.log.warn(f"تولید گزارش ناموفق: {type(exc).__name__}: {exc}")
            return {}

    def _recent_failures(self, limit: int = 500) -> List[TestResult]:
        """آخرین کانفیگ‌های ناموفق برای اینکه گزارش تصویر کامل بدهد."""
        return self.store.get_recent_failures(
            limit=limit, max_age_hours=self.pool.max_age_hours
        )

    def _prune_store(self) -> None:
        """هرس دوره‌ای جدول نتایج تا در مقیاس بالا از کنترل خارج نشود."""
        try:
            stats = self.store.prune(
                keep_per_config=int(self.settings.get("store.keep_results_per_config", 5)),
                older_than_days=float(self.settings.get("store.prune_after_days", 30)),
            )
            total = stats["removed_old"] + stats["removed_excess"]
            if total:
                self.log.info(f"هرس پایگاه داده: {total} رکورد قدیمی حذف شد")
        except Exception as exc:  # noqa: BLE001 - هرس نباید سرویس را بخواباند
            self.log.warn(f"هرس ناموفق: {type(exc).__name__}: {exc}")

    def _best_tunnel(self):
        """تونل روی بهترین کانفیگ سالم — برای غنی‌سازی جغرافیایی."""
        from contextlib import contextmanager

        @contextmanager
        def tunnel():
            top = self.store.get_top_working(limit=1, max_age_hours=self.pool.max_age_hours)
            if not top:
                yield None
                return
            pool = PortPool(
                int(self.settings.get("xray.port_start", 21000)),
                int(self.settings.get("xray.port_end", 22000)),
            )
            cfg = ProxyConfig.from_dict(top[0].config)
            with XrayInstance(cfg, self.settings, pool) as instance:
                yield instance.proxies

        return tunnel()

    # ------------------------------------------------------------------
    # حلقه‌ی اصلی
    # ------------------------------------------------------------------

    def run_forever(self, skip_gate: bool = False) -> None:
        """سرویس دائمی — تا وقتی متوقف نشده کار می‌کند."""
        self.migrate_legacy()

        telegram_in_service = bool(self.settings.get("live.telegram_in_service", False))

        self.log.heading("سرویس دائمی شروع شد")
        self.log.info(f"چرخه‌ی کشف: هر {self.discovery_interval / 60:.0f} دقیقه")
        self.log.info(f"بازبینی استخر: هر {self.pool_interval / 60:.0f} دقیقه")
        self.log.info(f"اندازه‌ی استخر: {self.pool.size} کانفیگ")
        db = self.store.get_stats()
        self.log.info(f"پایگاه داده: {db['total_configs']} کانفیگ · "
                      f"{db['total_results']} نتیجه · {db['blacklisted']} در لیست سیاه")

        if self.telegram.configured and not telegram_in_service:
            self.log.raw("")
            self.log.warn("تلگرام فقط در همین دور اول خوانده می‌شود.")
            self.log.raw("  دلیل: دریافت از تلگرام به فیلترشکن روشن نیاز دارد ولی تست پینگ")
            self.log.raw("  به فیلترشکن خاموش — نمی‌شود هر ساعت منتظر ماند شما آن را")
            self.log.raw("  جابه‌جا کنید. دورهای بعدی فقط از لینک‌های ساب می‌گیرند.")
            self.log.raw("  برای گرفتن کانفیگ تازه از تلگرام، هر وقت خواستید جدا اجرا کنید:")
            self.log.raw(self.log.paint("     python live.py --once", "cyan"))
            self.log.raw("")

        # دور اول بلافاصله
        try:
            self.run_discovery_cycle(skip_gate=skip_gate)
        except KeyboardInterrupt:
            raise
        except Exception as exc:  # noqa: BLE001
            self.log.error(f"دور کشف ناموفق: {type(exc).__name__}: {exc}")

        self._last_discovery = time.monotonic()
        self._last_pool_check = time.monotonic()

        while not self.stop_event.is_set():
            now = time.monotonic()
            next_discovery = self._last_discovery + self.discovery_interval
            next_pool = self._last_pool_check + self.pool_interval
            wake_at = min(next_discovery, next_pool)
            sleep_for = max(0.0, wake_at - now)

            if sleep_for > 0:
                mins = sleep_for / 60.0
                which = "کشف" if next_discovery <= next_pool else "بازبینی استخر"
                self.log.info(f"خواب {mins:.0f} دقیقه تا {which} بعدی...")
                # خواب تکه‌تکه تا توقف سریع جواب بدهد
                if self.stop_event.wait(timeout=sleep_for):
                    break

            now = time.monotonic()
            try:
                if now >= self._last_pool_check + self.pool_interval:
                    self.run_pool_cycle()
                    self._last_pool_check = time.monotonic()

                if now >= self._last_discovery + self.discovery_interval:
                    # دورهای بعدی: نه تلگرام نه دروازه. تلگرام به فیلترشکن روشن
                    # نیاز دارد و تست به فیلترشکن خاموش؛ سرویس دائمی نمی‌تواند
                    # هر ساعت منتظر بماند کاربر بین این دو جابه‌جا کند.
                    self.run_discovery_cycle(
                        skip_gate=True,
                        skip_telegram=not telegram_in_service,
                    )
                    self._last_discovery = time.monotonic()

            except KeyboardInterrupt:
                raise
            except Exception as exc:  # noqa: BLE001 - سرویس دائمی باید دوام بیاورد
                self.log.error(f"خطای دور: {type(exc).__name__}: {exc}")
                time.sleep(30)

        self.log.info("سرویس متوقف شد")
