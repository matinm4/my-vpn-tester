"""رابط خط فرمان."""

from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__
from .logging_util import Logger, enable_utf8_console
from .orchestrator import Orchestrator
from .settings import Settings

BANNER = r"""
  ┌─────────────────────────────────────────────┐
  │   V-Tester · تست پینگ واقعی با هسته‌ی Xray   │
  └─────────────────────────────────────────────┘
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="run.py",
        description="استخراج کانفیگ از لینک‌های سابسکریپشن و تست پینگ واقعی با هسته‌ی Xray.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "نمونه‌ها:\n"
            "  python run.py                              اجرای معمولی با config.yaml\n"
            "  python run.py -j 32 --attempts 5           ۳۲ تست همزمان، ۵ درخواست هر کدام\n"
            "  python run.py --limit 50 --fresh           تست سریع ۵۰ تا بدون کش\n"
            "  python run.py --link \"vmess://...\"         تست یک کانفیگ مشخص\n"
            "  python run.py --only vless,trojan          فقط این پروتکل‌ها\n"
            "  python run.py --max-latency 800            کانفیگ‌های کندتر را ضعیف علامت بزن\n"
        ),
    )
    p.add_argument("--version", action="version", version=f"vtester {__version__}")
    p.add_argument("-c", "--config", metavar="FILE", help="مسیر فایل تنظیمات (پیش‌فرض config.yaml)")

    g = p.add_argument_group("ورودی")
    g.add_argument("--subs", metavar="FILE", help="فایل لینک‌های سابسکریپشن")
    g.add_argument("--link", metavar="URL", action="append", default=None,
                   help="یک لینک سابسکریپشن یا کانفیگ مستقیم (قابل تکرار)")
    g.add_argument("--fetch-proxy", metavar="URL", help="پروکسی برای دانلود خود سابسکریپشن")
    g.add_argument("--user-agent", metavar="UA", help="یوزر ایجنت درخواست سابسکریپشن")

    g = p.add_argument_group("تست")
    g.add_argument("-j", "--concurrency", type=int, metavar="N", help="تعداد تست همزمان")
    g.add_argument("--attempts", type=int, metavar="N", help="تعداد درخواست به ازای هر کانفیگ")
    g.add_argument("--timeout", type=float, metavar="SEC", help="تایم‌اوت هر درخواست")
    g.add_argument("--retries", type=int, metavar="N", help="تلاش مجدد کل کانفیگ در صورت شکست")
    g.add_argument("--url", metavar="URL", help="آدرس سنجش پینگ")
    g.add_argument("--limit", type=int, metavar="N", help="فقط N کانفیگ اول تست شود")
    g.add_argument("--shuffle", action="store_true", default=None, help="ترتیب تست تصادفی شود")
    g.add_argument("--only", metavar="LIST", help="فقط این پروتکل‌ها، با کاما: vless,trojan")
    g.add_argument("--max-latency", type=float, metavar="MS", help="آستانه‌ی علامت‌گذاری کانفیگ ضعیف")
    g.add_argument("--no-ip-check", action="store_true", help="تشخیص IP خروجی انجام نشود")
    g.add_argument("--no-geo", action="store_true", help="غنی‌سازی کشور/ISP انجام نشود")

    g = p.add_argument_group("هسته‌ی Xray")
    g.add_argument("--xray", metavar="PATH", help="مسیر فایل اجرایی xray")
    g.add_argument("--log-level", choices=["none", "error", "warning", "info", "debug"],
                   help="سطح لاگ هسته (برای عیب‌یابی یک کانفیگ)")
    g.add_argument("--start-timeout", type=float, metavar="SEC", help="مهلت بالا آمدن هسته")
    g.add_argument("--allow-insecure", action="store_true", default=None,
                   help="خطای گواهی TLS نادیده گرفته شود")
    g.add_argument("--mux", action="store_true", default=None, help="فعال‌سازی Mux")
    g.add_argument("--ports", metavar="A-B", help="محدوده‌ی پورت محلی، مثل 21000-22000")

    g = p.add_argument_group("کش")
    g.add_argument("--no-cache", action="store_true", help="کش غیرفعال شود")
    g.add_argument("--fresh", action="store_true", help="کش پاک شود و همه از نو تست شوند")
    g.add_argument("--cache-ttl", type=float, metavar="HOURS", help="عمر مفید نتایج کش")
    g.add_argument("--retest-failed", action="store_true", default=None,
                   help="کانفیگ‌های ناموفقِ کش‌شده دوباره تست شوند")

    g = p.add_argument_group("خروجی")
    g.add_argument("-o", "--out", metavar="DIR", help="پوشه‌ی خروجی")
    g.add_argument("--sort", choices=["latency", "name", "protocol", "country"], help="ترتیب نتایج")
    g.add_argument("--working-only", action="store_true", help="کانفیگ‌های ناموفق در گزارش نیایند")
    g.add_argument("--open", action="store_true", help="گزارش HTML بعد از اتمام باز شود")
    g.add_argument("-q", "--quiet", action="store_true", help="فقط خلاصه چاپ شود")
    g.add_argument("-v", "--verbose", action="store_true", help="جزئیات بیشتر")

    return p


def overrides_from_args(args: argparse.Namespace) -> Dict[str, Any]:
    only: Optional[List[str]] = None
    if args.only:
        only = [x.strip().lower() for x in args.only.split(",") if x.strip()]

    overrides: Dict[str, Any] = {
        "input.subs_file": args.subs,
        "input.fetch_proxy": args.fetch_proxy,
        "input.user_agent": args.user_agent,
        "test.concurrency": args.concurrency,
        "test.attempts": args.attempts,
        "test.attempt_timeout": args.timeout,
        "test.retries": args.retries,
        "test.latency_url": args.url,
        "test.limit": args.limit,
        "test.shuffle": args.shuffle,
        "test.only_protocols": only,
        "test.max_latency_ms": args.max_latency,
        "test.ip_check": False if args.no_ip_check else None,
        "test.geo_enrich": False if args.no_geo else None,
        "xray.binary": args.xray,
        "xray.log_level": args.log_level,
        "xray.start_timeout": args.start_timeout,
        "xray.allow_insecure": args.allow_insecure,
        "xray.mux_enabled": args.mux,
        "cache.enabled": False if args.no_cache else None,
        "cache.ttl_hours": args.cache_ttl,
        "cache.retest_failed": args.retest_failed,
        "output.dir": args.out,
        "output.sort_by": args.sort,
        "output.include_failed": False if args.working_only else None,
    }

    if args.ports:
        try:
            start_s, _, end_s = args.ports.partition("-")
            overrides["xray.port_start"] = int(start_s)
            overrides["xray.port_end"] = int(end_s)
        except ValueError:
            raise SystemExit("قالب --ports باید مثل 21000-22000 باشد")

    return overrides


def print_summary(payload: Dict[str, Any], written: Dict[str, Path], log: Logger) -> None:
    s = payload["summary"]
    log.heading("خلاصه")

    def row(label: str, value: str) -> None:
        log.raw(f"  {label:.<32} {value}")

    row("کانفیگ استخراج‌شده", str(s["links_extracted"]))
    row("تکراری حذف‌شده", str(s["duplicates"]))
    row("تست‌شده", str(s["tested_total"]))
    if s.get("from_cache"):
        row("از کش", str(s["from_cache"]))
    row("سالم", log.paint(f"{s['working']}  ({s['success_rate']}٪)", "green", "bold"))
    row("ناموفق", str(s["failed"]))
    if s["best_ms"] is not None:
        row("بهترین پینگ", f"{s['best_ms']:.0f} ms")
        row("میانه‌ی پینگ", f"{s['median_ms']:.0f} ms")
        row("کشور یکتا", str(s["countries_count"]))

    if written:
        log.heading("فایل‌های خروجی")
        labels = {
            "html": "گزارش HTML", "json": "خروجی JSON",
            "working": "کانفیگ‌های سالم", "subscription": "سابسکریپشن base64",
        }
        for key, path in written.items():
            log.raw(f"  {labels.get(key, key):.<32} {path}")


def main(argv: Optional[List[str]] = None) -> int:
    enable_utf8_console()
    args = build_parser().parse_args(argv)

    level = "warn" if args.quiet else ("debug" if args.verbose else "info")
    log = Logger(level)

    if not args.quiet:
        log.raw(log.paint(BANNER, "cyan"))

    root = Path(__file__).resolve().parent.parent
    try:
        settings = Settings.load(args.config, root=str(root))
    except (FileNotFoundError, ValueError) as exc:
        log.error(str(exc))
        return 2

    settings.apply_overrides(overrides_from_args(args))

    try:
        settings.validate()
    except ValueError as exc:
        log.error("تنظیمات نامعتبر است:")
        log.raw(str(exc))
        return 2

    orchestrator = Orchestrator(settings, log, extra_entries=args.link)

    if args.fresh:
        orchestrator.cache.clear()
        log.info("کش پاک شد — همه‌ی کانفیگ‌ها از نو تست می‌شوند")

    interrupts = {"count": 0}

    def on_signal(_signum, _frame):
        interrupts["count"] += 1
        if interrupts["count"] == 1:
            log.warn("توقف درخواست شد — تست‌های در جریان تمام می‌شوند و گزارش ساخته می‌شود.")
            log.warn("برای خروج فوری دوباره Ctrl+C بزنید.")
            orchestrator.request_stop()
        else:
            # بار دوم یعنی کاربر عجله دارد: هسته‌ها بسته و بلافاصله خارج می‌شویم
            log.warn("خروج فوری...")
            raise KeyboardInterrupt

    signal.signal(signal.SIGINT, on_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, on_signal)
    if hasattr(signal, "SIGBREAK"):
        # Ctrl+Break روی ویندوز سیگنال جداگانه‌ای است و SIGINT آن را نمی‌گیرد
        signal.signal(signal.SIGBREAK, on_signal)

    try:
        outcome = orchestrator.run()
    except KeyboardInterrupt:
        log.warn("اجرا توسط کاربر متوقف شد. نتایج در کش هستند؛ "
                 "اجرای بعدی از همین‌جا ادامه می‌دهد.")
        return 130
    except RuntimeError as exc:
        log.error(str(exc))
        return 1
    except Exception as exc:  # noqa: BLE001
        log.error(f"خطای پیش‌بینی‌نشده: {type(exc).__name__}: {exc}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    print_summary(outcome["payload"], outcome["written"], log)

    html_path = outcome["written"].get("html")
    if args.open and html_path:
        import webbrowser
        webbrowser.open(html_path.resolve().as_uri())

    return 0
