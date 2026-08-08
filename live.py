#!/usr/bin/env python3
"""سرویس دائمی: دریافت خودکار از تلگرام + لینک ساب، تست پینگ واقعی، استخر زنده.

  python live.py              سرویس دائمی
  python live.py --once       فقط یک دور کامل
  python live.py --pool-only  فقط بازبینی استخر (بدون دریافت)
  python live.py --help
"""

from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path

from vtester.live import LiveService
from vtester.logging_util import Logger, enable_utf8_console
from vtester.settings import Settings

BANNER = r"""
  ┌──────────────────────────────────────────────────────┐
  │   V-Tester Live · دریافت خودکار + تست پینگ واقعی      │
  └──────────────────────────────────────────────────────┘
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="live.py",
        description="سرویس دائمی دریافت کانفیگ از تلگرام و لینک ساب، با تست پینگ واقعی.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "نمونه‌ها:\n"
            "  python live.py                    سرویس دائمی\n"
            "  python live.py --once             یک دور کامل و خروج\n"
            "  python live.py --pool-only        فقط بازبینی ۲۰ تای برتر\n"
            "  python live.py --no-telegram      فقط از لینک‌های ساب\n"
            "  python live.py --skip-gate        بدون توقف برای خاموش کردن فیلترشکن\n"
            "  python live.py --pool-size 30     استخر ۳۰تایی\n"
        ),
    )
    p.add_argument("-c", "--config", metavar="FILE", help="مسیر فایل تنظیمات")
    p.add_argument("--once", action="store_true", help="فقط یک دور کامل و خروج")
    p.add_argument("--pool-only", action="store_true", help="فقط بازبینی استخر")
    p.add_argument("--no-telegram", action="store_true", help="تلگرام غیرفعال شود")
    p.add_argument("--skip-gate", action="store_true",
                   help="بدون مکث برای خاموش کردن فیلترشکن (اگر از قبل خاموش است)")
    p.add_argument("--pool-size", type=int, metavar="N", help="اندازه‌ی استخر برتر")
    p.add_argument("--batch-size", type=int, metavar="N", help="اندازه‌ی هر فایل دسته‌ای")
    p.add_argument("-j", "--concurrency", type=int, metavar="N", help="تعداد تست همزمان")
    p.add_argument("--discovery-interval", type=float, metavar="MIN",
                   help="فاصله‌ی دورهای کشف (دقیقه)")
    p.add_argument("--pool-interval", type=float, metavar="MIN",
                   help="فاصله‌ی بازبینی استخر (دقیقه)")
    p.add_argument("--gate-minutes", type=float, metavar="MIN",
                   help="مهلت خاموش کردن فیلترشکن (دقیقه)")
    p.add_argument("--max-test", type=int, metavar="N",
                   help="حداکثر کانفیگ تست‌شده در هر دور")
    p.add_argument("-v", "--verbose", action="store_true", help="جزئیات بیشتر")
    p.add_argument("-q", "--quiet", action="store_true", help="فقط پیام‌های مهم")
    return p


def main(argv=None) -> int:
    enable_utf8_console()
    args = build_parser().parse_args(argv)

    level = "warn" if args.quiet else ("debug" if args.verbose else "info")
    log = Logger(level)
    if not args.quiet:
        log.raw(log.paint(BANNER, "cyan"))

    root = Path(__file__).resolve().parent
    try:
        settings = Settings.load(args.config, root=str(root))
    except (FileNotFoundError, ValueError) as exc:
        log.error(str(exc))
        return 2

    overrides = {
        "telegram.enabled": False if args.no_telegram else None,
        "pool.size": args.pool_size,
        "pool.batch_size": args.batch_size,
        "test.concurrency": args.concurrency,
        "live.discovery_interval_minutes": args.discovery_interval,
        "live.pool_interval_minutes": args.pool_interval,
        "live.batch_test_size": args.max_test,
        "vpn_gate.wait_minutes": args.gate_minutes,
        "vpn_gate.enabled": False if args.skip_gate else None,
    }
    settings.apply_overrides(overrides)

    try:
        settings.validate()
    except ValueError as exc:
        log.error("تنظیمات نامعتبر است:")
        log.raw(str(exc))
        return 2

    service = LiveService(settings, log)

    interrupts = {"count": 0}

    def on_signal(_signum, _frame):
        interrupts["count"] += 1
        if interrupts["count"] == 1:
            log.warn("توقف درخواست شد — کار جاری تمام می‌شود و خروجی‌ها ذخیره می‌شوند.")
            log.warn("برای خروج فوری دوباره Ctrl+C بزنید.")
            service.request_stop()
        else:
            log.warn("خروج فوری...")
            raise KeyboardInterrupt

    signal.signal(signal.SIGINT, on_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, on_signal)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, on_signal)

    exit_code = 0
    try:
        if args.pool_only:
            service.migrate_legacy()
            service.run_pool_cycle()
        elif args.once:
            service.migrate_legacy()
            service.run_discovery_cycle(skip_gate=args.skip_gate)
        else:
            service.run_forever(skip_gate=args.skip_gate)
    except KeyboardInterrupt:
        log.warn("متوقف شد. داده‌ها در پایگاه داده محفوظ‌اند.")
        exit_code = 130
    except RuntimeError as exc:
        log.error(str(exc))
        exit_code = 1
    except Exception as exc:  # noqa: BLE001
        log.error(f"خطای پیش‌بینی‌نشده: {type(exc).__name__}: {exc}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        exit_code = 1
    finally:
        service.close()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
