"""دروازه‌ی VPN بین مرحله‌ی دریافت و مرحله‌ی تست.

مرحله‌ی دریافت از تلگرام به فیلترشکن نیاز دارد. مرحله‌ی تست پینگ *نباید*
با فیلترشکن روشن اجرا شود، وگرنه ترافیک تست از تونل فیلترشکن رد می‌شود و
اعداد پینگ کاملاً بی‌معنا می‌شوند — هر کانفیگ ظاهراً کار می‌کند چون در
واقع فیلترشکن شما دارد کار می‌کند، نه آن کانفیگ.

این ماژول بین دو مرحله می‌ایستد، به کاربر مهلت می‌دهد فیلترشکن را خاموش
کند، و با مقایسه‌ی IP عمومی تشخیص می‌دهد که واقعاً خاموش شده یا نه.
"""

from __future__ import annotations

import queue
import sys
import threading
import time
from dataclasses import dataclass
from typing import Optional, Tuple

import requests


@dataclass
class NetworkIdentity:
    """هویت شبکه‌ای فعلی — برای تشخیص تغییر مسیر خروجی."""

    ip: str = ""
    country: str = ""
    ok: bool = False
    error: str = ""

    def differs_from(self, other: "NetworkIdentity") -> bool:
        """آیا مسیر خروجی عوض شده است؟"""
        if not (self.ok and other.ok):
            return False
        return self.ip != other.ip

    @property
    def label(self) -> str:
        if not self.ok:
            return "نامشخص"
        return f"{self.ip}" + (f" ({self.country})" if self.country else "")


def probe_identity(url: str = "http://cp.cloudflare.com/cdn-cgi/trace",
                   timeout: float = 12.0) -> NetworkIdentity:
    """IP عمومی فعلی را از اتصال مستقیم سیستم می‌خواند."""
    identity = NetworkIdentity()
    session = requests.Session()
    session.trust_env = False  # پروکسی محیطی نباید نتیجه را دستکاری کند
    try:
        resp = session.get(url, timeout=timeout)
        if resp.status_code != 200:
            identity.error = f"HTTP {resp.status_code}"
            return identity
        for line in resp.text.splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "ip":
                identity.ip = value.strip()
            elif key.strip() == "loc":
                identity.country = value.strip().upper()
        identity.ok = bool(identity.ip)
        if not identity.ok:
            identity.error = "پاسخ سرویس قابل تفسیر نبود"
    except requests.RequestException as exc:
        identity.error = f"{type(exc).__name__}"
    finally:
        session.close()
    return identity


class _InputWaiter:
    """خواندن ورودی کاربر در یک نخ جدا تا بشود همزمان تایمر داشت.

    یک نخ برای کل عمر دروازه: اگر برای هر تلاش نخ تازه بسازیم، نخ قبلی هنوز
    روی stdin بلاک است و معلوم نیست ورودی بعدی به کدام‌شان می‌رسد.
    """

    def __init__(self) -> None:
        self._queue: queue.Queue[str] = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self.stdin_available = True

    def start(self) -> None:
        def reader() -> None:
            while True:
                try:
                    line = sys.stdin.readline()
                except (OSError, ValueError):
                    self._queue.put("__no_stdin__")
                    return
                if line == "":  # EOF — اجرای بدون ترمینال
                    self._queue.put("__no_stdin__")
                    return
                self._queue.put(line.strip().lower())

        self._thread = threading.Thread(target=reader, daemon=True)
        self._thread.start()

    def poll(self, timeout: float) -> Optional[str]:
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None


class VpnGate:
    """دروازه‌ی بین دریافت و تست."""

    def __init__(self, settings, logger) -> None:
        self.settings = settings
        self.log = logger
        self.enabled = bool(settings.get("vpn_gate.enabled", True))
        self.wait_minutes = float(settings.get("vpn_gate.wait_minutes", 15))
        self.probe_url = settings.get("vpn_gate.probe_url",
                                      "http://cp.cloudflare.com/cdn-cgi/trace")
        self.require_ip_change = bool(settings.get("vpn_gate.require_ip_change", True))
        self.reminder_interval = float(settings.get("vpn_gate.reminder_seconds", 60))

    # ------------------------------------------------------------------

    def capture_baseline(self) -> NetworkIdentity:
        """IP در حالت «فیلترشکن روشن» — قبل از شروع دریافت صدا زده می‌شود."""
        if not self.enabled:
            return NetworkIdentity()
        identity = probe_identity(self.probe_url)
        if identity.ok:
            self.log.info(f"IP فعلی (با فیلترشکن): {identity.label}")
        else:
            self.log.warn(f"IP فعلی خوانده نشد: {identity.error}")
        return identity

    # ------------------------------------------------------------------

    def wait_for_direct_connection(self, baseline: NetworkIdentity) -> Tuple[bool, str]:
        """منتظر می‌ماند تا کاربر فیلترشکن را خاموش کند.

        خروجی: (اجازه‌ی ادامه, دلیل)
        """
        if not self.enabled:
            return True, "دروازه‌ی VPN غیرفعال است"

        deadline = time.monotonic() + self.wait_minutes * 60.0
        self._print_banner()

        waiter = _InputWaiter()
        waiter.start()
        last_reminder = time.monotonic()
        last_probe = 0.0
        no_stdin = False

        # فاصله‌ی بررسی خودکار IP — هر ۲ ثانیه یعنی صدها درخواست بی‌مورد
        probe_every = float(self.settings.get("vpn_gate.probe_every_seconds", 10))

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            answer = waiter.poll(timeout=min(1.0, remaining))

            if answer == "__no_stdin__":
                # اجرای بدون ترمینال (سرویس/زمان‌بند): فقط به تشخیص IP تکیه کن
                if not no_stdin:
                    self.log.info("ورودی کیبورد در دسترس نیست — منتظر تغییر خودکار IP")
                no_stdin = True
            elif answer is not None:
                ok, reason = self._verify(baseline, user_confirmed=True)
                if ok:
                    return True, reason
                self.log.warn(reason)
                self.log.raw("  فیلترشکن را خاموش کنید و دوباره Enter بزنید.")
                last_reminder = time.monotonic()
                continue

            now = time.monotonic()

            # تشخیص خودکار: اگر IP عوض شد یعنی فیلترشکن خاموش شده
            if (self.require_ip_change and baseline.ok
                    and now - last_probe >= probe_every):
                last_probe = now
                current = probe_identity(self.probe_url, timeout=6.0)
                if current.ok and current.differs_from(baseline):
                    self.log.raw("")
                    self.log.info(f"تغییر مسیر خروجی تشخیص داده شد: "
                                  f"{baseline.label} ← {current.label}")
                    return True, "اتصال مستقیم تشخیص داده شد"

            if now - last_reminder >= self.reminder_interval:
                mins, secs = divmod(int(deadline - now), 60)
                hint = "" if not no_stdin else " (منتظر تغییر IP)"
                self.log.raw(f"  ⏳ {mins:02d}:{secs:02d} باقی مانده{hint}")
                last_reminder = now

        return False, f"مهلت {self.wait_minutes:g} دقیقه‌ای تمام شد و اتصال مستقیم برقرار نشد"

    # ------------------------------------------------------------------

    def _verify(self, baseline: NetworkIdentity, user_confirmed: bool) -> Tuple[bool, str]:
        """بررسی اینکه واقعاً از مسیر مستقیم هستیم."""
        if not self.require_ip_change:
            return True, "تایید کاربر"

        current = probe_identity(self.probe_url, timeout=10.0)

        if not current.ok:
            # اینترنت قطع است یا سرویس در دسترس نیست؛ حرف کاربر را می‌پذیریم
            # ولی صریح می‌گوییم که تایید نشده.
            return True, f"IP قابل بررسی نبود ({current.error}) — تایید کاربر پذیرفته شد"

        if not baseline.ok:
            return True, f"مبنای مقایسه نداشتیم — IP فعلی {current.label}"

        if current.differs_from(baseline):
            return True, f"اتصال مستقیم تایید شد: {baseline.label} ← {current.label}"

        return False, (f"IP هنوز همان {current.label} است — به‌نظر فیلترشکن "
                       f"هنوز روشن است.")

    def _print_banner(self) -> None:
        line = "─" * 62
        self.log.raw("")
        self.log.raw(self.log.paint(f"  ┌{line}┐", "yellow"))
        self.log.raw(self.log.paint("  │  مرحله‌ی دریافت تمام شد.", "yellow", "bold"))
        self.log.raw(self.log.paint("  │", "yellow"))
        self.log.raw(self.log.paint("  │  حالا فیلترشکن را خاموش کنید و Enter بزنید.", "yellow"))
        self.log.raw(self.log.paint("  │", "yellow"))
        self.log.raw(self.log.paint(
            "  │  تست پینگ با فیلترشکن روشن بی‌معناست: ترافیک تست از تونل", "yellow"))
        self.log.raw(self.log.paint(
            "  │  فیلترشکن رد می‌شود و همه‌ی کانفیگ‌ها الکی سالم به نظر", "yellow"))
        self.log.raw(self.log.paint(
            "  │  می‌رسند.", "yellow"))
        self.log.raw(self.log.paint("  │", "yellow"))
        self.log.raw(self.log.paint(
            f"  │  مهلت: {self.wait_minutes:g} دقیقه. بعد از آن اجرا متوقف می‌شود و", "yellow"))
        self.log.raw(self.log.paint(
            "  │  کانفیگ‌های دریافت‌شده ذخیره می‌مانند.", "yellow"))
        self.log.raw(self.log.paint(f"  └{line}┘", "yellow"))
        self.log.raw("")
