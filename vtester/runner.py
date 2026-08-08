"""اجرای تست پینگ واقعی: بالا آوردن هسته‌ی Xray و عبور ترافیک واقعی از تونل."""

from __future__ import annotations

import json
import os
import shutil
import socket
import statistics
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from . import procguard
from .models import ProxyConfig, TestResult
from .xraycfg import BuildError, build_full_config

# روی ویندوز از باز شدن پنجره‌ی کنسول برای هر پروسه‌ی xray جلوگیری می‌کند
_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


class ProbeError(RuntimeError):
    """درخواست از داخل تونل ناموفق بود."""


class StartupError(RuntimeError):
    """هسته‌ی Xray بالا نیامد."""


# ---------------------------------------------------------------------------
# مدیریت پورت
# ---------------------------------------------------------------------------

class PortPool:
    """تخصیص thread-safe پورت محلی از یک محدوده."""

    def __init__(self, start: int, end: int) -> None:
        self._ports = list(range(start, end + 1))
        self._cursor = 0
        self._in_use: set[int] = set()
        self._lock = threading.Lock()

    @staticmethod
    def _is_free(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            try:
                sock.bind(("127.0.0.1", port))
                return True
            except OSError:
                return False

    def acquire(self) -> int:
        with self._lock:
            total = len(self._ports)
            for _ in range(total):
                port = self._ports[self._cursor % total]
                self._cursor += 1
                if port in self._in_use:
                    continue
                if self._is_free(port):
                    self._in_use.add(port)
                    return port
            raise StartupError("هیچ پورت آزادی در محدوده‌ی تعیین‌شده نیست")

    def release(self, port: int) -> None:
        with self._lock:
            self._in_use.discard(port)


# ---------------------------------------------------------------------------
# پروسه‌ی Xray
# ---------------------------------------------------------------------------

class XrayInstance:
    """یک نمونه‌ی موقت Xray با اینباند SOCKS محلی؛ به شکل context manager."""

    def __init__(self, cfg: ProxyConfig, settings, port_pool: PortPool) -> None:
        self.cfg = cfg
        self.settings = settings
        self.pool = port_pool
        self.port: Optional[int] = None
        self.workdir: Optional[str] = None
        self.proc: Optional[subprocess.Popen] = None
        self._log_path: Optional[Path] = None

    def __enter__(self) -> "XrayInstance":
        self.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.stop()

    # ------------------------------------------------------------------

    def start(self) -> None:
        self.port = self.pool.acquire()
        self.workdir = tempfile.mkdtemp(prefix="vtester-")
        config_path = Path(self.workdir) / "config.json"
        self._log_path = Path(self.workdir) / "xray.log"

        doc = build_full_config(self.cfg, self.port, self.settings)
        config_path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")

        binary = self.settings.path_of("xray.binary")
        env = os.environ.copy()
        env["XRAY_LOCATION_ASSET"] = str(self.settings.path_of("xray.assets_dir"))

        log_handle = open(self._log_path, "wb")
        try:
            self.proc = subprocess.Popen(
                [str(binary), "run", "-c", str(config_path)],
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                cwd=str(self.settings.root),
                env=env,
                creationflags=_CREATE_NO_WINDOW,
            )
        finally:
            log_handle.close()

        # اگر برنامه ناگهانی بمیرد، ویندوز این پروسه را هم می‌بندد
        procguard.adopt(self.proc)

        self._wait_until_ready()

    def _wait_until_ready(self) -> None:
        """صبر می‌کند تا اینباند SOCKS واقعاً به اتصال پاسخ دهد."""
        timeout = float(self.settings.get("xray.start_timeout", 8.0))
        deadline = time.monotonic() + timeout
        assert self.port is not None

        while time.monotonic() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                raise StartupError(f"هسته زودهنگام خارج شد: {self._tail_log()}")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.3):
                    return
            except OSError:
                time.sleep(0.05)

        raise StartupError(f"اینباند در {timeout:g} ثانیه بالا نیامد: {self._tail_log()}")

    def _tail_log(self, limit: int = 200) -> str:
        if not self._log_path or not self._log_path.exists():
            return "بدون لاگ"
        try:
            text = self._log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "بدون لاگ"
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        # خطوط بنر نسخه و اطلاعات عمومی به درد تشخیص خطا نمی‌خورند
        useful = [
            l for l in lines
            if "Xray" not in l.split("]")[0] and "[Info]" not in l and "anti-censorship" not in l
        ]
        chosen = (useful or lines)[-2:]
        return " | ".join(chosen)[:limit] if chosen else "بدون لاگ"

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            try:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=3)
            except OSError:
                pass
        self.proc = None

        if self.port is not None:
            self.pool.release(self.port)
            self.port = None

        if self.workdir:
            shutil.rmtree(self.workdir, ignore_errors=True)
            self.workdir = None

    @property
    def proxies(self) -> Dict[str, str]:
        # socks5h یعنی رزولوشن DNS هم از داخل تونل انجام شود — همان کاری که
        # یک کلاینت واقعی می‌کند.
        url = f"socks5h://127.0.0.1:{self.port}"
        return {"http": url, "https": url}


# ---------------------------------------------------------------------------
# سنجش
# ---------------------------------------------------------------------------

def _probe_once(proxies: Dict[str, str], url: str, timeout: float,
                accept_status: List[int], user_agent: str) -> Tuple[float, str]:
    """یک درخواست HTTP واقعی از داخل تونل؛ خروجی: (میلی‌ثانیه، بدنه)."""
    session = requests.Session()
    session.trust_env = False  # پروکسی سیستمی نباید در اندازه‌گیری دخالت کند
    try:
        start = time.perf_counter()
        resp = session.get(
            url,
            proxies=proxies,
            timeout=timeout,
            headers={"User-Agent": user_agent, "Cache-Control": "no-cache"},
            allow_redirects=False,
        )
        body = resp.content[:4096].decode("utf-8", errors="replace")
        elapsed_ms = (time.perf_counter() - start) * 1000.0
    except requests.exceptions.ConnectTimeout:
        raise ProbeError("تایم‌اوت در اتصال") from None
    except requests.exceptions.ReadTimeout:
        raise ProbeError("تایم‌اوت در دریافت پاسخ") from None
    except requests.exceptions.ProxyError as exc:
        raise ProbeError(f"اتصال از تونل برقرار نشد: {_short_exc(exc)}") from None
    except requests.exceptions.SSLError:
        raise ProbeError("خطای گواهی TLS") from None
    except requests.RequestException as exc:
        raise ProbeError(_short_exc(exc)) from None
    finally:
        session.close()

    if accept_status and resp.status_code not in accept_status:
        raise ProbeError(f"کد وضعیت غیرمنتظره: HTTP {resp.status_code}")
    return elapsed_ms, body


def _short_exc(exc: Exception) -> str:
    """پیام‌های خام urllib3 طولانی و نامفهوم‌اند؛ به علت واقعی ترجمه می‌شوند."""
    text = str(exc)
    lowered = text.lower()

    # ترتیب مهم است: از خاص به عام
    patterns = [
        ("10054", "اتصال توسط سرور قطع شد"),
        ("connectionreset", "اتصال توسط سرور قطع شد"),
        ("reset by peer", "اتصال توسط سرور قطع شد"),
        ("remotedisconnected", "سرور بدون پاسخ اتصال را بست"),
        ("without response", "سرور بدون پاسخ اتصال را بست"),
        ("10061", "اتصال رد شد"),
        ("connection refused", "اتصال رد شد"),
        ("0x01: general socks server failure", "سرور مقصد در دسترس نیست"),
        ("0x04: host unreachable", "میزبان مقصد در دسترس نیست"),
        ("0x03: network unreachable", "شبکه‌ی مقصد در دسترس نیست"),
        ("name or service not known", "نام دامنه resolve نشد"),
        ("getaddrinfo", "نام دامنه resolve نشد"),
        ("timed out", "تایم‌اوت"),
        ("bad handshake", "هندشیک ناموفق"),
        ("connection aborted", "اتصال نیمه‌کاره قطع شد"),
    ]
    for needle, message in patterns:
        if needle in lowered:
            return message

    collapsed = " ".join(text.split())
    return collapsed[:90]


def _parse_ip_info(body: str) -> Dict[str, str]:
    """پاسخ سرویس تشخیص IP را می‌خواند — هم فرمت trace و هم JSON."""
    info: Dict[str, str] = {}
    stripped = body.strip()

    if stripped.startswith("{"):
        try:
            doc = json.loads(stripped)
        except json.JSONDecodeError:
            return info
        if not isinstance(doc, dict):
            return info
        for key in ("query", "ip", "YourFuckingIPAddress", "origin"):
            if doc.get(key):
                info["ip"] = str(doc[key]).split(",")[0].strip()
                break
        if doc.get("countryCode"):
            info["country_code"] = str(doc["countryCode"]).upper()
        if doc.get("country"):
            info["country"] = str(doc["country"])
        if doc.get("city"):
            info["city"] = str(doc["city"])
        if doc.get("isp"):
            info["isp"] = str(doc["isp"])
        if doc.get("as"):
            info["asn"] = str(doc["as"])
        return info

    # فرمت cdn-cgi/trace :  key=value در هر خط
    for line in stripped.splitlines():
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key == "ip":
            info["ip"] = value
        elif key == "loc":
            info["country_code"] = value.upper()
    return info


# ---------------------------------------------------------------------------
# تست یک کانفیگ
# ---------------------------------------------------------------------------

class ConfigTester:
    def __init__(self, settings, port_pool: PortPool, stop_event: threading.Event) -> None:
        self.settings = settings
        self.pool = port_pool
        self.stop_event = stop_event

        self.attempts = max(1, int(settings.get("test.attempts", 3)))
        self.attempt_timeout = float(settings.get("test.attempt_timeout", 8.0))
        self.latency_url = settings.get("test.latency_url")
        self.accept_status = list(settings.get("test.accept_status") or [])
        self.retries = max(0, int(settings.get("test.retries", 1)))
        self.retry_delay = float(settings.get("test.retry_delay", 1.0))
        self.ip_check = bool(settings.get("test.ip_check", True))
        self.ip_check_url = settings.get("test.ip_check_url")
        self.ip_check_timeout = float(settings.get("test.ip_check_timeout", 10.0))
        self.user_agent = settings.get("input.user_agent", "v2rayN/6.45")

    # ------------------------------------------------------------------

    def test(self, cfg: ProxyConfig) -> TestResult:
        result = TestResult(
            fingerprint=cfg.fingerprint(),
            config=cfg.to_dict(),
            tested_at=time.time(),
            attempts_total=self.attempts,
        )
        started = time.perf_counter()

        # کانفیگی که اصلاً به outbound معتبر تبدیل نمی‌شود، بی‌خود پروسه نگیرد
        try:
            build_full_config(cfg, 0, self.settings)
        except BuildError as exc:
            result.stage = "build"
            result.error = str(exc)
            result.duration_s = time.perf_counter() - started
            return result

        last_error = ""
        last_stage = "start"

        for round_index in range(self.retries + 1):
            if self.stop_event.is_set():
                result.stage = "aborted"
                result.error = "لغو شد"
                result.duration_s = time.perf_counter() - started
                return result

            result.rounds = round_index + 1
            try:
                self._run_round(cfg, result)
                result.ok = True
                result.stage = "done"
                result.error = ""
                result.duration_s = time.perf_counter() - started
                return result
            except StartupError as exc:
                last_stage, last_error = "start", str(exc)
            except ProbeError as exc:
                last_stage, last_error = "probe", str(exc)
            except Exception as exc:  # noqa: BLE001 - نباید یک کانفیگ کل اجرا را بخواباند
                last_stage, last_error = "internal", f"{type(exc).__name__}: {exc}"[:140]

            if round_index < self.retries and not self.stop_event.is_set():
                time.sleep(self.retry_delay)

        result.ok = False
        result.stage = last_stage
        result.error = last_error
        result.duration_s = time.perf_counter() - started
        return result

    # ------------------------------------------------------------------

    def _run_round(self, cfg: ProxyConfig, result: TestResult) -> None:
        with XrayInstance(cfg, self.settings, self.pool) as instance:
            proxies = instance.proxies

            # درخواست اول سرد است: شامل برقراری تونل و هندشیک TLS با سرور
            handshake_ms, _ = _probe_once(
                proxies, self.latency_url, self.attempt_timeout,
                self.accept_status, self.user_agent,
            )
            result.handshake_ms = round(handshake_ms, 1)

            # درخواست‌های بعدی گرم‌اند و رفت‌وبرگشت خالص شبکه را نشان می‌دهند
            samples: List[float] = []
            errors: List[str] = []
            for _ in range(self.attempts - 1):
                if self.stop_event.is_set():
                    break
                try:
                    elapsed, _ = _probe_once(
                        proxies, self.latency_url, self.attempt_timeout,
                        self.accept_status, self.user_agent,
                    )
                    samples.append(elapsed)
                except ProbeError as exc:
                    errors.append(str(exc))

            # اگر همه‌ی نمونه‌های گرم شکست خوردند ولی سرد موفق بود، کانفیگ ناپایدار است
            if not samples and errors:
                raise ProbeError(f"اتصال ناپایدار: {errors[-1]}")

            measured = samples or [handshake_ms]
            result.samples = [round(s, 1) for s in measured]
            result.latency_ms = round(min(measured), 1)
            result.avg_ms = round(statistics.fmean(measured), 1)
            result.max_ms = round(max(measured), 1)
            result.jitter_ms = round(statistics.pstdev(measured), 1) if len(measured) > 1 else 0.0
            result.attempts_ok = 1 + len(samples)

            if self.ip_check and not self.stop_event.is_set():
                self._collect_ip_info(proxies, result)

    def _collect_ip_info(self, proxies: Dict[str, str], result: TestResult) -> None:
        """تشخیص IP خروجی — شکستش نباید کانفیگ سالم را ناموفق کند."""
        try:
            _, body = _probe_once(
                proxies, self.ip_check_url, self.ip_check_timeout,
                [200], self.user_agent,
            )
        except ProbeError:
            return
        info = _parse_ip_info(body)
        result.exit_ip = info.get("ip", "")
        result.country_code = info.get("country_code", "")
        result.country = info.get("country", "")
        result.city = info.get("city", "")
        result.isp = info.get("isp", "")
        result.asn = info.get("asn", "")
