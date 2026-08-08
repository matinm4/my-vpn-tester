"""مدل‌های داده‌ی مشترک بین ماژول‌ها."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# پروتکل‌هایی که هسته‌ی Xray به عنوان outbound پشتیبانی می‌کند
SUPPORTED_PROTOCOLS = ("vmess", "vless", "trojan", "shadowsocks", "socks", "http")

# پروتکل‌هایی که ممکن است در سابسکریپشن باشند ولی Xray پشتیبانی نمی‌کند
UNSUPPORTED_SCHEMES = {
    "hysteria": "Hysteria توسط هسته‌ی Xray پشتیبانی نمی‌شود",
    "hysteria2": "Hysteria2 توسط هسته‌ی Xray پشتیبانی نمی‌شود",
    "hy2": "Hysteria2 توسط هسته‌ی Xray پشتیبانی نمی‌شود",
    "tuic": "TUIC توسط هسته‌ی Xray پشتیبانی نمی‌شود",
    "ssr": "ShadowsocksR توسط هسته‌ی Xray پشتیبانی نمی‌شود",
    "snell": "Snell توسط هسته‌ی Xray پشتیبانی نمی‌شود",
    "juicity": "Juicity توسط هسته‌ی Xray پشتیبانی نمی‌شود",
    "wireguard": "WireGuard از لینک سابسکریپشن پشتیبانی نمی‌شود",
}


class ParseError(ValueError):
    """لینک قابل تبدیل به کانفیگ نیست."""


@dataclass
class ProxyConfig:
    """یک کانفیگ پراکسی که به شکل یکدست بین همه‌ی پروتکل‌ها نرمال شده است."""

    raw: str = ""
    protocol: str = ""
    address: str = ""
    port: int = 0
    remark: str = ""

    # ---- اعتبارنامه ----
    uuid: str = ""              # vmess / vless
    password: str = ""          # trojan / shadowsocks / socks / http
    username: str = ""          # socks / http
    method: str = ""            # shadowsocks
    alter_id: int = 0           # vmess
    vmess_security: str = "auto"
    vless_encryption: str = "none"
    flow: str = ""              # vless xtls-rprx-vision

    # ---- ترنسپورت ----
    network: str = "tcp"        # tcp | ws | grpc | h2 | quic | kcp | httpupgrade | xhttp
    security: str = "none"      # none | tls | reality
    sni: str = ""
    host: str = ""              # هدر Host
    path: str = ""
    alpn: str = ""
    fp: str = ""                # uTLS fingerprint
    header_type: str = ""       # none | http | srtp | ...
    service_name: str = ""      # grpc
    grpc_mode: str = ""         # gun | multi
    xhttp_mode: str = ""        # auto | packet-up | stream-up | stream-one
    seed: str = ""              # mKCP
    quic_security: str = ""
    quic_key: str = ""
    allow_insecure: bool = False

    # ---- REALITY ----
    public_key: str = ""
    short_id: str = ""
    spider_x: str = ""

    # ---- دفترداری ----
    source: str = ""
    index: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)

    _fp_cache: Optional[str] = field(default=None, repr=False, compare=False)

    # ------------------------------------------------------------------

    def fingerprint(self) -> str:
        """اثر انگشت پارامترهای اتصال — پایه‌ی تشخیص کانفیگ تکراری.

        عمداً «نام کانفیگ» و پارامترهای صرفاً نمایشی داخل آن نیستند، تا دو
        کانفیگ کاملاً یکسان با اسم متفاوت تکراری تشخیص داده شوند.
        """
        if self._fp_cache:
            return self._fp_cache
        parts = [
            self.protocol,
            self.address.strip().lower().rstrip("."),
            str(self.port),
            self.uuid or self.password,
            self.username,
            self.method,
            self.network,
            self.security,
            self.sni.strip().lower(),
            self.host.strip().lower(),
            self.path,
            self.service_name,
            self.header_type,
            self.flow,
            self.public_key,
            self.short_id,
        ]
        blob = "|".join(p or "" for p in parts)
        self._fp_cache = hashlib.sha1(blob.encode("utf-8")).hexdigest()[:16]
        return self._fp_cache

    @property
    def name(self) -> str:
        return self.remark or f"{self.protocol}-{self.address}:{self.port}"

    @property
    def endpoint(self) -> str:
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"{host}:{self.port}"

    @property
    def transport(self) -> str:
        """توصیف کوتاه ترنسپورت برای نمایش، مثل «ws+tls»."""
        sec = "" if self.security in ("", "none") else f"+{self.security}"
        return f"{self.network}{sec}"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("_fp_cache", None)
        d["fingerprint"] = self.fingerprint()
        d["name"] = self.name
        d["transport"] = self.transport
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ProxyConfig":
        """بازسازی از خروجی to_dict — کلیدهای مشتق‌شده نادیده گرفته می‌شوند."""
        fields = {f for f in cls.__dataclass_fields__ if f != "_fp_cache"}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in fields})


@dataclass
class TestResult:
    """نتیجه‌ی تست یک کانفیگ."""

    fingerprint: str = ""
    ok: bool = False

    # مرحله‌ای که کار در آن متوقف شد: start | probe | done
    stage: str = ""
    error: str = ""

    latency_ms: Optional[float] = None      # کمینه‌ی نمونه‌های گرم — عدد اصلی
    handshake_ms: Optional[float] = None    # درخواست سرد اول (شامل برقراری تونل)
    avg_ms: Optional[float] = None
    max_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    samples: List[float] = field(default_factory=list)

    attempts_ok: int = 0
    attempts_total: int = 0
    rounds: int = 0                          # چند بار کل کانفیگ از نو تست شد

    exit_ip: str = ""
    country_code: str = ""
    country: str = ""
    city: str = ""
    isp: str = ""
    asn: str = ""

    tested_at: float = 0.0
    duration_s: float = 0.0
    from_cache: bool = False

    config: Dict[str, Any] = field(default_factory=dict)

    @property
    def quality(self) -> str:
        """دسته‌بندی کیفیت بر اساس پینگ — برای رنگ/برچسب در گزارش.

        آستانه‌ها با واقعیت پراکسی از یک شبکه‌ی فیلترشده تنظیم شده‌اند، نه با
        پینگ شبکه‌ی محلی: زیر ۵۰۰ میلی‌ثانیه عملاً بهترین چیزی است که می‌شود
        انتظار داشت.
        """
        if not self.ok or self.latency_ms is None:
            return "dead"
        ms = self.latency_ms
        if ms < 500:
            return "excellent"
        if ms < 900:
            return "good"
        if ms < 1800:
            return "fair"
        return "poor"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TestResult":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})
