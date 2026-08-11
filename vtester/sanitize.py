"""پاک‌سازی نام کانفیگ‌ها پیش از انتشار عمومی.

نام کانفیگ (بخش «#...» در انتهای لینک، و فیلد «ps» در vmess) جای امنی نیست:
منبع‌ها معمولاً آی‌دی تلگرام، لینک کانال و متن تبلیغاتی داخلش می‌گذارند و
همان متن در کلاینت کاربر ظاهر می‌شود.

به‌جای تشخیص و حذف الگوهای تبلیغاتی، نام را **کامل بازنویسی** می‌کنیم. تشخیص
الگو همیشه از قلم می‌اندازد — تبلیغ تازه، اموجی، یونیکد شبیه‌ساز — ولی
بازنویسی کامل تضمین می‌کند هیچ متن ورودی به خروجی نرسد.

فقط نام عوض می‌شود. هیچ فیلد کارکردی (آدرس، پورت، uuid، sni، path، ...) دست
نمی‌خورد، پس کانفیگ دقیقاً مثل قبل کار می‌کند. اثر انگشت هم عوض نمی‌شود چون
نام عمداً در محاسبه‌ی اثر انگشت نیست.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, Optional

from .geo import flag_emoji

# کاراکترهایی که یک نام هرگز نباید داشته باشد: «#» مرز خود نام است، فاصله‌ی
# عمودی و کاراکتر کنترلی می‌تواند فایل خطی را دو تکه کند.
_FORBIDDEN = re.compile(r"[#\r\n\t\x00-\x1f\x7f]")


def clean_name(country_code: str = "", latency_ms: Optional[float] = None,
               rank: int = 0, tag: str = "") -> str:
    """نام تازه‌ی یک کانفیگ — فقط از داده‌ی سنجیده‌شده‌ی خودمان ساخته می‌شود.

    قالب: «🇩🇪 DE-01 | 210ms». اگر کشور معلوم نباشد XX می‌گذاریم تا شمارش
    و ترتیب به‌هم نریزد.
    """
    code = (country_code or "").strip().upper()[:2]
    parts = []

    if tag:
        parts.append(_FORBIDDEN.sub("", tag).strip())

    # پرچم را قبل از جایگزینی XX می‌گیریم: «XX» کد کشور واقعی نیست و
    # پرچمش یک مربع بی‌معنی می‌شود. «ZZ»/«XX» را هم منبع‌ها گاهی به‌جای
    # «نامشخص» می‌فرستند، پس مثل خالی با آن‌ها رفتار می‌کنیم.
    if code in ("XX", "ZZ", "??"):
        code = ""
    flag = flag_emoji(code) if code.isalpha() else ""
    code = code or "XX"
    label = f"{code}-{rank:02d}" if rank > 0 else code
    parts.append(f"{flag} {label}".strip() if flag else label)

    if latency_ms is not None:
        parts.append(f"{latency_ms:.0f}ms")

    return " | ".join(p for p in parts if p)


def _rewrite_vmess(raw: str, name: str) -> Optional[str]:
    """نام را داخل JSON بیس۶۴ vmess عوض می‌کند.

    خروجی None یعنی این لینک vmess کلاسیک نیست (فرمت URI است) و باید مثل
    بقیه‌ی پروتکل‌ها با جایگزینی fragment رفتار شود.
    """
    body = raw[len("vmess://"):].strip().split("#", 1)[0]
    if not body:
        return None

    cleaned = re.sub(r"\s+", "", body).replace("-", "+").replace("_", "/")
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        decoded = base64.b64decode(cleaned, validate=False).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if not decoded.lstrip().startswith("{"):
        return None

    try:
        doc: Any = json.loads(decoded)
    except json.JSONDecodeError:
        return None
    if not isinstance(doc, dict):
        return None

    # «ps» نام استاندارد است؛ بعضی تولیدکننده‌ها «remarks» می‌نویسند. هر دو
    # را می‌نویسیم تا کلاینت هر کدام را خواند، نام تمیز را ببیند.
    doc["ps"] = name
    if "remarks" in doc:
        doc["remarks"] = name

    blob = json.dumps(doc, ensure_ascii=False, separators=(",", ":"))
    encoded = base64.b64encode(blob.encode("utf-8")).decode("ascii")
    return f"vmess://{encoded}"


def sanitize_link(raw: str, name: str) -> str:
    """لینک را با نام تمیز برمی‌گرداند؛ بقیه‌ی لینک بیت‌به‌بیت دست‌نخورده.

    اگر لینک قابل تشخیص نبود، همان ورودی برمی‌گردد — خروجی ناقص بدتر از
    خروجی با نام قدیمی است، ولی این حالت عملاً پیش نمی‌آید چون هر لینکی که
    به اینجا می‌رسد قبلاً با موفقیت پارس و تست شده است.
    """
    raw = (raw or "").strip()
    if not raw or "://" not in raw:
        return raw

    name = _FORBIDDEN.sub("", name).strip()
    if not name:
        return raw

    if raw.lower().startswith("vmess://"):
        rewritten = _rewrite_vmess(raw, name)
        if rewritten is not None:
            return rewritten

    # بقیه‌ی پروتکل‌ها (و vmess فرمت URI): نام همان fragment انتهایی است.
    # عمداً رشته‌ای می‌بریم و از urlsplit/urlunsplit استفاده نمی‌کنیم تا
    # هیچ نرمال‌سازی ناخواسته‌ای روی بدنه‌ی لینک اعمال نشود.
    return f"{raw.split('#', 1)[0]}#{name}"


def sanitize_result_link(result, rank: int = 0, tag: str = "") -> str:
    """لینک تمیزشده‌ی یک TestResult — میان‌بر متداول در محل‌های خروجی."""
    cfg: Dict[str, Any] = result.config or {}
    return sanitize_link(
        str(cfg.get("raw", "")),
        clean_name(
            country_code=result.country_code or "",
            latency_ms=result.latency_ms,
            rank=rank,
            tag=tag,
        ),
    )
