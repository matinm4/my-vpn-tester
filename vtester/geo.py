"""غنی‌سازی اطلاعات جغرافیایی IP های خروجی با یک درخواست دسته‌ای."""

from __future__ import annotations

import json
from typing import Callable, ContextManager, Dict, Iterable, List, Optional

import requests

from .models import TestResult

_BATCH_SIZE = 100  # سقف ip-api.com برای هر درخواست


def _batch_lookup(url: str, ips: List[str], proxies: Optional[Dict[str, str]],
                  logger) -> Dict[str, Dict[str, str]]:
    """جست‌وجوی دسته‌ای؛ در صورت هر خطایی دیکشنری خالی برمی‌گرداند."""
    fields = "status,country,countryCode,city,isp,as,query"
    found: Dict[str, Dict[str, str]] = {}

    session = requests.Session()
    session.trust_env = False
    try:
        for start in range(0, len(ips), _BATCH_SIZE):
            chunk = ips[start:start + _BATCH_SIZE]
            payload = [{"query": ip, "fields": fields} for ip in chunk]
            try:
                resp = session.post(url, json=payload, timeout=25, proxies=proxies)
                if resp.status_code != 200:
                    logger.debug(f"غنی‌سازی جغرافیایی: HTTP {resp.status_code}")
                    return found
                doc = resp.json()
            except (requests.RequestException, json.JSONDecodeError) as exc:
                logger.debug(f"غنی‌سازی جغرافیایی ناموفق: {type(exc).__name__}")
                return found

            if not isinstance(doc, list):
                return found
            for entry in doc:
                if not isinstance(entry, dict) or entry.get("status") != "success":
                    continue
                ip = str(entry.get("query", ""))
                if ip:
                    found[ip] = {
                        "country": str(entry.get("country", "")),
                        "country_code": str(entry.get("countryCode", "")).upper(),
                        "city": str(entry.get("city", "")),
                        "isp": str(entry.get("isp", "")),
                        "asn": str(entry.get("as", "")),
                    }
    finally:
        session.close()
    return found


def enrich(
    results: Iterable[TestResult],
    settings,
    logger,
    tunnel: Optional[Callable[[], ContextManager[Optional[Dict[str, str]]]]] = None,
) -> int:
    """کشور/شهر/ISP را برای IP های خروجی یکتا پر می‌کند.

    ابتدا از اتصال مستقیم سیستم تلاش می‌شود. اگر سرویس از شبکه‌ی محلی در
    دسترس نباشد (که در شبکه‌های فیلترشده رایج است) همان درخواست از داخل
    بهترین تونل سالم تکرار می‌شود. شکست کامل بی‌صداست و نتایج تست را
    دست‌نخورده باقی می‌گذارد.
    """
    if not settings.get("test.geo_enrich", True):
        return 0

    items = [r for r in results if r.ok and r.exit_ip]
    # فقط IP هایی که اطلاعات‌شان ناقص است ارزش درخواست دارند
    pending = sorted({r.exit_ip for r in items if not r.isp or not r.country})
    if not pending:
        return 0

    url = settings.get("test.geo_batch_url", "http://ip-api.com/batch")

    lookup = _batch_lookup(url, pending, None, logger)
    if not lookup and tunnel is not None:
        logger.debug("سرویس جغرافیایی از شبکه‌ی محلی در دسترس نیست — از تونل تلاش می‌شود")
        try:
            with tunnel() as proxies:
                if proxies:
                    lookup = _batch_lookup(url, pending, proxies, logger)
        except Exception as exc:  # noqa: BLE001 - غنی‌سازی هرگز نباید اجرا را بخواباند
            logger.debug(f"تونل غنی‌سازی برقرار نشد: {type(exc).__name__}")

    if not lookup:
        return 0

    updated = 0
    for result in items:
        info = lookup.get(result.exit_ip)
        if not info:
            continue
        # داده‌ای که از خود تونل آمده معتبرتر است و بازنویسی نمی‌شود
        result.country = result.country or info["country"]
        result.country_code = result.country_code or info["country_code"]
        result.city = result.city or info["city"]
        result.isp = result.isp or info["isp"]
        result.asn = result.asn or info["asn"]
        updated += 1

    return updated


COUNTRY_NAMES_FA = {
    "AE": "امارات", "AL": "آلبانی", "AM": "ارمنستان", "AR": "آرژانتین", "AT": "اتریش",
    "AU": "استرالیا", "AZ": "آذربایجان", "BE": "بلژیک", "BG": "بلغارستان", "BH": "بحرین",
    "BR": "برزیل", "BY": "بلاروس", "CA": "کانادا", "CH": "سوئیس", "CL": "شیلی",
    "CN": "چین", "CO": "کلمبیا", "CY": "قبرس", "CZ": "چک", "DE": "آلمان",
    "DK": "دانمارک", "EE": "استونی", "EG": "مصر", "ES": "اسپانیا", "FI": "فنلاند",
    "FR": "فرانسه", "GB": "انگلیس", "GE": "گرجستان", "GR": "یونان", "HK": "هنگ‌کنگ",
    "HR": "کرواسی", "HU": "مجارستان", "ID": "اندونزی", "IE": "ایرلند", "IL": "اسرائیل",
    "IN": "هند", "IR": "ایران", "IS": "ایسلند", "IT": "ایتالیا", "JP": "ژاپن",
    "KR": "کره جنوبی", "KW": "کویت", "KZ": "قزاقستان", "LT": "لیتوانی", "LU": "لوکزامبورگ",
    "LV": "لتونی", "MD": "مولداوی", "MX": "مکزیک", "MY": "مالزی", "NL": "هلند",
    "NO": "نروژ", "NZ": "نیوزیلند", "OM": "عمان", "PH": "فیلیپین", "PL": "لهستان",
    "PT": "پرتغال", "QA": "قطر", "RO": "رومانی", "RS": "صربستان", "RU": "روسیه",
    "SA": "عربستان", "SE": "سوئد", "SG": "سنگاپور", "SI": "اسلوونی", "SK": "اسلواکی",
    "TH": "تایلند", "TR": "ترکیه", "TW": "تایوان", "UA": "اوکراین", "US": "آمریکا",
    "UZ": "ازبکستان", "VN": "ویتنام", "ZA": "آفریقای جنوبی",
}


def country_label(code: str, fallback: str = "") -> str:
    code = (code or "").upper()
    if not code:
        return fallback or "نامشخص"
    return COUNTRY_NAMES_FA.get(code, fallback or code)


def flag_emoji(code: str) -> str:
    """کد دو حرفی کشور را به پرچم تبدیل می‌کند."""
    code = (code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)
