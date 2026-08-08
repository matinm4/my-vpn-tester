"""گرفتن کانفیگ‌ها از لینک سابسکریپشن، فایل محلی یا لینک خام."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
import yaml

from .links import b64decode_loose, is_proxy_link, parse_link
from .models import ParseError, ProxyConfig


class SourceStats:
    """آمار مربوط به هر منبع، برای نمایش در گزارش."""

    def __init__(self) -> None:
        self.items: List[Dict[str, Any]] = []

    def add(self, name: str, kind: str, ok: bool, found: int = 0,
            failed: int = 0, error: str = "") -> None:
        self.items.append({
            "source": name,
            "kind": kind,
            "ok": ok,
            "configs_found": found,
            "parse_failed": failed,
            "error": error,
        })

    def as_list(self) -> List[Dict[str, Any]]:
        return list(self.items)


# ---------------------------------------------------------------------------
# استخراج لینک‌ها از محتوای یک سابسکریپشن
# ---------------------------------------------------------------------------

# عمداً http/https اینجا نیست: بدنه‌ی یک سابسکریپشن خراب (مثلاً صفحه‌ی خطای
# HTML) پر از URL معمولی است و کشیدن آن‌ها به عنوان کانفیگ فقط نویز می‌سازد.
_LINK_RE = re.compile(
    r"(?:vmess|vless|trojan|ss|ssr|socks5?|hysteria2?|hy2|tuic|snell|juicity)://[^\s\"'<>\\]+",
    re.IGNORECASE,
)


def _extract_from_clash(doc: Dict[str, Any]) -> List[str]:
    """تبدیل proxies یک فایل کلش به لینک‌های استاندارد."""
    links: List[str] = []
    for p in doc.get("proxies") or []:
        if not isinstance(p, dict):
            continue
        try:
            links.append(_clash_proxy_to_link(p))
        except Exception:
            continue
    return [l for l in links if l]


def _clash_proxy_to_link(p: Dict[str, Any]) -> str:
    """یک ورودی proxies کلش را به لینک تبدیل می‌کند (فقط انواع مورد پشتیبانی Xray)."""
    from urllib.parse import quote, urlencode

    ptype = str(p.get("type", "")).lower()
    server, port = p.get("server"), p.get("port")
    name = quote(str(p.get("name", "")), safe="")
    if not server or not port:
        return ""

    net = str(p.get("network", "tcp")).lower()
    tls = bool(p.get("tls"))
    q: Dict[str, str] = {"type": net}
    if tls:
        q["security"] = "tls"
    sni = p.get("servername") or p.get("sni")
    if sni:
        q["sni"] = str(sni)
    if p.get("skip-cert-verify"):
        q["allowInsecure"] = "1"
    if p.get("client-fingerprint"):
        q["fp"] = str(p["client-fingerprint"])

    if net == "ws":
        ws = p.get("ws-opts") or {}
        q["path"] = str(ws.get("path", p.get("ws-path", "/")))
        headers = ws.get("headers") or {}
        host = headers.get("Host") or headers.get("host")
        if host:
            q["host"] = str(host)
    elif net == "grpc":
        grpc = p.get("grpc-opts") or {}
        q["serviceName"] = str(grpc.get("grpc-service-name", ""))
    elif net in ("h2", "http"):
        h2 = p.get("h2-opts") or p.get("http-opts") or {}
        paths = h2.get("path")
        if isinstance(paths, list) and paths:
            q["path"] = str(paths[0])
        elif paths:
            q["path"] = str(paths)

    reality = p.get("reality-opts") or {}
    if reality:
        q["security"] = "reality"
        if reality.get("public-key"):
            q["pbk"] = str(reality["public-key"])
        if reality.get("short-id"):
            q["sid"] = str(reality["short-id"])

    if ptype == "vmess":
        q["encryption"] = str(p.get("cipher", "auto"))
        if p.get("alterId") is not None:
            q["alterId"] = str(p.get("alterId"))
        return f"vmess://{p.get('uuid','')}@{server}:{port}?{urlencode(q)}#{name}"
    if ptype == "vless":
        q["encryption"] = "none"
        if p.get("flow"):
            q["flow"] = str(p["flow"])
        return f"vless://{p.get('uuid','')}@{server}:{port}?{urlencode(q)}#{name}"
    if ptype == "trojan":
        q.setdefault("security", "tls")
        return f"trojan://{quote(str(p.get('password','')), safe='')}@{server}:{port}?{urlencode(q)}#{name}"
    if ptype == "ss":
        import base64 as _b64
        creds = f"{p.get('cipher','')}:{p.get('password','')}"
        enc = _b64.b64encode(creds.encode()).decode().rstrip("=")
        return f"ss://{enc}@{server}:{port}#{name}"
    if ptype in ("socks5", "socks"):
        auth = ""
        if p.get("username"):
            import base64 as _b64
            auth = _b64.b64encode(
                f"{p.get('username','')}:{p.get('password','')}".encode()
            ).decode().rstrip("=") + "@"
        return f"socks://{auth}{server}:{port}#{name}"
    return ""


def extract_links(content: str) -> List[str]:
    """همه‌ی لینک‌های پراکسی را از محتوای یک سابسکریپشن بیرون می‌کشد.

    ترتیب تلاش: لینک خام → base64 → JSON (کانفیگ کامل Xray یا لیست) → YAML کلش.
    """
    content = (content or "").strip()
    if not content:
        return []

    # ۱) محتوا خودش لینک دارد
    found = _LINK_RE.findall(content)
    if found:
        return [f.rstrip(",;") for f in found]

    # ۲) کل بدنه base64 است (رایج‌ترین حالت سابسکریپشن)
    decoded = b64decode_loose(content)
    if decoded:
        found = _LINK_RE.findall(decoded)
        if found:
            return [f.rstrip(",;") for f in found]

    # ۳) JSON
    for candidate in (content, decoded or ""):
        stripped = candidate.lstrip()
        if stripped.startswith(("{", "[")):
            try:
                doc = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            links = _links_from_json(doc)
            if links:
                return links

    # ۴) YAML کلش
    if "proxies:" in content:
        try:
            doc = yaml.safe_load(content)
        except yaml.YAMLError:
            doc = None
        if isinstance(doc, dict):
            links = _extract_from_clash(doc)
            if links:
                return links

    return []


def _links_from_json(doc: Any) -> List[str]:
    """لینک‌ها را از ساختارهای JSON مختلف پیدا می‌کند."""
    links: List[str] = []

    if isinstance(doc, list):
        for item in doc:
            if isinstance(item, str) and is_proxy_link(item):
                links.append(item)
            elif isinstance(item, dict):
                links.extend(_links_from_json(item))
        return links

    if isinstance(doc, dict):
        if isinstance(doc.get("proxies"), list):
            links.extend(_extract_from_clash(doc))
        # فایل کانفیگ کامل Xray: هر outbound را به لینک برنمی‌گردانیم،
        # فقط رشته‌های لینک‌مانند داخل آن را جمع می‌کنیم.
        for value in doc.values():
            if isinstance(value, str) and is_proxy_link(value):
                links.append(value)
            elif isinstance(value, (list, dict)):
                links.extend(_links_from_json(value))
    return links


# ---------------------------------------------------------------------------
# لودر
# ---------------------------------------------------------------------------

class ConfigLoader:
    def __init__(self, settings, logger) -> None:
        self.settings = settings
        self.log = logger
        self.stats = SourceStats()

    # ------------------------------------------------------------------

    def _session(self) -> requests.Session:
        sess = requests.Session()
        sess.headers.update({
            "User-Agent": self.settings.get("input.user_agent", "v2rayN/6.45"),
            "Accept": "*/*",
        })
        proxy = (self.settings.get("input.fetch_proxy") or "").strip()
        if proxy:
            sess.proxies.update({"http": proxy, "https": proxy})
        return sess

    def _read_sub_entries(self) -> List[str]:
        """خطوط فایل subs.txt را می‌خواند (کامنت‌ها و خطوط خالی حذف می‌شوند)."""
        path = self.settings.path_of("input.subs_file")
        if not path.exists():
            return []
        entries: List[str] = []
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.append(line)
        return entries

    # ------------------------------------------------------------------

    def load(self, extra_entries: Optional[Iterable[str]] = None) -> Tuple[List[ProxyConfig], List[Dict[str, Any]]]:
        """همه‌ی منابع را می‌خواند و لیست ProxyConfig برمی‌گرداند.

        خروجی دوم: لیست خطاهای پارس، برای گزارش.
        """
        entries: List[str] = list(extra_entries or [])
        entries.extend(self._read_sub_entries())
        for cf in self.settings.get("input.config_files") or []:
            entries.append(str(cf))

        # حذف تکراری‌های سطح منبع، با حفظ ترتیب
        seen_entries, ordered = set(), []
        for e in entries:
            if e not in seen_entries:
                seen_entries.add(e)
                ordered.append(e)

        if not ordered:
            return [], []

        session = self._session()
        configs: List[ProxyConfig] = []
        parse_errors: List[Dict[str, Any]] = []

        for entry in ordered:
            links, kind, error = self._resolve_entry(entry, session)
            if error:
                self.log.warn(f"منبع ناموفق [{entry[:60]}]: {error}")
                self.stats.add(entry, kind, ok=False, error=error)
                continue

            ok_count = 0
            fail_count = 0
            for idx, link in enumerate(links):
                try:
                    configs.append(parse_link(link, source=entry, index=idx))
                    ok_count += 1
                except ParseError as exc:
                    fail_count += 1
                    parse_errors.append({
                        "source": entry,
                        "link": link[:120],
                        "error": str(exc),
                    })

            self.log.info(f"منبع «{self._short(entry)}»: {ok_count} کانفیگ"
                          + (f" ({fail_count} ناسازگار)" if fail_count else ""))
            self.stats.add(entry, kind, ok=True, found=ok_count, failed=fail_count)

        return configs, parse_errors

    # ------------------------------------------------------------------

    def _resolve_entry(self, entry: str, session: requests.Session) -> Tuple[List[str], str, str]:
        """یک ورودی را به لیست لینک تبدیل می‌کند. خروجی: (links, kind, error)"""
        # الف) خود ورودی یک لینک پراکسی است
        if is_proxy_link(entry):
            return [entry], "inline", ""

        # ب) ورودی یک URL است
        if re.match(r"^https?://", entry, re.IGNORECASE):
            content, error = self._fetch(entry, session)
            if error:
                return [], "url", error
            links = extract_links(content)
            if not links:
                return [], "url", "هیچ کانفیگی در پاسخ سابسکریپشن پیدا نشد"
            return links, "url", ""

        # ج) ورودی یک مسیر فایل است
        path = Path(entry)
        if not path.is_absolute():
            path = self.settings.root / path
        if not path.exists():
            return [], "file", "فایل پیدا نشد"
        try:
            content = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            return [], "file", f"خطای خواندن فایل: {exc}"
        links = extract_links(content)
        if not links:
            return [], "file", "هیچ کانفیگی در فایل پیدا نشد"
        return links, "file", ""

    def _fetch(self, url: str, session: requests.Session) -> Tuple[str, str]:
        timeout = float(self.settings.get("input.fetch_timeout", 30))
        retries = int(self.settings.get("input.fetch_retries", 2))
        last_error = ""
        for attempt in range(retries + 1):
            try:
                resp = session.get(url, timeout=timeout)
                if resp.status_code != 200:
                    last_error = f"کد وضعیت HTTP {resp.status_code}"
                else:
                    return resp.text, ""
            except requests.RequestException as exc:
                last_error = f"{type(exc).__name__}: {exc}"[:160]
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
        return "", last_error

    @staticmethod
    def _short(text: str, width: int = 52) -> str:
        text = text.strip()
        return text if len(text) <= width else text[: width - 3] + "..."
