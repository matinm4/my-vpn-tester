"""تولید خروجی‌ها: JSON، لیست کانفیگ‌های سالم، سابسکریپشن base64 و گزارش HTML."""

from __future__ import annotations

import base64
import json
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .geo import country_label, flag_emoji
from .models import TestResult
from .sanitize import clean_name, sanitize_result_link

_TEMPLATE_PATH = Path(__file__).parent / "templates" / "report.html"

_SORT_KEYS = {
    "latency": lambda r: (not r.ok, r.latency_ms if r.latency_ms is not None else float("inf")),
    "name": lambda r: (not r.ok, str(r.config.get("name", "")).lower()),
    "protocol": lambda r: (str(r.config.get("protocol", "")), not r.ok,
                           r.latency_ms if r.latency_ms is not None else float("inf")),
    "country": lambda r: (r.country_code or "ZZ", not r.ok,
                          r.latency_ms if r.latency_ms is not None else float("inf")),
}


def sort_results(results: Sequence[TestResult], sort_by: str = "latency") -> List[TestResult]:
    key = _SORT_KEYS.get(sort_by, _SORT_KEYS["latency"])
    return sorted(results, key=key)


# ---------------------------------------------------------------------------
# ساخت داده‌ی گزارش
# ---------------------------------------------------------------------------

def _result_row(result: TestResult, index: int, clean: bool = False,
                tag: str = "") -> Dict[str, Any]:
    cfg = result.config or {}
    code = result.country_code or ""
    name = cfg.get("name") or cfg.get("remark") or "بدون نام"
    if clean:
        name = clean_name(code, result.latency_ms, index, tag)
    return {
        "i": index,
        "fingerprint": result.fingerprint,
        "name": name,
        "protocol": cfg.get("protocol", ""),
        "address": cfg.get("address", ""),
        "port": cfg.get("port", 0),
        "endpoint": f"{cfg.get('address','')}:{cfg.get('port','')}",
        "network": cfg.get("network", ""),
        "security": cfg.get("security", ""),
        "transport": cfg.get("transport", ""),
        "sni": cfg.get("sni", ""),
        "host": cfg.get("host", ""),
        "path": cfg.get("path", ""),
        "ok": result.ok,
        "quality": result.quality,
        "latency_ms": result.latency_ms,
        "handshake_ms": result.handshake_ms,
        "avg_ms": result.avg_ms,
        "max_ms": result.max_ms,
        "jitter_ms": result.jitter_ms,
        "samples": result.samples,
        "attempts_ok": result.attempts_ok,
        "attempts_total": result.attempts_total,
        "rounds": result.rounds,
        "exit_ip": result.exit_ip,
        "country_code": code,
        "country": country_label(code, result.country) if (code or result.country) else "",
        "flag": flag_emoji(code),
        "city": result.city,
        "isp": result.isp,
        "asn": result.asn,
        "error": result.error,
        "stage": result.stage,
        "from_cache": result.from_cache,
        "duration_s": round(result.duration_s, 2),
        "tested_at": result.tested_at,
        "source": "" if clean else cfg.get("source", ""),
        "link": (sanitize_result_link(result, rank=index, tag=tag)
                 if clean else cfg.get("raw", "")),
    }


def build_payload(
    results: Sequence[TestResult],
    *,
    settings,
    stats: Dict[str, Any],
    sources: List[Dict[str, Any]],
    parse_errors: List[Dict[str, Any]],
    xray_version: str = "",
    duration_s: float = 0.0,
) -> Dict[str, Any]:
    sort_by = settings.get("output.sort_by", "latency")
    ordered = sort_results(results, sort_by)

    working = [r for r in ordered if r.ok]
    latencies = [r.latency_ms for r in working if r.latency_ms is not None]

    protocol_counts: Dict[str, Dict[str, int]] = {}
    for r in ordered:
        proto = (r.config or {}).get("protocol", "?")
        bucket = protocol_counts.setdefault(proto, {"total": 0, "working": 0})
        bucket["total"] += 1
        if r.ok:
            bucket["working"] += 1

    country_counts: Dict[str, Dict[str, Any]] = {}
    for r in working:
        code = r.country_code or "??"
        bucket = country_counts.setdefault(code, {
            "code": code,
            "label": country_label(code, r.country),
            "flag": flag_emoji(code),
            "count": 0,
            "latencies": [],
        })
        bucket["count"] += 1
        if r.latency_ms is not None:
            bucket["latencies"].append(r.latency_ms)

    countries = []
    for bucket in country_counts.values():
        lat = bucket.pop("latencies")
        bucket["best_ms"] = round(min(lat), 1) if lat else None
        bucket["median_ms"] = round(statistics.median(lat), 1) if lat else None
        countries.append(bucket)
    countries.sort(key=lambda c: (-c["count"], c["label"]))

    total = len(ordered)
    summary = {
        **stats,
        "tested_total": total,
        "working": len(working),
        "failed": total - len(working),
        "success_rate": round(100.0 * len(working) / total, 1) if total else 0.0,
        "best_ms": round(min(latencies), 1) if latencies else None,
        "median_ms": round(statistics.median(latencies), 1) if latencies else None,
        "avg_ms": round(statistics.fmean(latencies), 1) if latencies else None,
        "worst_ms": round(max(latencies), 1) if latencies else None,
        "countries_count": len(countries),
        "protocols": protocol_counts,
        "countries": countries,
    }

    now = datetime.now(timezone.utc).astimezone()
    clean = bool(settings.get("output.clean_names", False))
    tag = str(settings.get("output.name_tag", "") or "")
    return {
        "generated_at": now.isoformat(timespec="seconds"),
        "generated_at_human": now.strftime("%Y-%m-%d %H:%M:%S"),
        "xray_version": xray_version,
        "duration_s": round(duration_s, 1),
        "title": settings.get("output.title", "گزارش تست کانفیگ‌های Xray"),
        "summary": summary,
        "sources": sources,
        "parse_errors": parse_errors[:500],
        "parse_errors_total": len(parse_errors),
        "settings": _effective_settings(settings),
        "results": [_result_row(r, i + 1, clean, tag) for i, r in enumerate(ordered)],
    }


def _effective_settings(settings) -> Dict[str, Any]:
    """تنظیمات مؤثر روی این اجرا — برای بازتولید نتیجه."""
    keys = [
        "test.concurrency", "test.attempts", "test.attempt_timeout",
        "test.latency_url", "test.retries", "test.ip_check", "test.ip_check_url",
        "test.max_latency_ms", "test.limit", "test.only_protocols",
        "xray.log_level", "xray.start_timeout", "xray.allow_insecure",
        "xray.domain_strategy", "xray.mux_enabled", "xray.sniffing",
        "dedup.enabled", "dedup.keep",
        "cache.enabled", "cache.ttl_hours", "cache.retest_failed",
    ]
    return {key: settings.get(key) for key in keys}


# ---------------------------------------------------------------------------
# نوشتن فایل‌ها
# ---------------------------------------------------------------------------

def write_outputs(payload: Dict[str, Any], results: Sequence[TestResult],
                  settings, logger) -> Dict[str, Path]:
    out_dir = settings.path_of("output.dir")
    out_dir.mkdir(parents=True, exist_ok=True)
    written: Dict[str, Path] = {}

    include_failed = bool(settings.get("output.include_failed", True))
    export_payload = payload
    if not include_failed:
        export_payload = dict(payload)
        export_payload["results"] = [r for r in payload["results"] if r["ok"]]

    # ---- JSON ----
    json_name = settings.get("output.json_file")
    if json_name:
        path = out_dir / json_name
        path.write_text(
            json.dumps(export_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        written["json"] = path

    # ---- لیست کانفیگ‌های سالم ----
    ordered_working = [r for r in sort_results(results, "latency") if r.ok]
    clean = bool(settings.get("output.clean_names", False))
    tag = str(settings.get("output.name_tag", "") or "")

    links = []
    for rank, r in enumerate(ordered_working, start=1):
        raw = str((r.config or {}).get("raw", ""))
        if not raw:
            continue
        links.append(sanitize_result_link(r, rank=rank, tag=tag) if clean else raw)

    working_name = settings.get("output.working_file")
    if working_name:
        path = out_dir / working_name
        path.write_text("\n".join(links) + ("\n" if links else ""), encoding="utf-8")
        written["working"] = path

    sub_name = settings.get("output.subscription_file")
    if sub_name:
        path = out_dir / sub_name
        blob = base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")
        path.write_text(blob, encoding="utf-8")
        written["subscription"] = path

    # ---- HTML ----
    html_name = settings.get("output.html_file")
    if html_name:
        path = out_dir / html_name
        path.write_text(render_html(export_payload), encoding="utf-8")
        written["html"] = path

    return written


def render_html(payload: Dict[str, Any]) -> str:
    template = _TEMPLATE_PATH.read_text(encoding="utf-8")
    # `<` را اسکیپ می‌کنیم تا رشته‌ی </script> داخل داده، تگ اسکریپت را نبندد
    blob = json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c")
    title = str(payload.get("title", "گزارش تست کانفیگ‌های Xray"))
    return template.replace("__TITLE__", title).replace('"__PAYLOAD__"', blob)
