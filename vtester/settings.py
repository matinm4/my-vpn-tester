"""بارگذاری و ادغام تنظیمات: config.yaml + آرگومان‌های خط فرمان."""

from __future__ import annotations

import copy
import os
import shutil
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

DEFAULTS: Dict[str, Any] = {
    "input": {
        "subs_file": "subs.txt",
        "config_files": [],
        "user_agent": "v2rayN/6.45",
        "fetch_timeout": 30,
        "fetch_retries": 2,
        "fetch_proxy": "",
    },
    "xray": {
        "binary": "xray.exe",
        "assets_dir": ".",
        "log_level": "none",
        "start_timeout": 8.0,
        "port_start": 21000,
        "port_end": 22000,
        "listen": "127.0.0.1",
        "allow_insecure": False,
        "domain_strategy": "AsIs",
        "sniffing": False,
        "mux_enabled": False,
        "mux_concurrency": 8,
        "extra_outbound": {},
    },
    "test": {
        "concurrency": 16,
        "attempts": 3,
        "attempt_timeout": 8.0,
        "latency_url": "http://cp.cloudflare.com/generate_204",
        "accept_status": [200, 204],
        "retries": 1,
        "retry_delay": 1.0,
        "ip_check": True,
        "ip_check_url": "http://cp.cloudflare.com/cdn-cgi/trace",
        "ip_check_timeout": 10.0,
        "geo_enrich": True,
        "geo_batch_url": "http://ip-api.com/batch",
        "max_latency_ms": 0,
        "limit": 0,
        "shuffle": False,
        "only_protocols": [],
    },
    "dedup": {"enabled": True, "keep": "first"},
    "cache": {
        "enabled": True,
        "path": ".cache/results.jsonl",
        "ttl_hours": 24,
        "retest_failed": False,
    },
    "store": {
        "path": ".cache/configs.db",
        "keep_results_per_config": 5,
        "prune_after_days": 30,
    },
    "health": {
        "blacklist_after_failures": 3,
        "blacklist_hours": 24,
    },
    "telegram": {
        "enabled": False,
        "api_id": 0,
        "api_hash": "",
        "session_string": "",
        "channels": [],
        "days_back": 30,
        "per_channel_timeout": 180,
        "total_timeout": 900,
        "max_messages_per_channel": 0,
        "state_file": ".cache/telegram_state.json",
        "legacy_output": "recive_config_from_telegram/configs_output.json",
    },
    "vpn_gate": {
        "enabled": True,
        "wait_minutes": 15,
        "probe_url": "http://cp.cloudflare.com/cdn-cgi/trace",
        "require_ip_change": True,
        "reminder_seconds": 60,
        "probe_every_seconds": 10,
    },
    "pool": {
        "size": 20,
        "batch_size": 20,
        "max_batches": 0,
        "max_age_hours": 24,
        "history_limit": 2000,
        "history_file": "pool_history.json",
        "top_file": "top20.txt",
        "top_sub_file": "top20_sub.txt",
        "batch_dir": "batches",
    },
    "live": {
        "discovery_interval_minutes": 60,
        "pool_interval_minutes": 30,
        "batch_test_size": 0,
        "max_untested_per_cycle": 5000,
        "retest_after_hours": 12,
        "log_failures": False,
        "telegram_in_service": False,
    },
    "output": {
        "dir": "output",
        "json_file": "results.json",
        "html_file": "report.html",
        "working_file": "working.txt",
        "subscription_file": "working_sub.txt",
        "sort_by": "latency",
        "include_failed": True,
        "title": "گزارش تست کانفیگ‌های Xray",
        # پیش‌فرض False تا نسخه‌ی محلی نام اصلی منبع را نگه دارد؛ خروجی
        # عمومی (config.ci.yaml) صریحاً روشنش می‌کند.
        "clean_names": False,
        "name_tag": "",
    },
}


def _deep_merge(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in (patch or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Settings:
    """دسترسی نقطه‌ای به تنظیمات: settings.get('test.concurrency')."""

    def __init__(self, data: Dict[str, Any], root: Path, config_path: Optional[Path] = None):
        self._data = data
        self.root = root
        self.config_path = config_path

    # ------------------------------------------------------------------

    @classmethod
    def load(cls, config_path: Optional[str] = None, root: Optional[str] = None) -> "Settings":
        base_root = Path(root).resolve() if root else Path.cwd().resolve()

        path: Optional[Path] = None
        if config_path:
            path = Path(config_path)
            if not path.is_absolute():
                path = base_root / path
            if not path.exists():
                raise FileNotFoundError(f"فایل تنظیمات پیدا نشد: {path}")
        else:
            candidate = base_root / "config.yaml"
            if candidate.exists():
                path = candidate

        loaded: Dict[str, Any] = {}
        if path is not None:
            with open(path, "r", encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
            if not isinstance(loaded, dict):
                raise ValueError(f"ساختار {path} باید یک نگاشت (mapping) باشد")

        return cls(_deep_merge(DEFAULTS, loaded), base_root, path)

    # ------------------------------------------------------------------

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, dotted: str, value: Any) -> None:
        parts = dotted.split(".")
        node = self._data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value

    def apply_overrides(self, overrides: Dict[str, Any]) -> None:
        """اعمال override های خط فرمان؛ مقادیر None نادیده گرفته می‌شوند."""
        for dotted, value in overrides.items():
            if value is not None:
                self.set(dotted, value)

    def path_of(self, dotted: str, default: Any = None) -> Path:
        """یک مقدار مسیر را نسبت به ریشه‌ی پروژه resolve می‌کند."""
        raw = self.get(dotted, default)
        p = Path(os.path.expandvars(os.path.expanduser(str(raw))))
        return p if p.is_absolute() else (self.root / p)

    def binary_of(self, dotted: str, default: Any = None) -> Path:
        """مثل path_of، ولی برای فایل اجرایی.

        اگر مقدار فقط یک نام باشد (مثل «xray» بدون هیچ جداکننده‌ی مسیر) و
        کنار پروژه پیدا نشود، در PATH دنبالش می‌گردیم. روی گیت‌هاب اکشن
        هسته در ~/.local/bin نصب می‌شود و در ریشه‌ی مخزن نیست.
        نامی که جداکننده دارد (مثل «./xray» یا «bin/xray») همیشه نسبت به
        ریشه‌ی پروژه معنا می‌شود — دقیقاً مثل قبل.
        """
        raw = str(self.get(dotted, default))
        expanded = os.path.expandvars(os.path.expanduser(raw))
        p = Path(expanded)

        if p.is_absolute():
            return p

        candidate = self.root / p
        if candidate.exists():
            return candidate

        # فقط نام خالی — نه «./xray» و نه «bin/xray»
        if Path(expanded).name == expanded:
            found = shutil.which(expanded)
            if found:
                return Path(found)

        return candidate

    def as_dict(self) -> Dict[str, Any]:
        return copy.deepcopy(self._data)

    # ------------------------------------------------------------------

    def validate(self) -> None:
        """بررسی‌های زودهنگام تا خطاها قبل از شروع تست معلوم شوند."""
        errors = []

        binary = self.binary_of("xray.binary")
        if not binary.exists():
            errors.append(f"هسته‌ی Xray پیدا نشد: {binary}")

        start = int(self.get("xray.port_start"))
        end = int(self.get("xray.port_end"))
        if not (1024 <= start < end <= 65535):
            errors.append(f"محدوده‌ی پورت نامعتبر است: {start}..{end}")

        concurrency = int(self.get("test.concurrency"))
        if concurrency < 1:
            errors.append("test.concurrency باید حداقل ۱ باشد")
        elif end - start + 1 < concurrency:
            errors.append(
                f"محدوده‌ی پورت ({end - start + 1} پورت) کمتر از concurrency ({concurrency}) است"
            )

        if int(self.get("test.attempts")) < 1:
            errors.append("test.attempts باید حداقل ۱ باشد")

        keep = self.get("dedup.keep")
        if keep not in ("first", "shortest_name"):
            errors.append("dedup.keep باید first یا shortest_name باشد")

        sort_by = self.get("output.sort_by")
        if sort_by not in ("latency", "name", "protocol", "country"):
            errors.append("output.sort_by باید یکی از latency/name/protocol/country باشد")

        if int(self.get("pool.size", 20)) < 1:
            errors.append("pool.size باید حداقل ۱ باشد")

        if int(self.get("pool.batch_size", 20)) < 1:
            errors.append("pool.batch_size باید حداقل ۱ باشد")

        if float(self.get("live.pool_interval_minutes", 30)) <= 0:
            errors.append("live.pool_interval_minutes باید بزرگ‌تر از صفر باشد")

        if float(self.get("live.discovery_interval_minutes", 60)) <= 0:
            errors.append("live.discovery_interval_minutes باید بزرگ‌تر از صفر باشد")

        # تلگرام فقط وقتی روشن است باید کامل باشد
        if self.get("telegram.enabled", False):
            missing = [
                key for key in ("api_id", "api_hash", "session_string")
                if not self.get(f"telegram.{key}")
            ]
            if missing:
                errors.append(
                    "تلگرام روشن است ولی این مقادیر خالی‌اند: " + "، ".join(missing)
                )
            if not self.get("telegram.channels"):
                errors.append("تلگرام روشن است ولی هیچ کانالی در telegram.channels نیست")

        if errors:
            raise ValueError("\n".join("  - " + e for e in errors))
