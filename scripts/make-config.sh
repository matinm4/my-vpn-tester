#!/usr/bin/env bash
# ============================================================================
#  ساخت config.yaml از روی config.ci.yaml + سکرت‌های گیت‌هاب
#
#  کد پایتون هیچ تغییری برای CI نمی‌خواهد: این اسکریپت قبل از اجرا یک
#  config.yaml معمولی می‌سازد که رمزها داخلش نشسته‌اند. فایل ساخته‌شده
#  در .gitignore است و با پایان job از بین می‌رود.
#
#  اگر سکرت‌های تلگرام تنظیم نشده باشند، بخش telegram خاموش می‌ماند و
#  سرویس فقط از subs.txt کار می‌کند — بدون خطا.
# ============================================================================
set -euo pipefail

[ -f "config.ci.yaml" ] || { echo "خطا: config.ci.yaml پیدا نشد" >&2; exit 1; }

python - <<'PY'
import os
import sys

import yaml

with open("config.ci.yaml", encoding="utf-8") as fh:
    cfg = yaml.safe_load(fh) or {}

tg = cfg.setdefault("telegram", {})

session = os.environ.get("VT_TELEGRAM_SESSION", "").strip()
api_id = os.environ.get("VT_TELEGRAM_API_ID", "").strip()
api_hash = os.environ.get("VT_TELEGRAM_API_HASH", "").strip()
channels = [c.strip() for c in os.environ.get("VT_TELEGRAM_CHANNELS", "").split(",") if c.strip()]

if session and api_id:
    if not api_id.isdigit():
        raise SystemExit(f"خطا: VT_TELEGRAM_API_ID باید عدد باشد، نه {api_id!r}")
    if not channels:
        print("::warning::VT_TELEGRAM_CHANNELS خالی است — تلگرام خاموش می‌ماند")
        tg["enabled"] = False
    else:
        tg.update({
            "enabled": True,
            "api_id": int(api_id),
            "api_hash": api_hash,
            "session_string": session,
            "channels": channels,
        })
else:
    tg["enabled"] = False
    if session or api_id:
        # نیمی از سکرت‌ها هست و نیمی نیست — احتمالاً اشتباه تنظیم شده
        print("::warning::سکرت‌های تلگرام ناقص‌اند — تلگرام خاموش می‌ماند")

with open("config.yaml", "w", encoding="utf-8") as fh:
    yaml.safe_dump(cfg, fh, allow_unicode=True, sort_keys=False, default_flow_style=False)

# ---- گزارش (بدون افشای رمز) ----
enabled = bool(tg.get("enabled"))
print("  config.yaml ساخته شد")
print(f"    تلگرام   : {'روشن' if enabled else 'خاموش'}"
      + (f" ({len(tg.get('channels') or [])} کانال)" if enabled else ""))
print(f"    دروازه   : {'روشن' if cfg.get('vpn_gate', {}).get('enabled') else 'خاموش'}")
print(f"    هسته     : {cfg.get('xray', {}).get('binary')}")
print(f"    همزمانی  : {cfg.get('test', {}).get('concurrency')}")
print(f"    استخر    : {cfg.get('pool', {}).get('size')} کانفیگ")
PY

# ---- بررسی نهایی: تنظیمات باید از دید خود برنامه معتبر باشد ----
python -c "
from pathlib import Path
from vtester.settings import Settings
s = Settings.load('config.yaml', root=str(Path.cwd()))
s.validate()
print('    اعتبارسنجی: پاس')
"
