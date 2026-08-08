#!/usr/bin/env bash
# خلاصه‌ی اجرا را در صفحه‌ی گیت‌هاب اکشن نشان می‌دهد.
# هرگز شکست نمی‌خورد — خلاصه‌ی ناقص نباید اجرای موفق را قرمز کند.
set -uo pipefail

OUT="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

if [ ! -f "output/results.json" ]; then
  {
    echo "### نتیجه‌ای تولید نشد"
    echo ""
    echo "لاگ مرحله‌ی قبل را بررسی کنید."
  } >> "$OUT"
  exit 0
fi

python - <<'PY' >> "$OUT" 2>/dev/null || echo "خلاصه ساخته نشد" >> "$OUT"
import json, os
from pathlib import Path

d = json.load(open("output/results.json", encoding="utf-8"))
s = d.get("summary", {})

def num(v):
    return "—" if v is None else f"{v:,.0f}" if isinstance(v, (int, float)) else str(v)

print("### نتیجه‌ی اجرا\n")
print("| | |")
print("|---|---|")
print(f"| کانفیگ در گزارش | {num(len(d.get('results', [])))} |")
print(f"| سالم | **{num(s.get('working'))}** ({s.get('success_rate', 0)}٪) |")
print(f"| ناموفق | {num(s.get('failed'))} |")
print(f"| بهترین پینگ | **{num(s.get('best_ms'))} ms** |")
print(f"| میانه‌ی پینگ | {num(s.get('median_ms'))} ms |")
print(f"| کشور یکتا | {num(s.get('countries_count'))} |")
if s.get("blacklisted"):
    print(f"| در لیست سیاه | {num(s.get('blacklisted'))} |")

# استخر فعلی
hist = Path("output/pool_history.json")
if hist.exists():
    try:
        h = json.load(open(hist, encoding="utf-8"))
        current = h.get("current", [])
        changes = [c for c in h.get("changes", []) if c.get("at_human")]
        if current:
            print(f"\n### استخر ({len(current)} کانفیگ)\n")
            print("| رتبه | پینگ | کشور | نام |")
            print("|---:|---:|:--:|---|")
            for c in current[:10]:
                name = str(c.get("name", ""))[:44].replace("|", "\\|")
                flag = c.get("country_code") or "—"
                print(f"| {c.get('rank')} | {num(c.get('latency_ms'))} ms | {flag} | {name} |")
            if len(current) > 10:
                print(f"\n_{len(current) - 10} کانفیگ دیگر در فایل خروجی_")

        # تغییرات همین اجرا
        if changes:
            last_at = changes[-1].get("at_human", "")
            recent = [c for c in changes if c.get("at_human") == last_at]
            added = [c for c in recent if c.get("action") == "added"]
            removed = [c for c in recent if c.get("action") == "removed"]
            if added or removed:
                print(f"\n**تغییرات این اجرا:** {len(added)} ورود · {len(removed)} خروج")
    except Exception:
        pass

# دسته‌های نوشته‌شده
idx = Path("output/batches/index.json")
if idx.exists():
    try:
        i = json.load(open(idx, encoding="utf-8"))
        print(f"\n**فایل‌های دسته‌ای:** {i.get('batches_written')} دسته · "
              f"{i.get('configs_in_batches')} کانفیگ")
        if i.get("omitted"):
            print(f" ({i['omitted']} کانفیگ در دسته‌ها نیامد)")
    except Exception:
        pass

print("\n> خروجی‌های کامل در بخش **Artifacts** همین صفحه قابل دانلود است.")
PY
