#!/usr/bin/env bash
# ============================================================================
#  انتشار خروجی‌ها در شاخه‌ی عمومی
#
#  فایل‌های کانفیگ (۲۰ برتر + دسته‌های کامل) را در شاخه‌ی جدا `public`
#  می‌گذارد تا با لینک ثابت raw.githubusercontent در هر کلاینتی import شوند
#  و خودکار به‌روز بمانند.
#
#  چرا شاخه‌ی جدا: شاخه همیشه تک‌کامیت است و هر بار جایگزین می‌شود. با اجرای
#  هر ۳۰ دقیقه، کامیت کردن روی main تاریخچه‌ی مخزن را در چند هفته غرق می‌کند.
#
#  چرا با دستورهای سطح‌پایین git: این اسکریپت هیچ‌وقت شاخه‌ی جاری یا فایل‌های
#  working tree را عوض نمی‌کند. state.sh هم روی همان مخزن کار می‌کند و
#  checkout کردن اینجا، آن یکی را خراب می‌کرد.
#
#  نام کانفیگ‌ها قبلاً در پایتون بازنویسی شده (output.clean_names)، پس هیچ
#  آی‌دی تلگرام و متن تبلیغاتی در فایل‌های اینجا نیست.
#
#  استفاده:  scripts/publish.sh
# ============================================================================
set -euo pipefail

BRANCH="${VT_PUBLIC_BRANCH:-public}"
OUT="output"
TOP="$OUT/top20.txt"

log() { echo "  $*"; }

[ -d "$OUT" ] || { log "پوشه‌ی خروجی نیست — چیزی برای انتشار نداریم"; exit 0; }

if [ ! -s "$TOP" ]; then
  # فایل خالی یعنی این دور هیچ کانفیگ سالمی نداشت. انتشارش لینک سالم قبلی
  # کاربر را با فایل خالی جایگزین می‌کند — بدتر از انتشار نکردن.
  log "کانفیگ سالمی در این اجرا نبود — انتشار رد شد تا نسخه‌ی قبلی بماند"
  exit 0
fi

STAGE="$(mktemp -d)"
INDEX="$(mktemp -u)"
trap 'rm -rf "$STAGE" "$INDEX"' EXIT

cp "$TOP" "$STAGE/"
[ -f "$OUT/top20_sub.txt" ] && cp "$OUT/top20_sub.txt" "$STAGE/"
if [ -d "$OUT/batches" ]; then
  mkdir -p "$STAGE/batches"
  cp "$OUT/batches"/batch_*.txt "$STAGE/batches/" 2>/dev/null || true
  [ -f "$OUT/batches/index.json" ] && cp "$OUT/batches/index.json" "$STAGE/batches/"
fi

# ---- صفحه‌ی راهنما ----
REPO="${GITHUB_REPOSITORY:-USER/REPO}"
RAW="https://raw.githubusercontent.com/$REPO/$BRANCH"
NOW="$(date -u '+%Y-%m-%d %H:%M UTC')"
COUNT="$(grep -c . "$TOP" 2>/dev/null || true)"
COUNT="${COUNT:-0}"

BATCHES=0
TOTAL=0
if [ -f "$OUT/batches/index.json" ]; then
  read -r BATCHES TOTAL <<EOF2
$(python -c "
import json
d = json.load(open('$OUT/batches/index.json', encoding='utf-8'))
print(d.get('batches_written', 0), d.get('total_working', 0))
" 2>/dev/null || echo "0 0")
EOF2
fi

{
  echo "# کانفیگ‌های تست‌شده"
  echo
  echo "آخرین به‌روزرسانی: **$NOW** · هر ۳۰ دقیقه خودکار به‌روز می‌شود."
  echo
  echo "همه‌ی کانفیگ‌ها با هسته‌ی واقعی Xray تست شده‌اند و ترافیک واقعی از"
  echo "داخلشان عبور کرده — مرتب‌شده از کم‌پینگ‌ترین."
  echo
  echo "## لینک اشتراک (پیشنهادی)"
  echo
  echo "این لینک را در کلاینت خود (v2rayNG، Nekoray، v2rayN، Hiddify) به عنوان"
  echo "Subscription اضافه کنید — خودش به‌روز می‌ماند:"
  echo
  echo '```'
  echo "$RAW/top20_sub.txt"
  echo '```'
  echo
  echo "## لینک خام"
  echo
  echo "برای کپی دستی ($COUNT کانفیگ برتر):"
  echo
  echo '```'
  echo "$RAW/top20.txt"
  echo '```'
  echo
  if [ "$BATCHES" -gt 0 ] 2>/dev/null; then
    echo "## دسته‌های کامل"
    echo
    echo "در مجموع **$TOTAL** کانفیگ سالم، در $BATCHES دسته:"
    echo
    echo "| دسته | لینک |"
    echo "|---|---|"
    for f in "$STAGE/batches"/batch_*.txt; do
      [ -e "$f" ] || continue
      b="$(basename "$f")"
      echo "| \`$b\` | $RAW/batches/$b |"
    done
    echo
  fi
  echo "## نکته‌ها"
  echo
  echo "- نام کانفیگ‌ها بازنویسی شده (\`🇩🇪 DE-01 | 210ms\`): کشور، رتبه، پینگ."
  echo "  هیچ نام کانال و متن تبلیغاتی منبع در خروجی نیست."
  echo "- کانفیگ‌ها از منابع عمومی جمع می‌شوند؛ تضمینی برای پایداری نیست."
  echo "- پینگ از رانر گیت‌هاب اندازه‌گیری شده و با شبکه‌ی شما فرق دارد."
} > "$STAGE/README.md"

# ---- ساخت کامیت بدون دست‌زدن به working tree ----
# ایندکس موقت جداست، پس ایندکس اصلی مخزن دست‌نخورده می‌ماند.
# autocrlf را خاموش می‌کنیم: اگر مخزن کاربر CRLF بزند، فایل اشتراک در
# کلاینت خراب می‌شود و دیباگش از سمت کاربر تقریباً غیرممکن است.
GIT_INDEX_FILE="$INDEX" git -c core.autocrlf=false -c core.eol=lf \
  --work-tree="$STAGE" add -A
TREE="$(GIT_INDEX_FILE="$INDEX" git write-tree)"

# اگر محتوا با نسخه‌ی منتشرشده یکی است، کامیت جدید بی‌فایده است
if git fetch --depth 1 origin "$BRANCH" >/dev/null 2>&1; then
  OLD="$(git rev-parse --verify --quiet FETCH_HEAD^{tree} || true)"
  if [ -n "$OLD" ] && [ "$OLD" = "$TREE" ]; then
    log "خروجی نسبت به نسخه‌ی منتشرشده تغییری نکرده — کامیت جدید لازم نیست"
    echo "  لینک اشتراک: $RAW/top20_sub.txt"
    exit 0
  fi
fi

COMMIT="$(
  GIT_AUTHOR_NAME="github-actions[bot]" \
  GIT_AUTHOR_EMAIL="41898282+github-actions[bot]@users.noreply.github.com" \
  GIT_COMMITTER_NAME="github-actions[bot]" \
  GIT_COMMITTER_EMAIL="41898282+github-actions[bot]@users.noreply.github.com" \
  git commit-tree "$TREE" -m "کانفیگ‌ها: $NOW"
)"

# شاخه‌ی یتیم و تک‌کامیت: هر بار جایگزین، نه اضافه
git push -f -q origin "$COMMIT:refs/heads/$BRANCH" \
  || { echo "خطا: انتشار ناموفق — دسترسی نوشتن مخزن را بررسی کنید" >&2; exit 1; }

log "منتشر شد → https://github.com/$REPO/tree/$BRANCH"
echo "  لینک اشتراک: $RAW/top20_sub.txt"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo ""
    echo "### 🔗 لینک عمومی"
    echo ""
    echo "این را در کلاینت به عنوان Subscription اضافه کنید — خودکار به‌روز می‌شود:"
    echo ""
    echo '```'
    echo "$RAW/top20_sub.txt"
    echo '```'
    echo ""
    echo "[صفحه‌ی راهنما و دسته‌های کامل](https://github.com/$REPO/tree/$BRANCH)"
  } >> "$GITHUB_STEP_SUMMARY"
fi
