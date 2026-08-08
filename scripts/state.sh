#!/usr/bin/env bash
# ============================================================================
#  ذخیره و بازیابی حافظه‌ی سرویس بین اجراهای گیت‌هاب اکشن
#
#  پایگاه داده (کانفیگ‌ها، نتایج، لیست سیاه) و کش تلگرام در یک شاخه‌ی جدا
#  به اسم data نگه داشته می‌شوند — اما **رمزنگاری‌شده**، چون مخزن عمومی است
#  و این داده‌ها حاوی UUID و رمز کانفیگ‌های سالم هستند.
#
#  رمز از سکرت VT_STATE_PASSPHRASE خوانده می‌شود. اگر تنظیم نشده باشد،
#  اسکریپت عمداً شکست می‌خورد تا داده‌ی حساس اشتباهی خام کامیت نشود.
#
#  استفاده:
#     scripts/state.sh pull     بازیابی قبل از اجرا
#     scripts/state.sh push     ذخیره بعد از اجرا
# ============================================================================
set -euo pipefail

BRANCH="${VT_STATE_BRANCH:-data}"
ARCHIVE="vtester-state.tar.gz.gpg"
STATE_PATHS=(".cache")

die() { echo "خطا: $*" >&2; exit 1; }
log() { echo "  $*"; }

[ -n "${VT_STATE_PASSPHRASE:-}" ] || die "سکرت VT_STATE_PASSPHRASE تنظیم نشده است"

# ---------------------------------------------------------------------------

pull_state() {
  if ! git ls-remote --exit-code --heads origin "$BRANCH" >/dev/null 2>&1; then
    log "شاخه‌ی $BRANCH هنوز وجود ندارد — اولین اجراست، از صفر شروع می‌شود"
    return 0
  fi

  git fetch --depth 1 origin "$BRANCH" >/dev/null 2>&1 \
    || { log "دریافت شاخه‌ی $BRANCH ناموفق — از صفر شروع می‌شود"; return 0; }

  if ! git show "FETCH_HEAD:$ARCHIVE" > "$ARCHIVE" 2>/dev/null; then
    log "آرشیوی در شاخه‌ی $BRANCH نبود — از صفر شروع می‌شود"
    rm -f "$ARCHIVE"
    return 0
  fi

  local size
  size=$(du -h "$ARCHIVE" | cut -f1)
  log "آرشیو دریافت شد ($size) — در حال رمزگشایی"

  if ! gpg --batch --yes --quiet \
        --passphrase "$VT_STATE_PASSPHRASE" \
        --output "state.tar.gz" --decrypt "$ARCHIVE" 2>/dev/null; then
    # رمز عوض شده یا آرشیو خراب است. ادامه با حافظه‌ی خالی بهتر از
    # خواباندن کل اجراست، ولی باید صریح گزارش شود.
    echo "::warning::رمزگشایی حافظه ناموفق بود — این اجرا از صفر شروع می‌شود." >&2
    echo "::warning::اگر VT_STATE_PASSPHRASE را عوض کرده‌اید، شاخه‌ی $BRANCH را پاک کنید." >&2
    rm -f "$ARCHIVE" "state.tar.gz"
    return 0
  fi

  tar xzf "state.tar.gz"
  rm -f "state.tar.gz" "$ARCHIVE"

  if [ -f ".cache/configs.db" ]; then
    local db_size
    db_size=$(du -h .cache/configs.db | cut -f1)
    log "پایگاه داده بازیابی شد ($db_size)"
  fi
  if [ -f ".cache/telegram_state.json" ]; then
    log "کش تلگرام بازیابی شد"
  fi
}

# ---------------------------------------------------------------------------

push_state() {
  local existing=()
  for p in "${STATE_PATHS[@]}"; do
    [ -e "$p" ] && existing+=("$p")
  done
  [ ${#existing[@]} -gt 0 ] || { log "چیزی برای ذخیره نیست"; return 0; }

  # SQLite در حالت WAL فایل‌های جانبی می‌سازد؛ باید ادغام شوند وگرنه
  # آرشیو ناقص می‌ماند و اجرای بعدی داده‌ی آخرین لحظات را نمی‌بیند.
  if [ -f ".cache/configs.db" ] && command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 .cache/configs.db "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || true
    rm -f .cache/configs.db-wal .cache/configs.db-shm
  fi

  tar czf "state.tar.gz" "${existing[@]}"
  gpg --batch --yes --quiet \
      --passphrase "$VT_STATE_PASSPHRASE" \
      --symmetric --cipher-algo AES256 \
      --output "$ARCHIVE" "state.tar.gz"
  rm -f "state.tar.gz"

  local size
  size=$(du -h "$ARCHIVE" | cut -f1)
  log "آرشیو رمزنگاری شد ($size)"

  # شاخه‌ی data همیشه تک‌کامیت است: هر بار جایگزین می‌شود، نه اضافه.
  # وگرنه با اجرای هر ۳۰ دقیقه، تاریخچه‌ی مخزن بی‌نهایت بزرگ می‌شود.
  git config user.name "github-actions[bot]"
  git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

  git checkout --orphan "state-tmp" >/dev/null 2>&1
  git rm -rf --cached . >/dev/null 2>&1 || true
  git add -f "$ARCHIVE"
  git commit -q -m "state: $(date -u '+%Y-%m-%d %H:%M UTC')"

  if git push -f -q origin "state-tmp:$BRANCH"; then
    log "حافظه در شاخه‌ی $BRANCH ذخیره شد"
  else
    die "ذخیره‌ی حافظه ناموفق بود — دسترسی نوشتن روی مخزن را بررسی کنید"
  fi
}

# ---------------------------------------------------------------------------

case "${1:-}" in
  pull) pull_state ;;
  push) push_state ;;
  *)    die "استفاده: $0 {pull|push}" ;;
esac
