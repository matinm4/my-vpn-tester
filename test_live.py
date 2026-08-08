"""تست‌های سرویس دائمی — بدون نیاز به شبکه.

  python test_live.py
"""

from __future__ import annotations

import base64
import json
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vtester.links import parse_link
from vtester.logging_util import Logger, enable_utf8_console
from vtester.models import TestResult
from vtester.settings import Settings
from vtester.store import ConfigStore

U = "b831381d-6324-4d53-ad4f-8cda48b30811"
ROOT = Path(__file__).resolve().parent
# مطلق، وگرنه اگر تست از پوشه‌ی دیگری اجرا شود مسیر موقت تست و مسیری که
# Settings.path_of می‌سازد به دو جای متفاوت اشاره می‌کنند.
TMP = ROOT / ".test_live_tmp"

passed = 0
failed: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    global passed
    if condition:
        passed += 1
        print(f"  PASS  {label}")
    else:
        failed.append(label)
        print(f"  FAIL  {label}" + (f" — {detail}" if detail else ""))


def cfg(host: str, name: str):
    return parse_link(f"vless://{U}@{host}:443?encryption=none&type=tcp#{name}")


def result(c, ok: bool, ms, at: float, ip: str = ""):
    return TestResult(
        fingerprint=c.fingerprint(), config=c.to_dict(), ok=ok, latency_ms=ms,
        tested_at=at, stage="done" if ok else "probe",
        error="" if ok else "timeout", exit_ip=ip,
    )


# ---------------------------------------------------------------------------

def test_pool_eviction() -> None:
    """کانفیگی که تازه افتاده باید فوراً از استخر خارج شود."""
    print("\n[۱] خروج کانفیگ مرده از استخر")
    store = ConfigStore(TMP / "evict.db")
    a, b, c = cfg("1.1.1.1", "A-fast"), cfg("2.2.2.2", "B-med"), cfg("3.3.3.3", "C-slow")
    store.upsert_configs_batch([a, b, c])
    t = time.time()

    for conf, ms in ((a, 100), (b, 200), (c, 300)):
        store.record_test_result(result(conf, True, ms, t))
    names = [r.config["name"] for r in store.get_top_working(limit=5)]
    check("هر سه در استخر", names == ["A-fast", "B-med", "C-slow"], str(names))

    # A می‌افتد — تست جدیدتر و ناموفق
    store.record_test_result(result(a, False, None, t + 10))
    names = [r.config["name"] for r in store.get_top_working(limit=5)]
    check("A بلافاصله خارج شد", "A-fast" not in names, str(names))
    check("B و C دست‌نخورده", names == ["B-med", "C-slow"], str(names))

    # A دوباره زنده می‌شود
    store.record_test_result(result(a, True, 150, t + 20))
    names = [r.config["name"] for r in store.get_top_working(limit=5)]
    check("A بعد از بازگشت دوباره اول", names == ["A-fast", "B-med", "C-slow"], str(names))

    check("ناموفق‌ها در گزارش", len(store.get_recent_failures()) == 0,
          "A الان سالم است پس نباید در ناموفق‌ها باشد")
    store.close()


def test_blacklist() -> None:
    """۳ شکست متوالی → ۲۴ ساعت کنار گذاشته شود؛ موفقیت شمارنده را صفر کند."""
    print("\n[۲] لیست سیاه بعد از ۳ شکست")
    store = ConfigStore(TMP / "black.db")
    x = cfg("9.9.9.9", "X")
    store.upsert_config(x)
    t = time.time()

    store.record_test_result(result(x, False, None, t))
    check("بعد از ۱ شکست هنوز آزاد", not store.is_blacklisted(x.fingerprint()))
    store.record_test_result(result(x, False, None, t + 1))
    check("بعد از ۲ شکست هنوز آزاد", not store.is_blacklisted(x.fingerprint()))
    store.record_test_result(result(x, False, None, t + 2))
    check("بعد از ۳ شکست در لیست سیاه", store.is_blacklisted(x.fingerprint()))

    # موفقیت باید شمارنده را صفر کند
    y = cfg("8.8.8.8", "Y")
    store.upsert_config(y)
    store.record_test_result(result(y, False, None, t))
    store.record_test_result(result(y, False, None, t + 1))
    store.record_test_result(result(y, True, 300, t + 2))
    store.record_test_result(result(y, False, None, t + 3))
    check("موفقیت شمارنده را صفر کرد", not store.is_blacklisted(y.fingerprint()),
          "بعد از موفقیت فقط ۱ شکست دارد")

    # کانفیگ تعلیق‌شده که دوباره کار می‌کند باید فوراً آزاد شود
    store.record_test_result(result(x, True, 250, t + 3))
    check("موفقیت تعلیق را برداشت", not store.is_blacklisted(x.fingerprint()))
    names = [r.config["name"] for r in store.get_top_working(limit=5)]
    check("و به استخر برگشت", "X" in names, str(names))

    # آستانه باید قابل تنظیم باشد
    store2 = ConfigStore(TMP / "black2.db", blacklist_after=2, blacklist_hours=1)
    z = cfg("6.6.6.6", "Z")
    store2.upsert_config(z)
    store2.record_test_result(result(z, False, None, t))
    check("با آستانه ۲: بعد از ۱ شکست آزاد", not store2.is_blacklisted(z.fingerprint()))
    store2.record_test_result(result(z, False, None, t + 1))
    check("با آستانه ۲: بعد از ۲ شکست تعلیق", store2.is_blacklisted(z.fingerprint()))
    store2.close()
    store.close()


def test_prune_and_geo() -> None:
    """هرس نباید آخرین وضعیت را از بین ببرد؛ غنی‌سازی نباید ردیف تکراری بسازد."""
    print("\n[۳] هرس و غنی‌سازی")
    store = ConfigStore(TMP / "prune.db")
    a = cfg("1.2.3.4", "A")
    store.upsert_config(a)
    t = time.time()

    for i in range(10):
        store.record_test_result(result(a, True, 200 + i, t + i))
    before = store.get_stats()["total_results"]

    stats = store.prune(keep_per_config=3, older_than_days=365)
    after = store.get_stats()["total_results"]
    check("هرس ردیف اضافی را حذف کرد", after == 3, f"{before} → {after}")
    check("کانفیگ هنوز در استخر", len(store.get_top_working(limit=5)) == 1)

    # غنی‌سازی باید UPDATE کند نه INSERT
    enriched = result(a, True, 209, t + 9, ip="5.6.7.8")
    enriched.country_code, enriched.isp = "DE", "Hetzner"
    ok = store.update_geo(enriched)
    check("update_geo موفق", ok)
    check("ردیف تکراری نساخت", store.get_stats()["total_results"] == 3)
    top = store.get_top_working(limit=1)
    check("داده‌ی جغرافیایی ذخیره شد",
          bool(top) and top[0].country_code == "DE" and top[0].isp == "Hetzner",
          str(top[0].country_code if top else None))
    store.close()


def test_scale() -> None:
    """کوئری استخر با ۲۰۰ هزار کانفیگ باید آنی بماند."""
    print("\n[۴] مقیاس ۲۰۰٬۰۰۰ کانفیگ")
    store = ConfigStore(TMP / "scale.db")
    t = time.time()
    total = 200_000

    build_start = time.perf_counter()
    chunk = []
    all_configs = []
    for i in range(total):
        c = cfg(f"10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}", f"N{i}")
        chunk.append(c)
        if len(chunk) >= 5000:
            store.upsert_configs_batch(chunk)
            all_configs.extend(chunk)
            chunk = []
    if chunk:
        store.upsert_configs_batch(chunk)
        all_configs.extend(chunk)
    first_pass = time.perf_counter() - build_start
    print(f"        دور اول (همه جدید): {first_pass:.1f} ثانیه")

    # دور دوم: همان کانفیگ‌ها دوباره می‌آیند — حالت رایج در سرویس دائمی
    again = time.perf_counter()
    for start in range(0, total, 5000):
        store.upsert_configs_batch(all_configs[start:start + 5000])
    second_pass = time.perf_counter() - again
    print(f"        دور دوم (همه تکراری): {second_pass:.1f} ثانیه")
    check("دور تکراری سریع‌تر از دور اول", second_pass < first_pass,
          f"{second_pass:.1f}s در برابر {first_pass:.1f}s")

    # ۲۰ هزارتای اول نتیجه بگیرند
    conn = store._get_conn()
    rows = conn.execute("SELECT config_data FROM configs LIMIT 20000").fetchall()
    import json as _json
    from vtester.models import ProxyConfig
    res_start = time.perf_counter()
    for idx, row in enumerate(rows):
        c = ProxyConfig.from_dict(_json.loads(row["config_data"]))
        store.record_test_result(result(c, idx % 3 != 0, 100 + idx % 900, t))
    print(f"        ثبت ۲۰٬۰۰۰ نتیجه در {time.perf_counter() - res_start:.1f} ثانیه")

    q = time.perf_counter()
    top = store.get_top_working(limit=20)
    elapsed_ms = (time.perf_counter() - q) * 1000
    print(f"        کوئری top-20: {elapsed_ms:.0f} ms")
    check("کوئری استخر زیر ۵۰۰ میلی‌ثانیه", elapsed_ms < 500, f"{elapsed_ms:.0f} ms")
    check("۲۰ کانفیگ برگشت", len(top) == 20, str(len(top)))
    check("مرتب بر اساس پینگ",
          all(top[i].latency_ms <= top[i + 1].latency_ms for i in range(len(top) - 1)))
    print(f"        آمار: {store.get_stats()}")
    store.close()


def test_settings() -> None:
    """همه‌ی کلیدهایی که ماژول‌های جدید لازم دارند باید موجود باشند."""
    print("\n[۵] تنظیمات")
    root = Path(__file__).resolve().parent
    settings = Settings.load(root=str(root))
    required = [
        "store.path", "store.keep_results_per_config", "store.prune_after_days",
        "telegram.enabled", "telegram.api_id", "telegram.api_hash",
        "telegram.session_string", "telegram.channels", "telegram.days_back",
        "telegram.per_channel_timeout", "telegram.total_timeout",
        "telegram.max_messages_per_channel", "telegram.state_file",
        "telegram.legacy_output",
        "vpn_gate.enabled", "vpn_gate.wait_minutes", "vpn_gate.probe_url",
        "vpn_gate.require_ip_change", "vpn_gate.reminder_seconds",
        "pool.size", "pool.batch_size", "pool.max_batches", "pool.max_age_hours",
        "pool.history_limit", "pool.history_file", "pool.top_file",
        "pool.top_sub_file", "pool.batch_dir",
        "live.discovery_interval_minutes", "live.pool_interval_minutes",
        "live.batch_test_size", "live.retest_after_hours", "live.log_failures",
        "live.telegram_in_service",
    ]
    missing = [k for k in required if settings.get(k, "__MISSING__") == "__MISSING__"]
    check("همه‌ی کلیدها موجودند", not missing, f"جا افتاده: {missing}")

    # نبودِ باینری Xray خطای تنظیمات نیست: در نسخه‌ی گیت‌هاب اکشن، هسته را
    # ورک‌فلو موقع اجرا دانلود می‌کند. فقط بقیه‌ی خطاها واقعی‌اند.
    try:
        settings.validate()
        check("اعتبارسنجی پاس شد", True)
    except ValueError as exc:
        msg = str(exc)
        only_binary = "Xray پیدا نشد" in msg and msg.strip().count("- ") == 1
        check("اعتبارسنجی پاس شد", only_binary,
              "نبود باینری (طبیعی)" if only_binary else msg)

    # اعتبارسنجی باید مقدار بد را بگیرد
    settings.set("pool.size", 0)
    try:
        settings.validate()
        check("pool.size=0 رد شد", False, "اعتبارسنجی اجازه داد")
    except ValueError:
        check("pool.size=0 رد شد", True)


def test_pool_outputs() -> None:
    """فایل‌های خروجی استخر و دسته‌بندی."""
    print("\n[۶] خروجی‌های استخر")
    from vtester.pool import PoolManager

    root = Path(__file__).resolve().parent
    settings = Settings.load(root=str(root))
    settings.set("output.dir", str(TMP / "out"))
    settings.set("pool.size", 3)
    settings.set("pool.batch_size", 2)

    store = ConfigStore(TMP / "pool.db")
    t = time.time()
    configs = [cfg(f"7.7.7.{i}", f"P{i}") for i in range(5)]
    store.upsert_configs_batch(configs)
    for i, c in enumerate(configs):
        store.record_test_result(result(c, True, 100 + i * 10, t))

    log = Logger("warn")
    pool = PoolManager(settings, log, store)
    members, changes = pool.refresh(note="تست")
    check("استخر ۳ عضو دارد", len(members) == 3, str(len(members)))
    check("۳ تغییر «ورود» ثبت شد",
          len([c for c in changes if c.action == "added"]) == 3)

    written = pool.write_outputs()
    top_file = Path(written["top"])
    check("top file ساخته شد", top_file.exists())
    check("۳ لینک در top", len(top_file.read_text(encoding="utf-8").strip().splitlines()) == 3)

    # مسیر دسته‌ها از خروجی خوانده می‌شود، نه حدس زده شود
    batch1 = Path(written["batch_01"])
    batch_dir = batch1.parent
    check("batch_01 ساخته شد", batch1.exists(), str(batch1))
    body = [l for l in batch1.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.startswith("#")]
    check("batch_01 دو لینک دارد", len(body) == 2, str(len(body)))
    check("۳ دسته برای ۵ کانفیگ",
          len(list(batch_dir.glob("batch_*.txt"))) == 3,
          str(sorted(p.name for p in batch_dir.glob("batch_*.txt"))))

    index = json.loads((batch_dir / "index.json").read_text(encoding="utf-8"))
    check("index.json درست است",
          index["total_working"] == 5 and index["batches_written"] == 3,
          str(index))

    sub_file = Path(written["top_sub"])
    decoded = base64.b64decode(sub_file.read_text(encoding="utf-8")).decode("utf-8")
    check("base64 قابل رمزگشایی", len(decoded.strip().splitlines()) == 3)

    # حالا سریع‌ترین می‌افتد
    store.record_test_result(result(configs[0], False, None, t + 100))
    members2, changes2 = pool.refresh(note="بعد از افتادن")
    names2 = [(m.config or {}).get("name") for m in members2]
    check("عضو افتاده خارج شد", "P0" not in names2, str(names2))
    check("جایگزین وارد شد", len(members2) == 3 and "P3" in names2, str(names2))
    check("تغییر خروج ثبت شد", any(c.action == "removed" for c in changes2))

    # فایل‌های دسته‌ای باید کوچک‌تر شوند و دسته‌ی کهنه پاک شود
    pool.write_outputs()
    check("دسته‌ها بعد از افتادن ۲ تا شدند",
          len(list(batch_dir.glob("batch_*.txt"))) == 2,
          str(sorted(p.name for p in batch_dir.glob("batch_*.txt"))))

    history_path = Path(pool.history_path)
    check("تاریخچه نوشته شد", history_path.exists())
    hist = json.loads(history_path.read_text(encoding="utf-8"))
    check("تاریخچه شامل ورود و خروج",
          any(c["action"] == "removed" for c in hist["changes"]),
          str(len(hist["changes"])))
    store.close()


def test_backlog() -> None:
    """کانفیگ ثبت‌شده ولی تست‌نشده باید در دورهای بعد برداشته شود.

    این همان باگی است که در اولین اجرای واقعی لو رفت: ۷۳۹۸ کانفیگ مهاجرت‌شده
    از تلگرام در پایگاه داده نشستند و چون در آن دور دوباره کشف نشدند، هرگز
    تست نمی‌شدند.
    """
    print("\n[۷] برداشتن کانفیگ‌های تست‌نشده از انبار")
    from vtester.live import CycleStats, LiveService

    settings = Settings.load(root=str(ROOT))
    settings.set("store.path", str(TMP / "backlog.db"))
    settings.set("output.dir", str(TMP / "bl_out"))
    settings.set("telegram.enabled", False)
    settings.set("live.max_untested_per_cycle", 10)

    service = LiveService(settings, Logger("warn"))
    t = time.time()

    # ۲۵ کانفیگ در انبار که هرگز تست نشده‌اند (مثل مهاجرت تلگرام)
    stored = [cfg(f"5.5.{i // 256}.{i % 256}", f"S{i}") for i in range(25)]
    service.store.upsert_configs_batch(stored)
    check("۲۵ کانفیگ تست‌نشده در انبار", service.store.count_untested() == 25,
          str(service.store.count_untested()))

    # این دور فقط ۲ کانفیگ تازه کشف می‌شود که هر دو از قبل تست شده‌اند
    fresh = [cfg("6.6.6.1", "F1"), cfg("6.6.6.2", "F2")]
    service.store.upsert_configs_batch(fresh)
    for c in fresh:
        service.store.record_test_result(result(c, True, 200, t))

    stats = CycleStats()
    selected = service.select_for_testing(fresh, stats)
    names = [c.remark for c in selected]

    check("کانفیگ‌های انبار برداشته شدند", len(selected) == 10, str(len(selected)))
    check("همه از انبار آمدند", all(n.startswith("S") for n in names), str(names))
    check("کانفیگ تازه‌تست‌شده دوباره تست نشد",
          not any(n.startswith("F") for n in names), str(names))
    check("باقی‌مانده گزارش شد", stats.backlog_remaining == 15,
          str(stats.backlog_remaining))

    # کانفیگ‌های برداشته‌شده تست می‌شوند → دور بعد بقیه می‌آیند
    for c in selected:
        service.store.record_test_result(result(c, False, None, t))
    check("انبار کم شد", service.store.count_untested() == 15,
          str(service.store.count_untested()))

    stats2 = CycleStats()
    selected2 = service.select_for_testing([], stats2)
    check("دور بعد ۱۰ تای دیگر برداشت", len(selected2) == 10, str(len(selected2)))
    check("تکراری برنداشت",
          not set(c.fingerprint() for c in selected2)
          & set(c.fingerprint() for c in selected))

    # کانفیگ در لیست سیاه نباید از انبار برداشته شود
    victim = cfg("7.7.7.7", "BL")
    service.store.upsert_config(victim)
    for _ in range(3):
        service.store.record_test_result(result(victim, False, None, t))
    backlog_names = [c.remark for c in service.store.get_untested_configs(limit=100)]
    check("کانفیگ لیست سیاه در انبار نیست", "BL" not in backlog_names)

    service.close()


# ---------------------------------------------------------------------------

def main() -> int:
    enable_utf8_console()
    if TMP.exists():
        shutil.rmtree(TMP, ignore_errors=True)
    TMP.mkdir(parents=True, exist_ok=True)

    print("=" * 64)
    print("  تست سرویس دائمی")
    print("=" * 64)

    try:
        test_pool_eviction()
        test_blacklist()
        test_prune_and_geo()
        test_settings()
        test_pool_outputs()
        test_backlog()
        if "--skip-scale" not in sys.argv:
            test_scale()
        else:
            print("\n[۴] مقیاس — رد شد (--skip-scale)")
    finally:
        shutil.rmtree(TMP, ignore_errors=True)

    print("\n" + "=" * 64)
    if failed:
        print(f"  {passed} موفق · {len(failed)} ناموفق")
        for name in failed:
            print(f"    ✕ {name}")
        return 1
    print(f"  همه‌ی {passed} تست موفق")
    return 0


if __name__ == "__main__":
    sys.exit(main())
