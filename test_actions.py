"""تست نسخه‌ی گیت‌هاب اکشن — بدون نیاز به شبکه یا خود گیت‌هاب.

  python test_actions.py

بررسی می‌کند که:
  • config.ci.yaml معتبر است و مقادیر مخصوص لینوکس را دارد
  • ساخت config.yaml از سکرت‌ها درست کار می‌کند (با و بدون تلگرام)
  • ورک‌فلوها YAML معتبرند و به فایل‌ها و فلگ‌های موجود ارجاع می‌دهند
  • اسکریپت‌های شل خط‌پایان LF دارند (وگرنه لینوکس اجرایشان نمی‌کند)
  • هیچ رمزی در فایل‌های قابل کامیت نیست
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

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


def build_config(env: dict) -> dict:
    """همان منطق scripts/make-config.sh، برای تست بدون bash."""
    cfg = yaml.safe_load((ROOT / "config.ci.yaml").read_text(encoding="utf-8")) or {}
    tg = cfg.setdefault("telegram", {})

    session = env.get("VT_TELEGRAM_SESSION", "").strip()
    api_id = env.get("VT_TELEGRAM_API_ID", "").strip()
    api_hash = env.get("VT_TELEGRAM_API_HASH", "").strip()
    channels = [c.strip() for c in env.get("VT_TELEGRAM_CHANNELS", "").split(",") if c.strip()]

    if session and api_id:
        if not api_id.isdigit():
            raise ValueError(f"api_id باید عدد باشد: {api_id!r}")
        if not channels:
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
    return cfg


# ---------------------------------------------------------------------------

def test_ci_config() -> None:
    print("\n[۱] فایل تنظیمات CI")
    path = ROOT / "config.ci.yaml"
    check("config.ci.yaml موجود است", path.exists())
    if not path.exists():
        return

    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    check("YAML معتبر است", isinstance(cfg, dict))
    check("هسته بدون .exe", cfg["xray"]["binary"] == "xray", cfg["xray"]["binary"])
    check("دروازه‌ی VPN خاموش", cfg["vpn_gate"]["enabled"] is False)
    check("تلگرام پیش‌فرض خاموش", cfg["telegram"]["enabled"] is False)
    check("تلگرام در سرویس روشن", cfg["live"]["telegram_in_service"] is True)
    check("سقف تست برای مهلت جاب", cfg["live"]["batch_test_size"] > 0,
          str(cfg["live"]["batch_test_size"]))
    check("محدوده‌ی پورت کافی",
          cfg["xray"]["port_end"] - cfg["xray"]["port_start"] >= cfg["test"]["concurrency"])

    # هیچ رمزی نباید در فایلی که کامیت می‌شود باشد
    raw = path.read_text(encoding="utf-8")
    check("بدون session_string", not re.search(r"session_string:\s*['\"]?\w{20,}", raw))
    check("بدون api_hash واقعی", not re.search(r"api_hash:\s*['\"]?[0-9a-f]{32}", raw))
    check("api_id صفر است", cfg["telegram"]["api_id"] == 0, str(cfg["telegram"]["api_id"]))


def test_config_generation() -> None:
    print("\n[۲] ساخت تنظیمات از سکرت‌ها")

    # بدون هیچ سکرتی
    cfg = build_config({})
    check("بدون سکرت: تلگرام خاموش", cfg["telegram"]["enabled"] is False)
    check("بدون سکرت: بقیه دست‌نخورده", cfg["xray"]["binary"] == "xray")

    # با سکرت کامل — مقادیر ساختگی، نه رمز واقعی
    cfg = build_config({
        "VT_TELEGRAM_SESSION": "1FAKEsessionSTRINGforTESTINGonly0000",
        "VT_TELEGRAM_API_ID": "11112222",
        "VT_TELEGRAM_API_HASH": "0" * 31 + "x",
        "VT_TELEGRAM_CHANNELS": "@ch1,@ch2, @ch3",
    })
    tg = cfg["telegram"]
    check("با سکرت: تلگرام روشن", tg["enabled"] is True)
    check("api_id عدد شد", tg["api_id"] == 11112222 and isinstance(tg["api_id"], int))
    check("۳ کانال", tg["channels"] == ["@ch1", "@ch2", "@ch3"], str(tg["channels"]))

    # کانال تکی بدون کاما — جایی که شکستن رشته خطرناک است
    cfg = build_config({
        "VT_TELEGRAM_SESSION": "abc", "VT_TELEGRAM_API_ID": "123",
        "VT_TELEGRAM_CHANNELS": "@onlyone",
    })
    check("کانال تکی درست", cfg["telegram"]["channels"] == ["@onlyone"],
          str(cfg["telegram"]["channels"]))

    # سکرت ناقص → باید خاموش بماند، نه اینکه با مقدار نصفه اجرا شود
    cfg = build_config({"VT_TELEGRAM_SESSION": "abc"})
    check("سکرت ناقص: خاموش", cfg["telegram"]["enabled"] is False)

    # سشن هست ولی کانالی نیست → خاموش (وگرنه اعتبارسنجی می‌شکند)
    cfg = build_config({"VT_TELEGRAM_SESSION": "abc", "VT_TELEGRAM_API_ID": "123"})
    check("بدون کانال: خاموش", cfg["telegram"]["enabled"] is False)

    # api_id غیرعددی باید صریح رد شود
    try:
        build_config({"VT_TELEGRAM_SESSION": "abc", "VT_TELEGRAM_API_ID": "not-a-number",
                      "VT_TELEGRAM_CHANNELS": "@x"})
        check("api_id نامعتبر رد شد", False, "خطا نداد")
    except ValueError:
        check("api_id نامعتبر رد شد", True)

    # خروجی باید از دید خود برنامه معتبر باشد
    from vtester.settings import Settings
    tmp = ROOT / ".test_ci_config.yaml"
    try:
        cfg = build_config({
            "VT_TELEGRAM_SESSION": "abc", "VT_TELEGRAM_API_ID": "123",
            "VT_TELEGRAM_API_HASH": "h", "VT_TELEGRAM_CHANNELS": "@a,@b",
        })
        tmp.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False),
                       encoding="utf-8")
        s = Settings.load(str(tmp), root=str(ROOT))
        check("Settings آن را می‌خواند", s.get("telegram.enabled") is True)
        check("کانال‌ها لیست ماندند", s.get("telegram.channels") == ["@a", "@b"])
        try:
            s.validate()
            check("اعتبارسنجی پاس شد", True)
        except ValueError as exc:
            # روی ویندوز باینری «xray» وجود ندارد؛ بقیه‌ی خطاها واقعی‌اند
            check("اعتبارسنجی فقط از نبود باینری شکست",
                  "Xray پیدا نشد" in str(exc), str(exc))
    finally:
        tmp.unlink(missing_ok=True)


def test_binary_lookup() -> None:
    """هسته روی رانر گیت‌هاب در ~/.local/bin است، نه در ریشه‌ی مخزن.

    قبلاً path_of نام خالی «xray» را به «<ریشه>/xray» تبدیل می‌کرد و
    اعتبارسنجی با «هسته‌ی Xray پیدا نشد» می‌شکست. binary_of باید در PATH
    هم بگردد، ولی مسیرهای صریح را دست‌نخورده بگذارد.
    """
    print("\n[۳] پیدا کردن هسته‌ی Xray")
    import shutil
    import tempfile

    from vtester.settings import Settings

    exe = "xray.bat" if os.name == "nt" else "xray"
    with tempfile.TemporaryDirectory() as tmpdir:
        bindir = Path(tmpdir) / "bin"
        bindir.mkdir()
        fake = bindir / exe
        fake.write_text("@echo off\necho Xray 0.0.0\n" if os.name == "nt"
                        else "#!/bin/sh\necho Xray 0.0.0\n", encoding="utf-8")
        fake.chmod(0o755)

        old_path = os.environ["PATH"]
        os.environ["PATH"] = str(bindir) + os.pathsep + old_path
        try:
            s = Settings({"xray": {"binary": "xray"}}, ROOT)
            found = s.binary_of("xray.binary")
            check("نام خالی از PATH پیدا می‌شود", found.exists(), str(found))
            check("همان فایل نصب‌شده است",
                  found.parent.resolve() == bindir.resolve(), str(found))
            check("shutil.which هم همان را می‌بیند", shutil.which("xray") is not None)

            # مسیرهای صریح نباید به PATH سرریز کنند
            for explicit in ("./xray", "bin/xray"):
                s = Settings({"xray": {"binary": explicit}}, ROOT)
                got = s.binary_of("xray.binary")
                check(f"{explicit} نسبت به ریشه می‌ماند",
                      ROOT in got.parents or got.parent == ROOT, str(got))

            # مسیر مطلق باید دست‌نخورده بماند
            s = Settings({"xray": {"binary": str(fake)}}, ROOT)
            check("مسیر مطلق دست‌نخورده", s.binary_of("xray.binary") == fake)
        finally:
            os.environ["PATH"] = old_path

        # بدون PATH و بدون فایل، خطا باید همان پیام روشن قبلی باشد
        s = Settings({"xray": {"binary": "definitely-not-a-real-core"}}, ROOT)
        missing = s.binary_of("xray.binary")
        check("هسته‌ی نبود همچنان خطا می‌دهد", not missing.exists(), str(missing))


def test_workflows() -> None:
    print("\n[۴] ورک‌فلوها")
    wf_dir = ROOT / ".github" / "workflows"
    check("پوشه‌ی ورک‌فلو موجود است", wf_dir.is_dir())
    if not wf_dir.is_dir():
        return

    files = sorted(wf_dir.glob("*.yml"))
    check("دو ورک‌فلو", len(files) == 2, str([f.name for f in files]))

    # فلگ‌هایی که live.py واقعاً می‌شناسد
    live_src = (ROOT / "live.py").read_text(encoding="utf-8")
    known_flags = set(re.findall(r'add_argument\("(--[a-z-]+)"', live_src))

    for f in files:
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        name = f.name
        # نکته: در YAML کلمه‌ی on به True تبدیل می‌شود
        trigger = doc.get("on", doc.get(True))
        check(f"{name}: YAML معتبر", isinstance(doc, dict))
        check(f"{name}: زمان‌بندی دارد", "schedule" in (trigger or {}))
        check(f"{name}: اجرای دستی دارد", "workflow_dispatch" in (trigger or {}))
        check(f"{name}: قفل همزمانی", doc.get("concurrency", {}).get("group") == "vtester-state")
        check(f"{name}: اجازه‌ی نوشتن", doc.get("permissions", {}).get("contents") == "write")

        job = next(iter(doc["jobs"].values()))
        check(f"{name}: مهلت دارد", "timeout-minutes" in job)
        steps = job["steps"]
        runs = " ".join(s.get("run", "") for s in steps)

        check(f"{name}: تنظیمات را می‌سازد", "make-config.sh" in runs)
        check(f"{name}: حافظه را بازیابی می‌کند", "state.sh pull" in runs)
        check(f"{name}: حافظه را ذخیره می‌کند", "state.sh push" in runs)
        check(f"{name}: خروجی را آپلود می‌کند",
              any("upload-artifact" in str(s.get("uses", "")) for s in steps))

        # ذخیره‌ی حافظه باید حتی با شکست تست هم انجام شود
        push_step = next((s for s in steps if "state.sh push" in s.get("run", "")), None)
        check(f"{name}: ذخیره با if:always", push_step and push_step.get("if") == "always()")

        # هر فلگی که به live.py داده می‌شود باید واقعاً وجود داشته باشد
        for flag in set(re.findall(r"(--[a-z-]+)", runs)):
            if flag.startswith("--") and "live.py" in runs:
                if flag in ("--once", "--pool-only", "--skip-gate", "--max-test", "--config"):
                    check(f"{name}: فلگ {flag} شناخته‌شده است", flag in known_flags,
                          f"live.py این فلگ را ندارد")


def test_shell_scripts() -> None:
    print("\n[۵] اسکریپت‌های شل")
    scripts = ROOT / "scripts"
    check("پوشه‌ی scripts موجود است", scripts.is_dir())
    if not scripts.is_dir():
        return

    for name in ("make-config.sh", "state.sh", "summary.sh"):
        path = scripts / name
        check(f"{name} موجود است", path.exists())
        if not path.exists():
            continue
        raw = path.read_bytes()
        check(f"{name}: شبانگ دارد", raw.startswith(b"#!"))
        # CRLF روی لینوکس خطای «bad interpreter» می‌دهد
        check(f"{name}: بدون CRLF", b"\r\n" not in raw,
              "با make-actions-copy.ps1 تبدیل می‌شود")

    state = (scripts / "state.sh").read_text(encoding="utf-8")
    check("state.sh: بدون رمز اجرا نمی‌شود", "VT_STATE_PASSPHRASE" in state)
    check("state.sh: رمزنگاری AES256", "AES256" in state)
    check("state.sh: WAL را ادغام می‌کند", "wal_checkpoint" in state)
    check("state.sh: شاخه را جایگزین می‌کند", "--orphan" in state)


def test_no_secrets() -> None:
    print("\n[۶] نبود رمز در فایل‌های قابل کامیت")
    # الگوی session_string تلگرام: رشته‌ی بلند base64 که با 1B شروع می‌شود
    session_re = re.compile(r"1[A-Za-z]{2}\w{40,}")
    hash_re = re.compile(r"\b[0-9a-f]{32}\b")

    committed = []
    for pattern in ("config.ci.yaml", ".github/**/*.yml", "scripts/*.sh",
                    "actions-*.md", "*.py"):
        committed.extend(ROOT.glob(pattern))

    leaks = []
    for f in committed:
        if not f.is_file():
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        if session_re.search(text) or hash_re.search(text):
            leaks.append(f.name)

    check("هیچ رمزی در فایل‌های اکشن نیست", not leaks, str(leaks))

    gitignore = ROOT / ".gitignore"
    if gitignore.exists():
        ig = gitignore.read_text(encoding="utf-8")
        check("config.yaml در gitignore", "config.yaml" in ig)


# ---------------------------------------------------------------------------

def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    print("=" * 64)
    print("  تست نسخه‌ی گیت‌هاب اکشن")
    print("=" * 64)

    test_ci_config()
    test_config_generation()
    test_binary_lookup()
    test_workflows()
    test_shell_scripts()
    test_no_secrets()

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
