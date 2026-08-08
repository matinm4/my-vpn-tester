"""دریافت کانفیگ از کانال‌های تلگرام.

بازنویسی اسکریپت اصلی به شکل ماژول قابل فراخوانی. تفاوت کلیدی: شکست
تلگرام هرگز نباید کل سرویس را بخواباند — اگر تلگرام در دسترس نبود،
سرویس با لینک‌های ساب ادامه می‌دهد.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# الگوی کانفیگ — همان الگوی اسکریپت اصلی
_CONFIG_RE = re.compile(
    r"(vmess|vless|trojan|ss|ssr|hysteria|hysteria2|tuic)://\S+",
    re.IGNORECASE,
)


@dataclass
class TelegramResult:
    """نتیجه‌ی یک دور دریافت از تلگرام."""

    ok: bool = False
    links: List[str] = field(default_factory=list)
    new_links: List[str] = field(default_factory=list)
    channels_ok: int = 0
    channels_failed: int = 0
    messages_scanned: int = 0
    error: str = ""
    duration_s: float = 0.0

    @property
    def summary(self) -> str:
        if not self.ok:
            return f"ناموفق: {self.error}"
        return (f"{len(self.new_links)} کانفیگ جدید از {self.channels_ok} کانال "
                f"({self.messages_scanned} پیام بررسی شد)")


class TelegramScraper:
    """دریافت کانفیگ از کانال‌های تلگرام با کش پیام‌های پردازش‌شده."""

    def __init__(self, settings, logger) -> None:
        self.settings = settings
        self.log = logger

        self.api_id = settings.get("telegram.api_id")
        self.api_hash = settings.get("telegram.api_hash")
        self.session_string = settings.get("telegram.session_string")
        self.channels: List[str] = list(settings.get("telegram.channels") or [])
        self.days_back = int(settings.get("telegram.days_back", 30))
        self.per_channel_timeout = float(settings.get("telegram.per_channel_timeout", 180))
        self.total_timeout = float(settings.get("telegram.total_timeout", 900))
        self.max_messages = int(settings.get("telegram.max_messages_per_channel", 0))

        self.state_path = settings.path_of("telegram.state_file")
        self._processed: Dict[str, Set[int]] = {}
        self._seen_links: Set[str] = set()

    # ------------------------------------------------------------------

    @property
    def configured(self) -> bool:
        """آیا اطلاعات لازم برای اتصال هست؟"""
        return bool(
            self.settings.get("telegram.enabled", False)
            and self.api_id and self.api_hash
            and self.session_string and self.channels
        )

    # ------------------------------------------------------------------

    def _load_state(self) -> None:
        """کش پیام‌های پردازش‌شده را می‌خواند."""
        if not self.state_path.exists():
            return
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self._processed = {
                k: set(v) for k, v in (data.get("processed_messages") or {}).items()
            }
            self._seen_links = set(data.get("seen_links") or [])
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            self.log.warn(f"کش تلگرام خوانده نشد ({type(exc).__name__}) — از صفر شروع می‌شود")
            self._processed = {}
            self._seen_links = set()

    def _save_state(self) -> None:
        """کش را اتمی می‌نویسد تا قطع وسط نوشتن فایل را خراب نکند."""
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "processed_messages": {k: sorted(v) for k, v in self._processed.items()},
            "seen_links": sorted(self._seen_links),
            "saved_at": time.time(),
        }
        tmp = self.state_path.with_suffix(".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.state_path)
        except OSError as exc:
            self.log.warn(f"ذخیره‌ی کش تلگرام ناموفق: {exc}")
            if tmp.exists():
                tmp.unlink(missing_ok=True)

    # ------------------------------------------------------------------

    def fetch(self) -> TelegramResult:
        """دریافت همزمان از همه‌ی کانال‌ها. هرگز استثنا پرتاب نمی‌کند."""
        started = time.perf_counter()
        result = TelegramResult()

        if not self.configured:
            result.error = "تلگرام تنظیم نشده یا غیرفعال است"
            return result

        try:
            import telethon  # noqa: F401
        except ImportError:
            result.error = "کتابخانه telethon نصب نیست (pip install telethon)"
            self.log.warn(result.error)
            return result

        self._load_state()

        try:
            result = asyncio.run(
                asyncio.wait_for(self._fetch_async(result), timeout=self.total_timeout)
            )
        except asyncio.TimeoutError:
            result.error = f"مهلت کلی {self.total_timeout:g} ثانیه تمام شد"
            self.log.warn(f"تلگرام: {result.error}")
            # کانفیگ‌هایی که تا اینجا گرفته شده‌اند معتبرند
            result.ok = bool(result.links)
        except Exception as exc:  # noqa: BLE001 - تلگرام نباید سرویس را بخواباند
            result.error = f"{type(exc).__name__}: {exc}"[:160]
            self.log.warn(f"تلگرام ناموفق بود: {result.error}")
        finally:
            self._save_state()
            result.duration_s = time.perf_counter() - started

        return result

    async def _fetch_async(self, result: TelegramResult) -> TelegramResult:
        from telethon import TelegramClient
        from telethon.sessions import StringSession

        client = TelegramClient(
            StringSession(self.session_string), int(self.api_id), self.api_hash
        )

        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=self.days_back)

        await client.connect()
        try:
            if not await client.is_user_authorized():
                result.error = "نشست تلگرام معتبر نیست (session_string را بررسی کنید)"
                self.log.warn(result.error)
                return result

            self.log.info(f"تلگرام متصل شد — {len(self.channels)} کانال")

            for channel in self.channels:
                try:
                    await asyncio.wait_for(
                        self._scrape_channel(client, channel, start_date, end_date, result),
                        timeout=self.per_channel_timeout,
                    )
                    result.channels_ok += 1
                except asyncio.TimeoutError:
                    result.channels_failed += 1
                    self.log.warn(f"کانال {channel}: مهلت تمام شد — رد می‌شود")
                except Exception as exc:  # noqa: BLE001 - یک کانال خراب بقیه را نخواباند
                    result.channels_failed += 1
                    self.log.warn(f"کانال {channel}: {type(exc).__name__} — رد می‌شود")

                self._save_state()
                await asyncio.sleep(1.5)  # فاصله برای جلوگیری از محدودیت نرخ

            result.ok = True
        finally:
            try:
                await client.disconnect()
            except Exception:  # noqa: BLE001
                pass

        return result

    async def _scrape_channel(self, client, channel: str, start_date, end_date,
                              result: TelegramResult) -> None:
        from telethon.errors import FloodWaitError

        entity = await client.get_entity(channel)
        key = getattr(entity, "username", None) or str(channel)
        processed = self._processed.setdefault(key, set())

        scanned = 0
        found = 0

        try:
            async for message in client.iter_messages(entity):
                if message.date < start_date:
                    break
                if message.date > end_date:
                    continue
                if message.id in processed:
                    continue

                processed.add(message.id)
                scanned += 1
                result.messages_scanned += 1

                text = await self._message_text(client, message)
                for match in _CONFIG_RE.finditer(text or ""):
                    link = match.group(0).strip().rstrip(",;)»")
                    result.links.append(link)
                    if link not in self._seen_links:
                        self._seen_links.add(link)
                        result.new_links.append(link)
                        found += 1

                if self.max_messages and scanned >= self.max_messages:
                    break

        except FloodWaitError as exc:
            # صبر کردن برای محدودیت نرخ تلگرام منطقی نیست وقتی سرویس دائمی است
            self.log.warn(f"کانال {key}: محدودیت نرخ ({exc.seconds}s) — این دور رد می‌شود")

        self.log.info(f"  کانال {key}: {found} کانفیگ جدید از {scanned} پیام تازه")

    async def _message_text(self, client, message) -> str:
        """متن پیام + محتوای فایل txt پیوست."""
        content = message.message or ""

        if message.document and message.file and message.file.name:
            if message.file.name.lower().endswith((".txt", ".json", ".yaml", ".yml")):
                try:
                    blob = await asyncio.wait_for(
                        client.download_media(message.document, bytes), timeout=30
                    )
                    if blob and len(blob) < 8 * 1024 * 1024:  # سقف ۸ مگابایت
                        content += "\n" + blob.decode("utf-8", errors="ignore")
                except Exception:  # noqa: BLE001 - فایل خراب پیام را نباید بسوزاند
                    pass

        return content


def import_legacy_output(json_path: Path, logger) -> List[str]:
    """خواندن خروجی اسکریپت قدیمی (configs_output.json) برای مهاجرت."""
    if not json_path.exists():
        return []
    try:
        with open(json_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warn(f"خروجی قدیمی تلگرام خوانده نشد: {exc}")
        return []

    links: List[str] = []
    for channel_configs in (data or {}).values():
        if not isinstance(channel_configs, list):
            continue
        for entry in channel_configs:
            if isinstance(entry, dict) and entry.get("config"):
                links.append(str(entry["config"]))

    return links
