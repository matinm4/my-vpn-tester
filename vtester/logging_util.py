"""لاگر ساده و thread-safe با رنگ برای کنسول ویندوز."""

from __future__ import annotations

import os
import sys
import threading

LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40, "quiet": 100}


def enable_utf8_console() -> None:
    """کنسول ویندوز به صورت پیش‌فرض cp1252 است و متن فارسی را خراب می‌کند."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        # فعال‌سازی ANSI روی کنسول قدیمی ویندوز
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            return False
    return True


class Logger:
    C = {
        "reset": "\033[0m",
        "dim": "\033[2m",
        "bold": "\033[1m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "cyan": "\033[36m",
        "grey": "\033[90m",
    }

    def __init__(self, level: str = "info") -> None:
        self.level = LEVELS.get(level, 20)
        self.color = _supports_color()
        self._lock = threading.Lock()

    def paint(self, text: str, *styles: str) -> str:
        if not self.color:
            return text
        prefix = "".join(self.C.get(s, "") for s in styles)
        return f"{prefix}{text}{self.C['reset']}" if prefix else text

    def _emit(self, level: int, text: str) -> None:
        if level < self.level:
            return
        with self._lock:
            print(text, flush=True)

    def debug(self, msg: str) -> None:
        self._emit(10, self.paint(f"  · {msg}", "grey"))

    def info(self, msg: str) -> None:
        self._emit(20, f"  {msg}")

    def warn(self, msg: str) -> None:
        self._emit(30, self.paint(f"  ! {msg}", "yellow"))

    def error(self, msg: str) -> None:
        self._emit(40, self.paint(f"  × {msg}", "red"))

    def raw(self, text: str = "") -> None:
        self._emit(20, text)

    def heading(self, text: str) -> None:
        self._emit(20, "\n" + self.paint(text, "bold", "cyan"))
