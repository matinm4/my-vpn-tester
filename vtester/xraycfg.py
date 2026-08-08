"""ساخت فایل کانفیگ JSON هسته‌ی Xray از روی یک ProxyConfig."""

from __future__ import annotations

import copy
from typing import Any, Dict, List

from .models import ProxyConfig


class BuildError(ValueError):
    """کانفیگ قابل تبدیل به outbound معتبر نیست."""


def _deep_merge(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in (patch or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _alpn_list(alpn: str) -> List[str]:
    return [a.strip() for a in alpn.replace(" ", "").split(",") if a.strip()]


# هدرهای مبهم‌سازی mKCP که در Xray 26 از طریق finalmask تنظیم می‌شوند
_KCP_HEADERS = {"srtp", "utp", "wechat-video", "dtls", "wireguard", "dns"}


# ---------------------------------------------------------------------------
# streamSettings
# ---------------------------------------------------------------------------

def build_stream_settings(cfg: ProxyConfig, allow_insecure_global: bool = False) -> Dict[str, Any]:
    network = cfg.network or "tcp"

    # Xray 26 ترنسپورت مستقل HTTP/2 را حذف کرده و آن را به XHTTP در حالت
    # stream-one منتقل کرده است. لینک‌های قدیمیِ type=http خودکار مهاجرت می‌شوند.
    h2_migrated = network == "h2"
    if h2_migrated:
        network = "xhttp"

    stream: Dict[str, Any] = {"network": network}

    # ---- لایه‌ی امنیت ----
    security = cfg.security if cfg.security in ("tls", "reality") else "none"
    stream["security"] = security

    if security == "tls":
        tls: Dict[str, Any] = {
            "serverName": cfg.sni or cfg.host or cfg.address,
            "allowInsecure": bool(cfg.allow_insecure or allow_insecure_global),
        }
        if cfg.alpn:
            tls["alpn"] = _alpn_list(cfg.alpn)
        elif h2_migrated:
            tls["alpn"] = ["h2"]
        if cfg.fp:
            tls["fingerprint"] = cfg.fp
        stream["tlsSettings"] = tls
    elif security == "reality":
        if not cfg.public_key:
            raise BuildError("REALITY بدون publicKey قابل استفاده نیست")
        reality: Dict[str, Any] = {
            "serverName": cfg.sni or cfg.address,
            "publicKey": cfg.public_key,
            "fingerprint": cfg.fp or "chrome",
        }
        if cfg.short_id:
            reality["shortId"] = cfg.short_id
        if cfg.spider_x:
            reality["spiderX"] = cfg.spider_x
        stream["realitySettings"] = reality

    # ---- لایه‌ی ترنسپورت ----
    if network == "tcp":
        if (cfg.header_type or "none") == "http":
            host_list = [h.strip() for h in (cfg.host or cfg.address).split(",") if h.strip()]
            stream["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "version": "1.1",
                        "method": "GET",
                        "path": [cfg.path or "/"],
                        "headers": {
                            "Host": host_list or [cfg.address],
                            "User-Agent": [
                                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
                            ],
                            "Accept-Encoding": ["gzip, deflate"],
                            "Connection": ["keep-alive"],
                            "Pragma": "no-cache",
                        },
                    },
                }
            }

    elif network == "ws":
        ws: Dict[str, Any] = {"path": cfg.path or "/"}
        if cfg.host:
            ws["host"] = cfg.host
        stream["wsSettings"] = ws

    elif network == "grpc":
        grpc: Dict[str, Any] = {"serviceName": cfg.service_name or ""}
        if cfg.grpc_mode == "multi":
            grpc["multiMode"] = True
        if cfg.sni:
            grpc["authority"] = cfg.sni
        stream["grpcSettings"] = grpc

    elif network == "httpupgrade":
        hu: Dict[str, Any] = {"path": cfg.path or "/"}
        if cfg.host:
            hu["host"] = cfg.host
        stream["httpupgradeSettings"] = hu

    elif network == "xhttp":
        xh: Dict[str, Any] = {"path": cfg.path or "/"}
        host = cfg.host or (cfg.sni if h2_migrated else "")
        if host:
            xh["host"] = host
        mode = cfg.xhttp_mode or ("stream-one" if h2_migrated else "")
        if mode:
            xh["mode"] = mode
        stream["xhttpSettings"] = xh

    elif network == "kcp":
        # در Xray 26 کلیدهای header و seed حذف شده‌اند؛ جایگزین‌ها
        # finalmask (برای مبهم‌سازی) و mkcp-aes128gcm (برای seed) هستند.
        kcp: Dict[str, Any] = {}
        header = (cfg.header_type or "none").strip().lower()
        if header in _KCP_HEADERS:
            kcp["finalmask"] = f"header-{header}"
        if cfg.seed:
            kcp["mkcp-aes128gcm"] = cfg.seed
        stream["kcpSettings"] = kcp

    elif network == "quic":
        # Xray 26 ترنسپورت خام QUIC را حذف کرده و به XHTTP روی H3 منتقل کرده است.
        # این دو معادل سیم‌به‌سیم نیستند، پس به جای تست غلط، پشتیبانی‌نشده اعلام می‌شود.
        raise BuildError("ترنسپورت QUIC در Xray 26 حذف شده است")

    else:
        raise BuildError(f"ترنسپورت پشتیبانی‌نشده: {network}")

    return stream


# ---------------------------------------------------------------------------
# outbound
# ---------------------------------------------------------------------------

def build_outbound(cfg: ProxyConfig, settings) -> Dict[str, Any]:
    allow_insecure = bool(settings.get("xray.allow_insecure", False))
    proto = cfg.protocol

    if proto == "vmess":
        user: Dict[str, Any] = {
            "id": cfg.uuid,
            "alterId": int(cfg.alter_id or 0),
            "security": cfg.vmess_security or "auto",
            "level": 0,
        }
        settings_block: Dict[str, Any] = {
            "vnext": [{"address": cfg.address, "port": cfg.port, "users": [user]}]
        }

    elif proto == "vless":
        user = {"id": cfg.uuid, "encryption": cfg.vless_encryption or "none", "level": 0}
        if cfg.flow:
            user["flow"] = cfg.flow
        settings_block = {
            "vnext": [{"address": cfg.address, "port": cfg.port, "users": [user]}]
        }

    elif proto == "trojan":
        settings_block = {
            "servers": [{
                "address": cfg.address,
                "port": cfg.port,
                "password": cfg.password,
                "level": 0,
            }]
        }

    elif proto == "shadowsocks":
        settings_block = {
            "servers": [{
                "address": cfg.address,
                "port": cfg.port,
                "method": cfg.method,
                "password": cfg.password,
                "uot": False,
                "level": 0,
            }]
        }

    elif proto in ("socks", "http"):
        server: Dict[str, Any] = {"address": cfg.address, "port": cfg.port}
        if cfg.username or cfg.password:
            server["users"] = [{"user": cfg.username, "pass": cfg.password, "level": 0}]
        settings_block = {"servers": [server]}

    else:
        raise BuildError(f"پروتکل پشتیبانی‌نشده: {proto}")

    outbound: Dict[str, Any] = {
        "tag": "proxy",
        "protocol": proto,
        "settings": settings_block,
        "streamSettings": build_stream_settings(cfg, allow_insecure),
    }

    if settings.get("xray.mux_enabled", False):
        outbound["mux"] = {
            "enabled": True,
            "concurrency": int(settings.get("xray.mux_concurrency", 8)),
        }

    extra = settings.get("xray.extra_outbound") or {}
    if extra:
        outbound = _deep_merge(outbound, extra)

    return outbound


# ---------------------------------------------------------------------------
# کانفیگ کامل
# ---------------------------------------------------------------------------

def build_full_config(cfg: ProxyConfig, socks_port: int, settings) -> Dict[str, Any]:
    """یک کانفیگ کامل Xray با یک اینباند SOCKS محلی و outbound این کانفیگ."""
    listen = settings.get("xray.listen", "127.0.0.1")
    log_level = settings.get("xray.log_level", "none")

    inbound: Dict[str, Any] = {
        "tag": "socks-in",
        "listen": listen,
        "port": socks_port,
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": False},
    }
    if settings.get("xray.sniffing", False):
        inbound["sniffing"] = {
            "enabled": True,
            "destOverride": ["http", "tls"],
            "routeOnly": False,
        }

    doc: Dict[str, Any] = {
        "log": {"loglevel": log_level},
        "inbounds": [inbound],
        "outbounds": [build_outbound(cfg, settings)],
    }

    strategy = settings.get("xray.domain_strategy", "AsIs")
    if strategy and strategy != "AsIs":
        doc["routing"] = {"domainStrategy": strategy, "rules": []}

    return doc
