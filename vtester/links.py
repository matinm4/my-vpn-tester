"""تبدیل لینک‌های اشتراک (vmess://، vless://، trojan://، ss://، ...) به ProxyConfig."""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, unquote, urlsplit

from .models import UNSUPPORTED_SCHEMES, ParseError, ProxyConfig

_TRUE = {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# کمکی‌ها
# ---------------------------------------------------------------------------

def b64decode_loose(data: str) -> Optional[str]:
    """دیکد base64 با تحمل padding ناقص و حالت urlsafe."""
    if not data:
        return None
    cleaned = re.sub(r"\s+", "", data)
    cleaned = cleaned.replace("-", "+").replace("_", "/")
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        raw = base64.b64decode(cleaned, validate=False)
    except Exception:
        return None
    for encoding in ("utf-8", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def _q(params: Dict[str, list], *names: str, default: str = "") -> str:
    """اولین مقدار موجود از میان چند نام مستعار برای یک پارامتر."""
    for name in names:
        if name in params and params[name]:
            value = params[name][0]
            if value != "":
                return unquote(value)
    return default


def _split_hostport(netloc: str) -> tuple[str, int]:
    """جدا کردن host و port با پشتیبانی از IPv6 داخل براکت."""
    netloc = netloc.strip()
    if netloc.startswith("["):
        end = netloc.find("]")
        if end == -1:
            raise ParseError("آدرس IPv6 ناقص است")
        host = netloc[1:end]
        rest = netloc[end + 1:]
        if not rest.startswith(":"):
            raise ParseError("پورت مشخص نشده است")
        port_s = rest[1:]
    else:
        if ":" not in netloc:
            raise ParseError("پورت مشخص نشده است")
        host, _, port_s = netloc.rpartition(":")
    if not host:
        raise ParseError("آدرس سرور خالی است")
    try:
        port = int(port_s)
    except ValueError:
        raise ParseError(f"پورت نامعتبر: {port_s!r}") from None
    if not (0 < port < 65536):
        raise ParseError(f"پورت خارج از محدوده: {port}")
    return host, port


def _normalise_network(net: str) -> str:
    net = (net or "tcp").strip().lower()
    aliases = {
        "": "tcp",
        "h2": "h2",
        "http": "h2",          # در لینک‌ها «http» یعنی HTTP/2
        "splithttp": "xhttp",  # نام قدیمی xhttp
        "raw": "tcp",          # نام جدید tcp در Xray
        "mkcp": "kcp",
    }
    return aliases.get(net, net)


def _normalise_security(sec: str) -> str:
    sec = (sec or "none").strip().lower()
    if sec in ("", "0", "none"):
        return "none"
    if sec in ("1", "tls"):
        return "tls"
    return sec  # tls | reality | xtls


# ---------------------------------------------------------------------------
# vmess://
# ---------------------------------------------------------------------------

def _parse_vmess(raw: str) -> ProxyConfig:
    body = raw[len("vmess://"):].strip()
    decoded = b64decode_loose(body.split("#", 1)[0])

    if decoded and decoded.lstrip().startswith("{"):
        return _parse_vmess_json(raw, decoded)

    # فرمت جایگزین: vmess://uuid@host:port?...#name
    if "@" in body:
        return _parse_uri_style(raw, "vmess")

    raise ParseError("بدنه‌ی vmess نه JSON بیس۶۴ است نه فرمت URI")


def _parse_vmess_json(raw: str, decoded: str) -> ProxyConfig:
    try:
        j: Dict[str, Any] = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise ParseError(f"JSON داخل vmess نامعتبر است: {exc.msg}") from None
    if not isinstance(j, dict):
        raise ParseError("JSON داخل vmess باید یک شیء باشد")

    def s(*names: str, default: str = "") -> str:
        for n in names:
            if n in j and j[n] not in (None, ""):
                return str(j[n]).strip()
        return default

    address = s("add", "address", "host")
    if not address:
        raise ParseError("آدرس سرور در vmess نیست")
    try:
        port = int(s("port", default="0"))
    except ValueError:
        raise ParseError(f"پورت نامعتبر: {s('port')!r}") from None
    if not (0 < port < 65536):
        raise ParseError(f"پورت خارج از محدوده: {port}")

    uuid = s("id", "uuid")
    if not uuid:
        raise ParseError("شناسه (id) در vmess نیست")

    try:
        alter_id = int(s("aid", "alterId", default="0"))
    except ValueError:
        alter_id = 0

    network = _normalise_network(s("net", "network", default="tcp"))
    security = _normalise_security(s("tls", "security", default="none"))
    header_type = s("type", "headerType", default="none")
    path = s("path", default="")
    host = s("host", default="")

    cfg = ProxyConfig(
        raw=raw,
        protocol="vmess",
        address=address,
        port=port,
        remark=s("ps", "remarks", "name"),
        uuid=uuid,
        alter_id=alter_id,
        vmess_security=s("scy", "security_method", default="auto") or "auto",
        network=network,
        security=security,
        sni=s("sni", "peer", default=""),
        host=host,
        path=path,
        alpn=s("alpn", default=""),
        fp=s("fp", "fingerprint", default=""),
        header_type=header_type,
        allow_insecure=s("allowInsecure", "skip-cert-verify", default="").lower() in _TRUE,
    )

    # در فرمت vmess کلاسیک، grpc نام سرویس را در path یا در type نگه می‌دارد
    if network == "grpc":
        cfg.service_name = s("serviceName", "path", default="")
        cfg.grpc_mode = "multi" if header_type == "multi" else "gun"
        cfg.header_type = ""
    elif network == "kcp":
        cfg.seed = s("seed", "path", default="")
    elif network == "quic":
        cfg.quic_security = s("quicSecurity", "host", default="none") or "none"
        cfg.quic_key = s("key", "path", default="")
    elif network == "xhttp":
        cfg.xhttp_mode = s("mode", default="auto") or "auto"

    if cfg.security == "tls" and not cfg.sni:
        cfg.sni = cfg.host or cfg.address
    return cfg


# ---------------------------------------------------------------------------
# vless:// و trojan:// و vmess فرمت URI
# ---------------------------------------------------------------------------

def _parse_uri_style(raw: str, protocol: str) -> ProxyConfig:
    parts = urlsplit(raw)
    if not parts.netloc:
        raise ParseError("ساختار لینک نامعتبر است")

    userinfo, _, hostport = parts.netloc.rpartition("@")
    if not userinfo:
        raise ParseError("بخش اعتبارنامه در لینک نیست")
    address, port = _split_hostport(hostport)

    params = parse_qs(parts.query, keep_blank_values=True)
    secret = unquote(userinfo)

    network = _normalise_network(_q(params, "type", "network", default="tcp"))
    security = _normalise_security(
        _q(params, "security", default="tls" if protocol == "trojan" else "none")
    )

    cfg = ProxyConfig(
        raw=raw,
        protocol=protocol,
        address=address,
        port=port,
        remark=unquote(parts.fragment or ""),
        network=network,
        security=security,
        sni=_q(params, "sni", "peer", "host"),
        host=_q(params, "host"),
        path=_q(params, "path", default="/") if network in ("ws", "h2", "httpupgrade", "xhttp") else _q(params, "path"),
        alpn=_q(params, "alpn"),
        fp=_q(params, "fp", "fingerprint"),
        header_type=_q(params, "headerType", default=""),
        service_name=_q(params, "serviceName"),
        grpc_mode=_q(params, "mode") if network == "grpc" else "",
        xhttp_mode=_q(params, "mode") if network == "xhttp" else "",
        seed=_q(params, "seed"),
        quic_security=_q(params, "quicSecurity"),
        quic_key=_q(params, "key"),
        public_key=_q(params, "pbk", "publicKey"),
        short_id=_q(params, "sid", "shortId"),
        spider_x=_q(params, "spx", "spiderX"),
        flow=_q(params, "flow"),
        allow_insecure=_q(params, "allowInsecure", "insecure", "skip-cert-verify").lower() in _TRUE,
    )

    if protocol in ("vless", "vmess"):
        cfg.uuid = secret
        if protocol == "vless":
            cfg.vless_encryption = _q(params, "encryption", default="none") or "none"
        else:
            cfg.vmess_security = _q(params, "encryption", default="auto") or "auto"
            try:
                cfg.alter_id = int(_q(params, "alterId", default="0") or 0)
            except ValueError:
                cfg.alter_id = 0
    else:  # trojan
        cfg.password = secret

    if not (cfg.uuid or cfg.password):
        raise ParseError("اعتبارنامه خالی است")

    # sni پیش‌فرض وقتی TLS هست ولی sni تصریح نشده
    if cfg.security in ("tls", "reality") and not cfg.sni:
        cfg.sni = cfg.host or cfg.address
    if cfg.security == "reality" and not cfg.public_key:
        raise ParseError("REALITY بدون publicKey (pbk) قابل استفاده نیست")

    return cfg


# ---------------------------------------------------------------------------
# ss://
# ---------------------------------------------------------------------------

def _parse_shadowsocks(raw: str) -> ProxyConfig:
    body = raw[len("ss://"):]
    remark = ""
    if "#" in body:
        body, _, frag = body.partition("#")
        remark = unquote(frag)

    query = ""
    if "?" in body:
        body, _, query = body.partition("?")
    params = parse_qs(query, keep_blank_values=True)

    if "@" in body:
        # ss://base64(method:password)@host:port  یا  ss://method:password@host:port
        userinfo, _, hostport = body.rpartition("@")
        address, port = _split_hostport(hostport)
        decoded = b64decode_loose(userinfo)
        creds = decoded if (decoded and ":" in decoded) else unquote(userinfo)
    else:
        # ss://base64(method:password@host:port)
        decoded = b64decode_loose(body)
        if not decoded or "@" not in decoded:
            raise ParseError("بدنه‌ی ss قابل دیکد نیست")
        creds, _, hostport = decoded.rpartition("@")
        address, port = _split_hostport(hostport)

    if ":" not in creds:
        raise ParseError("ساختار method:password در ss نامعتبر است")
    method, _, password = creds.partition(":")
    method = method.strip()
    if not method:
        raise ParseError("روش رمزنگاری ss خالی است")

    plugin = _q(params, "plugin")
    if plugin and not plugin.startswith("none"):
        raise ParseError(f"پلاگین shadowsocks پشتیبانی نمی‌شود: {plugin.split(';')[0]}")

    return ProxyConfig(
        raw=raw,
        protocol="shadowsocks",
        address=address,
        port=port,
        remark=remark,
        method=method,
        password=password,
    )


# ---------------------------------------------------------------------------
# socks:// و http://
# ---------------------------------------------------------------------------

def _parse_socks_http(raw: str, protocol: str) -> ProxyConfig:
    scheme, _, body = raw.partition("://")
    remark = ""
    if "#" in body:
        body, _, frag = body.partition("#")
        remark = unquote(frag)
    body = body.split("?", 1)[0]

    username = password = ""
    if "@" in body:
        userinfo, _, hostport = body.rpartition("@")
        decoded = b64decode_loose(userinfo)
        creds = decoded if (decoded and ":" in decoded) else unquote(userinfo)
        username, _, password = creds.partition(":")
    else:
        hostport = body

    address, port = _split_hostport(hostport)
    return ProxyConfig(
        raw=raw,
        protocol=protocol,
        address=address,
        port=port,
        remark=remark,
        username=username,
        password=password,
        security="tls" if scheme.lower() == "https" else "none",
    )


# ---------------------------------------------------------------------------
# نقطه‌ی ورود
# ---------------------------------------------------------------------------

_DISPATCH = {
    "vmess": _parse_vmess,
    "vless": lambda raw: _parse_uri_style(raw, "vless"),
    "trojan": lambda raw: _parse_uri_style(raw, "trojan"),
    "ss": _parse_shadowsocks,
    "socks": lambda raw: _parse_socks_http(raw, "socks"),
    "socks5": lambda raw: _parse_socks_http(raw, "socks"),
    "http": lambda raw: _parse_socks_http(raw, "http"),
    "https": lambda raw: _parse_socks_http(raw, "http"),
}

# در سطح ورودی، رشته‌ای که با http(s):// شروع می‌شود همیشه «لینک سابسکریپشن»
# است، نه کانفیگ پراکسی HTTP. پراکسی HTTP در سابسکریپشن‌ها عملاً دیده نمی‌شود،
# در حالی که اشتباه گرفتن این دو باعث می‌شد لینک سابسکریپشن هرگز دانلود نشود.
_SUBSCRIPTION_SCHEMES = {"http", "https"}


def is_proxy_link(text: str) -> bool:
    scheme = text.split("://", 1)[0].strip().lower() if "://" in text else ""
    if scheme in _SUBSCRIPTION_SCHEMES:
        return False
    return scheme in _DISPATCH or scheme in UNSUPPORTED_SCHEMES


def parse_link(raw: str, source: str = "", index: int = 0) -> ProxyConfig:
    """یک لینک را به ProxyConfig تبدیل می‌کند یا ParseError می‌اندازد."""
    raw = raw.strip()
    if "://" not in raw:
        raise ParseError("لینک بدون scheme است")

    scheme = raw.split("://", 1)[0].strip().lower()
    if scheme in UNSUPPORTED_SCHEMES:
        raise ParseError(UNSUPPORTED_SCHEMES[scheme])

    handler = _DISPATCH.get(scheme)
    if handler is None:
        raise ParseError(f"پروتکل ناشناخته: {scheme}")

    cfg = handler(raw)
    cfg.source = source
    cfg.index = index
    if not cfg.remark:
        cfg.remark = f"{cfg.protocol}-{cfg.address}:{cfg.port}"
    return cfg
