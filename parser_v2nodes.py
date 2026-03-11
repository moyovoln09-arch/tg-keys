import asyncio
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

import requests
from telethon import TelegramClient

# === Telegram credentials ===
api_id = 0  # TODO: set your api_id
api_hash = ""  # TODO: set your api_hash

CHANNEL = "@v2nodes"
OUTPUT_FILE = Path("valid_keys.txt")
VALIDATION_URL = "http://captive.apple.com/hotspot-detect.html"

# Optional proxy for URL validation, e.g. "socks5h://127.0.0.1:1080"
# IMPORTANT: this proxy must be поднят внешним клиентом (sing-box/v2ray/xray),
# иначе URL-проверка будет обычной проверкой вашего локального интернета.
URL_CHECK_PROXY = ""

KEY_PATTERN = re.compile(r"^(trojan|hysteria2)://\S+", re.IGNORECASE)


@dataclass
class ParsedKey:
    raw: str
    protocol: str
    host: str
    port: int


def month_delta(dt: datetime, months: int) -> datetime:
    """Approximate month delta with 30-day windows (good enough for filtering)."""
    return dt - timedelta(days=30 * months)


def clean_link(line: str) -> str | None:
    line = line.strip()
    m = KEY_PATTERN.match(line)
    if not m:
        return None

    # Cut away channel tags/comments after '#'
    line = line.split("#", 1)[0].strip()

    # Remove obvious trailing punctuation/noise
    line = re.sub(r"[\s\]\[\)\(,;]+$", "", line)
    return line


def extract_links(text: str) -> list[str]:
    links: list[str] = []
    for ln in text.splitlines():
        cleaned = clean_link(ln)
        if cleaned:
            links.append(cleaned)
    return links


def parse_host_port(link: str) -> ParsedKey | None:
    try:
        parts = urlsplit(link)
        protocol = parts.scheme.lower()
        if protocol not in {"trojan", "hysteria2"}:
            return None

        host = parts.hostname
        port = parts.port
        if not host or not port:
            return None

        return ParsedKey(raw=link, protocol=protocol, host=host, port=port)
    except Exception:
        return None


def tcp_check(host: str, port: int, timeout: float = 2.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def captive_check_via_proxy(proxy_url: str, timeout: float = 8.0) -> bool:
    """Check URL through a preconfigured local proxy (if provided by user)."""
    try:
        proxies = {"http": proxy_url, "https": proxy_url}
        resp = requests.get(VALIDATION_URL, timeout=timeout, proxies=proxies)
        return resp.status_code == 200 and "Success" in resp.text
    except requests.RequestException:
        return False


async def collect_keys() -> list[str]:
    if not api_id or not api_hash:
        raise ValueError("Set api_id and api_hash in script before running.")

    now = datetime.now()
    start_dt = month_delta(now, 6)
    end_dt = month_delta(now, 3)

    collected: list[str] = []

    async with TelegramClient("v2nodes_session", api_id, api_hash) as client:
        async for message in client.iter_messages(CHANNEL):
            if not message.date:
                continue

            msg_dt = message.date.replace(tzinfo=None)
            if msg_dt < start_dt:
                break
            if start_dt <= msg_dt <= end_dt:
                text = message.message or ""
                if text:
                    collected.extend(extract_links(text))

    # Deduplicate while preserving order
    seen = set()
    uniq = []
    for key in collected:
        if key not in seen:
            seen.add(key)
            uniq.append(key)
    return uniq


def validate_keys(keys: Iterable[str], proxy_url: str = "") -> list[str]:
    """
    Validation steps:
      1) TCP check against host:port from key.
      2) Optional URL check via user-supplied local proxy endpoint.

    By requirement, we keep keys that passed port check.
    URL check is informational and works only if `proxy_url` is set correctly.
    """
    valid: list[str] = []
    url_check_enabled = bool(proxy_url)

    if not url_check_enabled:
        print("[INFO] URL-check отключен: задайте URL_CHECK_PROXY, если хотите проверять через локальный proxy-клиент.")

    for link in keys:
        parsed = parse_host_port(link)
        if not parsed:
            continue

        step1 = tcp_check(parsed.host, parsed.port)
        if not step1:
            print(f"[DEAD] {parsed.host}:{parsed.port}")
            continue

        valid.append(parsed.raw)

        if url_check_enabled:
            step2 = captive_check_via_proxy(proxy_url)
            if step2:
                print(f"[OK]   {parsed.host}:{parsed.port} | URL OK")
            else:
                print(f"[OK]   {parsed.host}:{parsed.port} | URL FAIL")
        else:
            print(f"[OK]   {parsed.host}:{parsed.port} | URL SKIP")

    return valid


async def main() -> None:
    keys = await collect_keys()
    print(f"Найдено ключей: {len(keys)}")

    answer = input(f"Найдено {len(keys)} ключей. Начать проверку? (y/n): ").strip().lower()
    if answer != "y":
        print("Проверка отменена пользователем.")
        return

    valid = validate_keys(keys, proxy_url=URL_CHECK_PROXY.strip())
    OUTPUT_FILE.write_text("\n".join(valid), encoding="utf-8")
    print(f"Готово. Ключей с открытым портом: {len(valid)}")
    print(f"Сохранено в: {OUTPUT_FILE.resolve()}")


if __name__ == "__main__":
    asyncio.run(main())
