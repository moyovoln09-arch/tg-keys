import asyncio
import json
import random
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from telethon import TelegramClient

# === Telegram credentials ===
api_id = 0  # TODO: set your api_id
api_hash = ""  # TODO: set your api_hash

CHANNEL = "@v2nodes"
OUTPUT_FILE = Path("valid_keys.txt")
VALIDATION_URL = "http://captive.apple.com/hotspot-detect.html"
SING_BOX_BIN = "sing-box"
SINGBOX_START_TIMEOUT_SEC = 4.0

KEY_PATTERN = re.compile(r"^(trojan|hysteria2)://\S+", re.IGNORECASE)


@dataclass
class ParsedKey:
    raw: str
    protocol: str
    host: str
    port: int
    user: str
    params: dict[str, list[str]]


def month_delta(dt: datetime, months: int) -> datetime:
    return dt - timedelta(days=30 * months)


def clean_link(line: str) -> str | None:
    line = line.strip()
    if not KEY_PATTERN.match(line):
        return None
    line = line.split("#", 1)[0].strip()
    line = re.sub(r"[\s\]\[\)\(,;]+$", "", line)
    return line


def extract_links(text: str) -> list[str]:
    return [cleaned for ln in text.splitlines() if (cleaned := clean_link(ln))]


def parse_key(link: str) -> ParsedKey | None:
    try:
        parts = urlsplit(link)
        protocol = parts.scheme.lower()
        if protocol not in {"trojan", "hysteria2"}:
            return None
        host = parts.hostname
        port = parts.port
        user = unquote(parts.username or "")
        if not host or not port or not user:
            return None
        return ParsedKey(
            raw=link,
            protocol=protocol,
            host=host,
            port=port,
            user=user,
            params=parse_qs(parts.query),
        )
    except Exception:
        return None


def _pick_local_port() -> int:
    return random.randint(20000, 50000)


def build_outbound(parsed: ParsedKey) -> dict:
    insecure = parsed.params.get("insecure", ["0"])[0] in {"1", "true"}
    sni = parsed.params.get("sni", [""])[0] or parsed.params.get("peer", [""])[0]

    if parsed.protocol == "trojan":
        tls_cfg = {"enabled": True, "insecure": insecure}
        if sni:
            tls_cfg["server_name"] = sni
        return {
            "type": "trojan",
            "tag": "proxy",
            "server": parsed.host,
            "server_port": parsed.port,
            "password": parsed.user,
            "tls": tls_cfg,
        }

    obfs = parsed.params.get("obfs", [""])[0]
    outbound = {
        "type": "hysteria2",
        "tag": "proxy",
        "server": parsed.host,
        "server_port": parsed.port,
        "password": parsed.user,
        "tls": {"enabled": True, "insecure": insecure},
    }
    if sni:
        outbound["tls"]["server_name"] = sni
    if obfs == "salamander":
        obfs_password = parsed.params.get("obfs-password", [""])[0]
        if obfs_password:
            outbound["obfs"] = {"type": "salamander", "password": obfs_password}
    return outbound


def build_config(parsed: ParsedKey, socks_port: int) -> dict:
    return {
        "log": {"level": "error"},
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": socks_port,
            }
        ],
        "outbounds": [build_outbound(parsed)],
        "route": {"final": "proxy"},
    }


def check_url_via_singbox(parsed: ParsedKey) -> bool:
    socks_port = _pick_local_port()
    config = build_config(parsed, socks_port)

    with tempfile.TemporaryDirectory(prefix="sb-check-") as td:
        config_path = Path(td) / "config.json"
        config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")

        proc = subprocess.Popen(
            [SING_BOX_BIN, "run", "-c", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            start_at = time.time()
            while time.time() - start_at < SINGBOX_START_TIMEOUT_SEC:
                if proc.poll() is not None:
                    return False
                time.sleep(0.15)

            curl_cmd = [
                "curl",
                "--silent",
                "--show-error",
                "--max-time",
                "12",
                "--proxy",
                f"socks5h://127.0.0.1:{socks_port}",
                VALIDATION_URL,
            ]
            result = subprocess.run(curl_cmd, capture_output=True, text=True)
            return result.returncode == 0 and "Success" in result.stdout
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()


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
                collected.extend(extract_links(message.message or ""))

    seen = set()
    uniq = []
    for key in collected:
        if key not in seen:
            seen.add(key)
            uniq.append(key)
    return uniq


def validate_keys(keys: list[str]) -> list[str]:
    valid: list[str] = []
    for link in keys:
        parsed = parse_key(link)
        if not parsed:
            continue

        ok = check_url_via_singbox(parsed)
        if ok:
            valid.append(link)
            print(f"[OK]   {parsed.host}:{parsed.port}")
        else:
            print(f"[DEAD] {parsed.host}:{parsed.port}")

    return valid


async def main() -> None:
    keys = await collect_keys()
    print(f"Найдено ключей: {len(keys)}")

    answer = input(f"Найдено {len(keys)} ключей. Начать проверку? (y/n): ").strip().lower()
    if answer != "y":
        print("Проверка отменена пользователем.")
        return

    valid = validate_keys(keys)
    OUTPUT_FILE.write_text("\n".join(valid), encoding="utf-8")
    print(f"Готово. Валидных ключей: {len(valid)}")
    print(f"Сохранено в: {OUTPUT_FILE.resolve()}")


if __name__ == "__main__":
    asyncio.run(main())
