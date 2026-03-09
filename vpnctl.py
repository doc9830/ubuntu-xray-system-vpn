#!/usr/bin/env python3
"""System-wide Xray VPN controller for Ubuntu.

This tool manages:
- VPN on/off/status lifecycle
- Safe policy routing with rollback
- Profile management and link import (vless/vmess/reality)
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import ipaddress
import json
import logging
import os
import random
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

APP_NAME = "xray-system-vpn"
APP_ROOT = Path(__file__).resolve().parent
DATA_DIR = APP_ROOT / "data"
PROFILES_DIR = DATA_DIR / "profiles"
BACKUPS_DIR = APP_ROOT / "backups"
SETTINGS_FILE = DATA_DIR / "client-settings.json"
RUNTIME_DIR = Path("/tmp/xray-system-vpn")
STATE_FILE = RUNTIME_DIR / "state.json"
LOG_FILE = RUNTIME_DIR / "vpn-client.log"
RUNTIME_CONFIG_FILE = RUNTIME_DIR / "runtime-config.json"

DEFAULT_TABLE_ID = 24910
RULE_PREF_SERVER_BYPASS_BASE = 17900
RULE_PREF_DNS_BYPASS_BASE = 17940
RULE_PREF_MAIN_SPECIFIC = 18000
RULE_PREF_VPN_DEFAULT = 18010
RULE_PREF_SPLIT_BASE = 18100
BACKUP_KEEP_COUNT = 4
DNS_TRACKED_PATHS = [
    Path("/etc/resolv.conf"),
    Path("/etc/systemd/resolved.conf"),
]

CONNECTIVITY_CACHE: Dict[str, Any] = {
    "ts": 0.0,
    "ok": False,
    "detail": "pending",
}


class VPNError(RuntimeError):
    """Expected operational error that should be shown to user."""


I18N = {
    "ru": {
        "app_title": "Xray System VPN",
        "app_subtitle": "Системный VPN-клиент для Ubuntu (TUN + policy routing)",
        "vpn_status": "Состояние VPN",
        "status_on": "ВКЛ",
        "status_off": "ВЫКЛ",
        "status_degraded": "ПРОБЛЕМА",
        "active_profile": "Активный профиль",
        "profile_state": "Состояние профиля",
        "profile_ok": "OK",
        "profile_missing": "Файл не найден",
        "profile_invalid_json": "Некорректный JSON",
        "profile_invalid_structure": "Некорректная структура",
        "connection_test": "Тест подключения",
        "conn_ok": "РАБОТАЕТ",
        "conn_fail": "НЕ РАБОТАЕТ",
        "conn_checking": "ПРОВЕРКА",
        "language": "Язык",
        "menu_title": "Меню",
        "menu_on": "Включить VPN",
        "menu_off": "Выключить VPN",
        "menu_status": "Показать детальный статус",
        "menu_import_link": "Импорт ссылки",
        "menu_select_profile": "Выбрать профиль из списка",
        "menu_switch_language": "Сменить язык",
        "menu_exit": "Выход",
        "menu_back": "Назад",
        "select_prompt": "Выбор",
        "error": "Ошибка",
        "press_enter": "Нажмите Enter для продолжения...",
        "import_name_prompt": "Имя профиля (опционально): ",
        "import_link_prompt": "VLESS/VMess/Reality ссылка: ",
        "import_cancel_hint": "Введите 0 для отмены",
        "profile_select_title": "Выбор активного профиля",
        "profile_select_current": "Текущий",
        "profile_select_cancel": "0. Отмена",
        "profile_select_prompt": "Номер профиля",
        "profile_select_saved": "Активный профиль переключен",
        "no_profiles": "Профили не найдены",
        "language_title": "Выбор языка",
        "language_saved": "Язык интерфейса переключен",
        "invalid_choice": "Некорректный выбор",
        "vpn_enabled": "VPN включен",
        "vpn_disabled": "VPN выключен",
        "import_done": "Профиль импортирован",
        "profiles_title": "Профили",
        "startup_title": "Инициализация XRAY SYSTEM VPN",
        "startup_wait": "Нажмите Enter для открытия меню...",
        "check_dirs": "Проверка каталогов проекта",
        "check_profiles": "Проверка профилей Xray",
        "check_ifaces": "Проверка сетевых интерфейсов",
        "check_xray": "Проверка Xray",
        "check_connectivity": "Быстрый тест сети",
        "check_ok": "OK",
        "check_warn": "WARN",
        "check_fail": "FAIL",
        "ifaces_found": "Найдено интерфейсов",
        "xray_found": "Найден Xray",
        "xray_missing": "Xray не найден",
        "xray_install_ask": "Установить Xray автоматически сейчас? [y/N]: ",
        "xray_install_step": "Запуск установки Xray",
        "xray_install_ok": "Установка Xray завершена",
        "xray_install_fail": "Не удалось установить Xray автоматически",
        "startup_done": "Проверки завершены",
        "backup_prune_done": "Старые бэкапы очищены",
        "root_required_install": "Для автоустановки нужны права root (запустите через sudo)",
    },
    "en": {
        "app_title": "Xray System VPN",
        "app_subtitle": "System VPN client for Ubuntu (TUN + policy routing)",
        "vpn_status": "VPN status",
        "status_on": "ON",
        "status_off": "OFF",
        "status_degraded": "DEGRADED",
        "active_profile": "Active profile",
        "profile_state": "Profile state",
        "profile_ok": "OK",
        "profile_missing": "File missing",
        "profile_invalid_json": "Invalid JSON",
        "profile_invalid_structure": "Invalid structure",
        "connection_test": "Connection test",
        "conn_ok": "WORKING",
        "conn_fail": "FAILED",
        "conn_checking": "CHECKING",
        "language": "Language",
        "menu_title": "Menu",
        "menu_on": "VPN ON",
        "menu_off": "VPN OFF",
        "menu_status": "Show detailed status",
        "menu_import_link": "Import link",
        "menu_select_profile": "Select profile from list",
        "menu_switch_language": "Switch language",
        "menu_exit": "Exit",
        "menu_back": "Back",
        "select_prompt": "Select",
        "error": "Error",
        "press_enter": "Press Enter to continue...",
        "import_name_prompt": "Profile name (optional): ",
        "import_link_prompt": "VLESS/VMess/Reality link: ",
        "import_cancel_hint": "Type 0 to cancel",
        "profile_select_title": "Select active profile",
        "profile_select_current": "Current",
        "profile_select_cancel": "0. Cancel",
        "profile_select_prompt": "Profile number",
        "profile_select_saved": "Active profile switched",
        "no_profiles": "No profiles found",
        "language_title": "Select language",
        "language_saved": "UI language switched",
        "invalid_choice": "Invalid choice",
        "vpn_enabled": "VPN enabled",
        "vpn_disabled": "VPN disabled",
        "import_done": "Profile imported",
        "profiles_title": "Profiles",
        "startup_title": "XRAY SYSTEM VPN bootstrap checks",
        "startup_wait": "Press Enter to open menu...",
        "check_dirs": "Project directories check",
        "check_profiles": "Xray profiles check",
        "check_ifaces": "Network interfaces check",
        "check_xray": "Xray check",
        "check_connectivity": "Quick network check",
        "check_ok": "OK",
        "check_warn": "WARN",
        "check_fail": "FAIL",
        "ifaces_found": "Interfaces found",
        "xray_found": "Xray found",
        "xray_missing": "Xray not found",
        "xray_install_ask": "Install Xray automatically now? [y/N]: ",
        "xray_install_step": "Running Xray installation",
        "xray_install_ok": "Xray installation completed",
        "xray_install_fail": "Could not install Xray automatically",
        "startup_done": "Checks completed",
        "backup_prune_done": "Old backups pruned",
        "root_required_install": "Root privileges are required for auto-install (run via sudo)",
    },
}


def normalize_language(value: str) -> str:
    val = (value or "").strip().lower()
    return "en" if val.startswith("en") else "ru"


def tr(settings: Optional[Dict[str, Any]], key: str, **kwargs: Any) -> str:
    lang = normalize_language(str((settings or {}).get("language", "ru")))
    text = I18N.get(lang, I18N["ru"]).get(key, I18N["en"].get(key, key))
    return text.format(**kwargs) if kwargs else text


def paint(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def setup_logging() -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.INFO)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.ERROR)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[file_handler, stream_handler],
    )


def run_cmd(
    cmd: List[str],
    check: bool = True,
    capture: bool = True,
    timeout: Optional[float] = None,
) -> subprocess.CompletedProcess:
    logging.debug("Running command: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, text=True, capture_output=capture, timeout=timeout)
    except subprocess.TimeoutExpired:
        if check:
            raise VPNError(f"Command timeout ({' '.join(cmd)})")
        return subprocess.CompletedProcess(cmd, 124, "", "timeout")
    if check and result.returncode != 0:
        stderr = result.stderr.strip() if result.stderr else ""
        stdout = result.stdout.strip() if result.stdout else ""
        raise VPNError(f"Command failed ({' '.join(cmd)}): {stderr or stdout or 'unknown error'}")
    return result


def run_ip(
    args: List[str],
    family: Optional[str] = None,
    check: bool = True,
    timeout: Optional[float] = None,
) -> subprocess.CompletedProcess:
    cmd = ["ip"]
    if family:
        cmd.append(family)
    cmd.extend(args)
    return run_cmd(cmd, check=check, timeout=timeout)


def require_root() -> None:
    if os.geteuid() != 0:
        raise VPNError("This command must be run as root (use sudo).")


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    tmp.replace(path)


def default_settings() -> Dict[str, Any]:
    return {
        "active_profile": "default.json",
        "language": "ru",
        "route_mode": "full",  # full | split
        "split_interfaces": [],
        "tun_name": "xray0",
        "tun_mtu": 1500,
        "table_id": DEFAULT_TABLE_ID,
        "xray_bin": "",
    }


def default_profile() -> Dict[str, Any]:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "tun-in",
                "protocol": "tun",
                "settings": {
                    "name": "xray0",
                    "MTU": 1500,
                    "userLevel": 0,
                },
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "example.com",
                            "port": 443,
                            "users": [
                                {
                                    "id": "00000000-0000-0000-0000-000000000000",
                                    "encryption": "none",
                                    "flow": "",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": "example.com",
                    },
                },
            },
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "domain": ["geosite:private"], "outboundTag": "direct"},
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
            ],
        },
    }


def ensure_layout() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)

    if not SETTINGS_FILE.exists():
        save_json(SETTINGS_FILE, default_settings())

    default_profile_path = PROFILES_DIR / "default.json"
    if not default_profile_path.exists():
        save_json(default_profile_path, default_profile())


def load_settings() -> Dict[str, Any]:
    settings = default_settings()
    stored = load_json(SETTINGS_FILE, default={})
    if isinstance(stored, dict):
        settings.update(stored)
    return settings


def save_settings(settings: Dict[str, Any]) -> None:
    save_json(SETTINGS_FILE, settings)


def clear_terminal() -> None:
    if sys.stdout.isatty():
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()


def print_check(settings: Dict[str, Any], label_key: str, level: str, detail: str = "") -> None:
    tag_key = "check_ok" if level == "ok" else "check_warn" if level == "warn" else "check_fail"
    tag_color = "32" if level == "ok" else "33" if level == "warn" else "31"
    tag = paint(tr(settings, tag_key), tag_color)
    suffix = f" :: {detail}" if detail else ""
    print(f"[{tag}] {tr(settings, label_key)}{suffix}")


def profile_state_key(profile_file: Path) -> str:
    if not profile_file.exists():
        return "profile_missing"
    try:
        data = load_json(profile_file, default=None)
    except Exception:
        return "profile_invalid_json"
    if not isinstance(data, dict):
        return "profile_invalid_structure"
    if not isinstance(data.get("inbounds"), list):
        return "profile_invalid_structure"
    outbounds = data.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds:
        return "profile_invalid_structure"
    return "profile_ok"


def connectivity_test(timeout: float = 1.2) -> Tuple[bool, str]:
    targets = [("1.1.1.1", 443), ("8.8.8.8", 443)]
    tcp_ok = False
    tcp_target = "-"
    for host, port in targets:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                tcp_ok = True
                tcp_target = f"{host}:{port}"
                break
        except OSError:
            continue

    dns_ok, dns_detail = dns_resolution_test(timeout=max(0.35, timeout))

    return tcp_ok and dns_ok, f"tcp={tcp_target if tcp_ok else 'fail'},dns={'ok' if dns_ok else 'fail'}:{dns_detail}"


def build_dns_query_packet(domain: str, txid: int) -> bytes:
    labels = [x for x in domain.strip(".").split(".") if x]
    question = b"".join(bytes([len(lbl)]) + lbl.encode("ascii", errors="ignore") for lbl in labels) + b"\x00"
    qtype = b"\x00\x01"  # A
    qclass = b"\x00\x01"  # IN
    header = (
        txid.to_bytes(2, "big")
        + b"\x01\x00"  # recursion desired
        + b"\x00\x01"  # QDCOUNT
        + b"\x00\x00"  # ANCOUNT
        + b"\x00\x00"  # NSCOUNT
        + b"\x00\x00"  # ARCOUNT
    )
    return header + question + qtype + qclass


def parse_dns_response_ok(packet: bytes, txid: int) -> bool:
    if len(packet) < 12:
        return False
    resp_id = int.from_bytes(packet[0:2], "big")
    if resp_id != txid:
        return False
    flags = int.from_bytes(packet[2:4], "big")
    rcode = flags & 0x000F
    ancount = int.from_bytes(packet[6:8], "big")
    if rcode != 0:
        return False
    return ancount > 0


def dns_udp_query(server_ip: str, domain: str, timeout: float) -> Tuple[bool, str]:
    txid = random.randint(1, 65535)
    payload = build_dns_query_packet(domain, txid)
    family = socket.AF_INET6 if ":" in server_ip else socket.AF_INET
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
    except OSError as exc:
        return False, f"{server_ip}:sock-{exc.__class__.__name__}"
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (server_ip, 53))
        data, _ = sock.recvfrom(2048)
        return parse_dns_response_ok(data, txid), server_ip
    except OSError as exc:
        return False, f"{server_ip}:{exc.__class__.__name__}"
    finally:
        sock.close()


def dns_resolution_test(timeout: float = 1.2) -> Tuple[bool, str]:
    # Primary path: ask system resolver first (closest to real user behavior).
    try:
        socket.getaddrinfo("example.com", 443)
        return True, "system-resolver"
    except OSError:
        pass

    getent = run_cmd(["getent", "hosts", "example.com"], check=False, timeout=timeout)
    if getent.returncode == 0 and bool((getent.stdout or "").strip()):
        return True, "getent"

    servers = detect_dns_servers()
    domains = ["example.com", "cloudflare.com"]

    if not servers:
        return False, "no-dns-servers"

    failures: List[str] = []
    for server in servers:
        for domain in domains:
            ok, detail = dns_udp_query(server, domain, timeout=timeout)
            if ok:
                return True, f"{detail}:{domain}"
            failures.append(detail)

    uniq = sorted(set(failures))
    short = ",".join(uniq[:3]) if uniq else "query-failed"
    return False, short


def get_cached_connectivity(
    force: bool = False,
    max_age_sec: float = 8.0,
    timeout: float = 0.35,
) -> Tuple[bool, str]:
    now = time.monotonic()
    ts = float(CONNECTIVITY_CACHE.get("ts", 0.0))
    if not force and ts and (now - ts) <= max_age_sec:
        return bool(CONNECTIVITY_CACHE.get("ok", False)), str(CONNECTIVITY_CACHE.get("detail", "pending"))

    ok, detail = connectivity_test(timeout=timeout)
    CONNECTIVITY_CACHE["ts"] = now
    CONNECTIVITY_CACHE["ok"] = ok
    CONNECTIVITY_CACHE["detail"] = detail
    return ok, detail


def reset_connectivity_cache() -> None:
    CONNECTIVITY_CACHE["ts"] = 0.0


def get_cached_connectivity_view(settings: Dict[str, Any]) -> Tuple[str, str]:
    ts = float(CONNECTIVITY_CACHE.get("ts", 0.0))
    if not ts:
        return paint_status_label(settings, "conn_checking"), "pending"
    ok = bool(CONNECTIVITY_CACHE.get("ok", False))
    detail = str(CONNECTIVITY_CACHE.get("detail", "pending"))
    return paint_status_label(settings, "conn_ok" if ok else "conn_fail"), detail


def status_key_and_state(settings: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    state = load_json(STATE_FILE, default=None)
    if not isinstance(state, dict):
        return "status_off", {}

    pid = state.get("pid")
    tun_name = state.get("tun_name", settings.get("tun_name", "xray0"))
    running = is_running(pid)
    tun_up = run_cmd(["ip", "link", "show", tun_name], check=False).returncode == 0
    if running and tun_up:
        return "status_on", state
    return "status_degraded", state


def paint_status_label(settings: Dict[str, Any], key: str) -> str:
    text = tr(settings, key)
    if key == "status_on":
        return paint(text, "32")
    if key in {"status_degraded", "conn_fail"}:
        return paint(text, "33")
    if key == "status_off":
        return paint(text, "31")
    if key == "conn_ok":
        return paint(text, "32")
    if key == "conn_checking":
        return paint(text, "36")
    return text


def list_profile_names() -> List[str]:
    if not PROFILES_DIR.exists():
        return []
    return [p.name for p in sorted(PROFILES_DIR.glob("*.json"))]


def prune_snapshot_backups(keep: int = BACKUP_KEEP_COUNT) -> None:
    if keep < 1 or not BACKUPS_DIR.exists():
        return
    dirs = [p for p in BACKUPS_DIR.iterdir() if p.is_dir()]
    dirs.sort(key=lambda p: p.name, reverse=True)
    for old in dirs[keep:]:
        try:
            shutil.rmtree(old)
        except OSError as exc:
            logging.warning("Could not remove old backup dir %s: %s", old, exc)


def prune_sibling_backups_for_file(file_path: Path, keep: int = BACKUP_KEEP_COUNT) -> None:
    if keep < 1:
        return
    parent = file_path.parent
    if not parent.exists():
        return

    prefix = f"{file_path.name}.xsysvpn-"
    by_stamp: Dict[str, List[Path]] = {}
    for p in parent.iterdir():
        name = p.name
        if not name.startswith(prefix):
            continue
        stamp = name[len(prefix) :].split(".", 1)[0]
        by_stamp.setdefault(stamp, []).append(p)

    ordered = sorted(by_stamp.keys(), reverse=True)
    for stamp in ordered[keep:]:
        for p in by_stamp.get(stamp, []):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass


def prune_backup_storage(settings: Dict[str, Any], current_profile: Path, keep: int = BACKUP_KEEP_COUNT) -> None:
    prune_snapshot_backups(keep=keep)
    tracked = list(DNS_TRACKED_PATHS)
    tracked.append(SETTINGS_FILE)
    tracked.append(current_profile)
    tracked.extend(PROFILES_DIR.glob("*.json"))
    for path in tracked:
        prune_sibling_backups_for_file(path, keep=keep)
    logging.info("%s (keep=%s)", tr(settings, "backup_prune_done"), keep)


def try_install_xray(settings: Dict[str, Any]) -> bool:
    if os.geteuid() != 0:
        print_check(settings, "check_xray", "fail", tr(settings, "root_required_install"))
        return False
    print_check(settings, "check_xray", "warn", tr(settings, "xray_install_step"))
    steps = [
        ["apt-get", "update"],
        ["apt-get", "install", "-y", "xray"],
    ]
    alt_steps = [["apt-get", "install", "-y", "xray-core"]]

    for cmd in steps:
        if subprocess.run(cmd, text=True).returncode != 0:
            break
    else:
        try:
            xray_path = find_xray_binary(settings)
            settings["xray_bin"] = xray_path
            save_settings(settings)
            print_check(settings, "check_xray", "ok", f"{tr(settings, 'xray_install_ok')}: {xray_path}")
            return True
        except VPNError:
            pass

    for cmd in alt_steps:
        subprocess.run(cmd, text=True)

    try:
        xray_path = find_xray_binary(settings)
        settings["xray_bin"] = xray_path
        save_settings(settings)
        print_check(settings, "check_xray", "ok", f"{tr(settings, 'xray_install_ok')}: {xray_path}")
        return True
    except VPNError:
        print_check(settings, "check_xray", "fail", tr(settings, "xray_install_fail"))
        return False


def run_startup_screen() -> None:
    settings = load_settings()
    clear_terminal()
    print(paint("+------------------------------------------------------------------+", "32"))
    print(paint(f"| {tr(settings, 'startup_title'):<64}|", "32"))
    print(paint("+------------------------------------------------------------------+", "32"))

    try:
        ensure_layout()
        print_check(settings, "check_dirs", "ok", str(DATA_DIR))
    except Exception as exc:
        print_check(settings, "check_dirs", "fail", str(exc))

    profiles = list_profile_names()
    if profiles:
        print_check(settings, "check_profiles", "ok", f"{len(profiles)}")
    else:
        print_check(settings, "check_profiles", "fail", tr(settings, "no_profiles"))

    interfaces = list_interfaces()
    if interfaces:
        print_check(settings, "check_ifaces", "ok", f"{tr(settings, 'ifaces_found')}: {len(interfaces)}")
        for idx, iface in enumerate(interfaces, 1):
            print(f"  {idx}. {iface}")
    else:
        print_check(settings, "check_ifaces", "warn", tr(settings, "ifaces_found") + ": 0")

    xray_ok = True
    try:
        xray_path = find_xray_binary(settings)
        print_check(settings, "check_xray", "ok", f"{tr(settings, 'xray_found')}: {xray_path}")
    except VPNError:
        xray_ok = False
        print_check(settings, "check_xray", "warn", tr(settings, "xray_missing"))
        if sys.stdin.isatty():
            answer = input(tr(settings, "xray_install_ask")).strip().lower()
            if answer in {"y", "yes", "д", "да"}:
                xray_ok = try_install_xray(settings)

    conn_ok, conn_detail = get_cached_connectivity(force=True, max_age_sec=0.0, timeout=1.2)
    print_check(settings, "check_connectivity", "ok" if conn_ok else "warn", conn_detail)

    print(paint("-" * 66, "32"))
    done_level = "ok" if xray_ok else "warn"
    print_check(settings, "startup_done", done_level)
    if sys.stdin.isatty():
        input(tr(settings, "startup_wait"))


def detect_active_uplink(tun_name: str) -> Dict[str, Any]:
    routes = json.loads(run_cmd(["ip", "-j", "route", "show", "default"]).stdout or "[]")
    if not routes:
        raise VPNError("Default route not found. Network seems down.")

    # Prefer route with lowest metric that is not the VPN TUN interface.
    candidates = [r for r in routes if r.get("dev") and r.get("dev") != tun_name]
    if not candidates:
        raise VPNError("Could not determine active uplink interface.")

    candidates.sort(key=lambda r: int(r.get("metric", 0)))
    chosen = candidates[0]
    return {
        "dev": chosen.get("dev"),
        "gateway": chosen.get("gateway"),
        "src": chosen.get("prefsrc"),
    }


def get_interface_source_ip(dev: str) -> Optional[str]:
    data = json.loads(run_cmd(["ip", "-j", "addr", "show", "dev", dev]).stdout or "[]")
    if not data:
        return None
    for addr in data[0].get("addr_info", []):
        if addr.get("family") == "inet" and addr.get("scope") in {"global", "site"}:
            return addr.get("local")
    return None


def detect_dns_servers() -> List[str]:
    dns_ips: List[str] = []
    resolv = Path("/etc/resolv.conf")
    if not resolv.exists():
        return dns_ips

    for line in resolv.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2 or parts[0] != "nameserver":
            continue
        ip = parts[1]
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ip not in dns_ips:
            dns_ips.append(ip)
    return dns_ips


def list_interfaces() -> List[str]:
    out = run_cmd(["ip", "-o", "link", "show"], check=False).stdout or ""
    interfaces: List[str] = []
    for line in out.splitlines():
        parts = line.split(":", 2)
        if len(parts) < 2:
            continue
        name = parts[1].strip()
        if name:
            interfaces.append(name)
    return interfaces


def find_xray_binary(settings: Dict[str, Any]) -> str:
    configured = settings.get("xray_bin", "").strip()
    candidates: List[str] = []
    if configured:
        candidates.append(configured)

    which = run_cmd(["bash", "-lc", "command -v xray"], check=False)
    if which.returncode == 0 and which.stdout.strip():
        candidates.append(which.stdout.strip())

    candidates.extend(["/usr/local/bin/xray", "/usr/bin/xray", "/usr/sbin/xray"])

    for candidate in candidates:
        path = Path(candidate)
        if path.exists() and os.access(path, os.X_OK):
            return str(path)

    raise VPNError(f"Xray binary not found. Install xray-core or set xray_bin in {SETTINGS_FILE}")


def ensure_xray_capabilities(xray_bin: str) -> None:
    # Root can still run Xray without setcap, but setcap improves compatibility.
    cap_out = run_cmd(["getcap", xray_bin], check=False)
    if "cap_net_admin" in (cap_out.stdout or ""):
        return

    setcap = run_cmd(["bash", "-lc", "command -v setcap"], check=False)
    if setcap.returncode != 0:
        logging.warning("setcap is not available. Continuing as root.")
        return

    run_cmd(["setcap", "cap_net_admin,cap_net_bind_service+ep", xray_bin], check=False)
    cap_out2 = run_cmd(["getcap", xray_bin], check=False)
    if "cap_net_admin" not in (cap_out2.stdout or ""):
        logging.warning("Could not set cap_net_admin on xray binary. Continuing as root.")


def profile_path(profile: Optional[str], settings: Dict[str, Any]) -> Path:
    name = profile or settings.get("active_profile", "default.json")
    p = Path(name)
    if p.is_absolute() and p.exists():
        return p

    if not name.endswith(".json"):
        name = f"{name}.json"

    p = PROFILES_DIR / name
    if not p.exists():
        raise VPNError(f"Profile not found: {p}")
    return p


def slugify_profile_name(name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name.strip())
    if not cleaned:
        cleaned = "profile"
    if not cleaned.endswith(".json"):
        cleaned += ".json"
    return cleaned


def parse_list_param(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


def is_running(pid: Optional[int]) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def backup_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def sanitize_path_for_backup(path: Path) -> str:
    return str(path).strip("/").replace("/", "__").replace(":", "_")


def copy_file_to_backup(file_path: Path, timestamp: str, backup_root: Path) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "path": str(file_path),
        "exists": file_path.exists() or file_path.is_symlink(),
        "is_symlink": file_path.is_symlink(),
        "timestamp": timestamp,
    }
    if not entry["exists"]:
        return entry

    backup_root.mkdir(parents=True, exist_ok=True)
    sibling_backup = file_path.parent / f"{file_path.name}.xsysvpn-{timestamp}.bak"
    snapshot_name = f"{sanitize_path_for_backup(file_path)}.bak"
    snapshot_backup = backup_root / snapshot_name

    if file_path.is_symlink():
        link_target = os.readlink(file_path)
        entry["link_target"] = link_target
        sibling_link_meta = file_path.parent / f"{file_path.name}.xsysvpn-{timestamp}.link"
        sibling_link_meta.write_text(link_target + "\n", encoding="utf-8")
        entry["sibling_backup"] = str(sibling_link_meta)

        snapshot_link_meta = backup_root / f"{sanitize_path_for_backup(file_path)}.link"
        snapshot_link_meta.write_text(link_target + "\n", encoding="utf-8")
        entry["snapshot_backup"] = str(snapshot_link_meta)

        if file_path.exists():
            shutil.copy2(file_path, sibling_backup)
            shutil.copy2(file_path, snapshot_backup)
            entry["sibling_data_backup"] = str(sibling_backup)
            entry["snapshot_data_backup"] = str(snapshot_backup)
        return entry

    shutil.copy2(file_path, sibling_backup)
    shutil.copy2(file_path, snapshot_backup)
    entry["sibling_backup"] = str(sibling_backup)
    entry["snapshot_backup"] = str(snapshot_backup)
    return entry


def restore_file_from_backup(entry: Dict[str, Any]) -> None:
    if not entry.get("exists"):
        return

    dst = Path(entry["path"])
    dst.parent.mkdir(parents=True, exist_ok=True)

    if entry.get("is_symlink"):
        target = entry.get("link_target")
        if not target:
            return
        if dst.exists() or dst.is_symlink():
            dst.unlink(missing_ok=True)
        os.symlink(target, dst)
        return

    source_candidates = [
        Path(entry["snapshot_backup"]) if entry.get("snapshot_backup") else None,
        Path(entry["sibling_backup"]) if entry.get("sibling_backup") else None,
    ]
    for source in source_candidates:
        if source and source.exists():
            shutil.copy2(source, dst)
            return


def save_backup_snapshot(timestamp: str) -> Path:
    out_dir = BACKUPS_DIR / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)

    # Backup current routing/rule/address state before any mutation.
    (out_dir / "ip-route-main.txt").write_text(run_cmd(["ip", "route", "show", "table", "main"]).stdout, encoding="utf-8")
    (out_dir / "ip-rule.txt").write_text(run_cmd(["ip", "rule", "show"]).stdout, encoding="utf-8")
    (out_dir / "ip-addr.txt").write_text(run_cmd(["ip", "addr", "show"]).stdout, encoding="utf-8")

    return out_dir


def backup_dns_settings(timestamp: str, backup_dir: Path) -> List[Dict[str, Any]]:
    dns_backup_dir = backup_dir / "dns"
    dns_entries: List[Dict[str, Any]] = []
    for dns_file in DNS_TRACKED_PATHS:
        dns_entries.append(copy_file_to_backup(dns_file, timestamp, dns_backup_dir))
    return dns_entries


def restore_dns_settings(dns_entries: List[Dict[str, Any]]) -> None:
    for entry in dns_entries:
        try:
            restore_file_from_backup(entry)
        except Exception as exc:
            logging.warning("DNS restore failed for %s: %s", entry.get("path"), exc)


def backup_local_config_files(timestamp: str, backup_dir: Path, files: List[Path]) -> List[Dict[str, Any]]:
    cfg_backup_dir = backup_dir / "configs"
    entries: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for file_path in files:
        file_key = str(file_path.resolve()) if file_path.exists() else str(file_path)
        if file_key in seen:
            continue
        seen.add(file_key)
        entries.append(copy_file_to_backup(file_path, timestamp, cfg_backup_dir))
    return entries


def build_stream_settings_from_params(params: Dict[str, str], default_network: str = "tcp") -> Dict[str, Any]:
    network = (params.get("type") or params.get("net") or default_network or "tcp").lower()
    security = (params.get("security") or params.get("tls") or "none").lower()

    if network == "raw":
        network = "tcp"

    stream: Dict[str, Any] = {
        "network": network,
        "security": security if security in {"none", "tls", "reality"} else "none",
    }

    if network == "ws":
        ws: Dict[str, Any] = {"path": urllib.parse.unquote(params.get("path", "/") or "/")}
        host = params.get("host")
        if host:
            ws["host"] = host
        stream["wsSettings"] = ws

    if network == "grpc":
        grpc: Dict[str, Any] = {}
        service_name = urllib.parse.unquote(params.get("serviceName") or params.get("path") or "")
        if service_name:
            grpc["serviceName"] = service_name
        authority = params.get("authority")
        if authority:
            grpc["authority"] = authority
        if grpc:
            stream["grpcSettings"] = grpc

    if stream["security"] == "tls":
        tls_settings: Dict[str, Any] = {}
        server_name = params.get("sni") or params.get("serverName")
        if server_name:
            tls_settings["serverName"] = server_name
        alpn = params.get("alpn")
        if alpn:
            tls_settings["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        fp = params.get("fp") or params.get("fingerprint")
        if fp:
            tls_settings["fingerprint"] = fp
        insecure = params.get("allowInsecure")
        if insecure in {"1", "true", "True"}:
            tls_settings["allowInsecure"] = True
        if tls_settings:
            stream["tlsSettings"] = tls_settings

    if stream["security"] == "reality":
        reality: Dict[str, Any] = {}
        server_name = params.get("sni") or params.get("serverName")
        if server_name:
            reality["serverName"] = server_name
        fp = params.get("fp") or params.get("fingerprint")
        if fp:
            reality["fingerprint"] = fp
        public_key = params.get("pbk") or params.get("publicKey") or params.get("password")
        if public_key:
            # Most links provide `pbk`; outbound expects `publicKey`.
            reality["publicKey"] = public_key
        short_id = params.get("sid") or params.get("shortId")
        if short_id:
            reality["shortId"] = short_id
        spider_x = params.get("spx") or params.get("spiderX")
        if spider_x:
            reality["spiderX"] = spider_x
        if reality:
            stream["realitySettings"] = reality

    return stream


def base_profile_template(proxy_outbound: Dict[str, Any]) -> Dict[str, Any]:
    # Minimal system profile: TUN inbound + proxy/direct/block outbounds.
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "tun-in",
                "protocol": "tun",
                "settings": {
                    "name": "xray0",
                    "MTU": 1500,
                    "userLevel": 0,
                },
            }
        ],
        "outbounds": [
            proxy_outbound,
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "domain": ["geosite:private"], "outboundTag": "direct"},
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
            ],
        },
    }


def decode_vmess_payload(link: str) -> Dict[str, Any]:
    payload = link[len("vmess://") :].strip()
    payload += "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload.encode("utf-8")).decode("utf-8")
        data = json.loads(decoded)
    except Exception as exc:
        raise VPNError(f"Invalid vmess link: {exc}") from exc
    if not isinstance(data, dict):
        raise VPNError("Invalid vmess link payload")
    return data


def parse_vmess_link(link: str) -> Tuple[Dict[str, Any], str]:
    data = decode_vmess_payload(link)
    address = data.get("add") or data.get("address")
    port = int(data.get("port", 443))
    uid = data.get("id")
    if not address or not uid:
        raise VPNError("VMess link missing address or id")

    params = {
        "net": str(data.get("net", "tcp")),
        "type": str(data.get("net", "tcp")),
        "security": "tls" if str(data.get("tls", "")).lower() in {"tls", "xtls"} else "none",
        "sni": str(data.get("sni", "")),
        "host": str(data.get("host", "")),
        "path": str(data.get("path", "")),
        "alpn": str(data.get("alpn", "")),
        "fp": str(data.get("fp", "")),
    }
    stream = build_stream_settings_from_params(params, default_network="tcp")

    security = str(data.get("scy", "auto"))
    aid = int(data.get("aid", 0)) if str(data.get("aid", "0")).isdigit() else 0

    proxy = {
        "tag": "proxy",
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [
                        {
                            "id": uid,
                            "alterId": aid,
                            "security": security,
                        }
                    ],
                }
            ]
        },
        "streamSettings": stream,
    }
    profile = base_profile_template(proxy)
    profile_name = str(data.get("ps") or "vmess-import")
    return profile, profile_name


def parse_vless_link(link: str) -> Tuple[Dict[str, Any], str]:
    parsed = urllib.parse.urlparse(link)
    if not parsed.username or not parsed.hostname:
        raise VPNError("Invalid VLESS/REALITY link: missing user or host")

    params_raw = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params = {k: urllib.parse.unquote(v[0]) for k, v in params_raw.items() if v}

    stream = build_stream_settings_from_params(params, default_network="tcp")
    flow = params.get("flow", "")
    encryption = params.get("encryption", "none")

    proxy = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": parsed.hostname,
                    "port": parsed.port or 443,
                    "users": [
                        {
                            "id": urllib.parse.unquote(parsed.username),
                            "encryption": encryption,
                            "flow": flow,
                        }
                    ],
                }
            ]
        },
        "streamSettings": stream,
    }

    profile = base_profile_template(proxy)
    profile_name = urllib.parse.unquote(parsed.fragment or "vless-import")
    return profile, profile_name


def profile_from_share_link(link: str) -> Tuple[Dict[str, Any], str]:
    raw = link.strip()
    low = raw.lower()
    if low.startswith("vmess://"):
        return parse_vmess_link(raw)
    if low.startswith("vless://"):
        return parse_vless_link(raw)
    if low.startswith("reality://"):
        # Some tools label REALITY links this way; normalize to VLESS syntax.
        return parse_vless_link("vless://" + raw[len("reality://") :])
    raise VPNError("Unsupported link scheme. Supported: vmess://, vless://, reality://")


def ensure_runtime_profile(base: Dict[str, Any], tun_name: str, tun_mtu: int, uplink_dev: str, uplink_src: Optional[str]) -> Dict[str, Any]:
    config = json.loads(json.dumps(base))

    inbounds = config.setdefault("inbounds", [])
    tun_inbound = None
    for inbound in inbounds:
        if inbound.get("protocol") == "tun":
            tun_inbound = inbound
            break

    if tun_inbound is None:
        tun_inbound = {"tag": "tun-in", "protocol": "tun", "settings": {}}
        inbounds.append(tun_inbound)

    tun_settings = tun_inbound.setdefault("settings", {})
    tun_settings["name"] = tun_name
    tun_settings["MTU"] = int(tun_mtu)
    tun_settings["userLevel"] = int(tun_settings.get("userLevel", 0) or 0)

    outbounds = config.setdefault("outbounds", [])
    tags = {o.get("tag") for o in outbounds if isinstance(o, dict)}
    if "direct" not in tags:
        outbounds.append({"tag": "direct", "protocol": "freedom", "settings": {}})
    if "block" not in tags:
        outbounds.append({"tag": "block", "protocol": "blackhole", "settings": {}})

    # Bind proxy outbound sockets to real uplink to avoid route loops.
    for outbound in outbounds:
        if outbound.get("tag") in {"direct", "block"}:
            continue
        stream = outbound.setdefault("streamSettings", {})
        sockopt = stream.setdefault("sockopt", {})
        sockopt["interface"] = uplink_dev
        if uplink_src:
            outbound["sendThrough"] = uplink_src

    routing = config.setdefault("routing", {})
    rules = routing.setdefault("rules", [])
    if not any(isinstance(r, dict) and r.get("ip") == ["geoip:private"] for r in rules):
        rules.append({"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"})

    return config


def extract_remote_hosts(config: Dict[str, Any]) -> List[str]:
    hosts: List[str] = []
    for outbound in config.get("outbounds", []):
        settings = outbound.get("settings", {})
        for node in settings.get("vnext", []):
            address = node.get("address")
            if address:
                hosts.append(str(address))
    return sorted(set(hosts))


def resolve_host_ips(host: str) -> List[str]:
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass

    ips: List[str] = []
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except socket.gaierror as exc:
        logging.warning("Could not resolve %s: %s", host, exc)
    return ips


def add_rule(pref: int, args_tail: List[str], state: Dict[str, Any], family: Optional[str] = None) -> None:
    args = ["rule", "add", "pref", str(pref)] + args_tail
    run_ip(args, family=family)
    state.setdefault("added_rules", []).append({"pref": pref, "family": family})


def configure_routing(
    tun_name: str,
    table_id: int,
    route_mode: str,
    split_interfaces: List[str],
    remote_ips: List[str],
    dns_servers: List[str],
    state: Dict[str, Any],
) -> None:
    run_ip(["route", "flush", "table", str(table_id)], check=False)
    run_ip(["route", "replace", "default", "dev", tun_name, "table", str(table_id)])

    # Bypass VPN for upstream server IPs to prevent proxy self-loop.
    pref = RULE_PREF_SERVER_BYPASS_BASE
    for ip in remote_ips:
        family = "-6" if ":" in ip else "-4"
        prefix = f"{ip}/128" if family == "-6" else f"{ip}/32"
        add_rule(pref, ["to", prefix, "lookup", "main"], state, family=family)
        pref += 1

    dns_pref = RULE_PREF_DNS_BYPASS_BASE
    for dns_ip in dns_servers:
        family = "-6" if ":" in dns_ip else "-4"
        prefix = f"{dns_ip}/128" if family == "-6" else f"{dns_ip}/32"
        add_rule(dns_pref, ["to", prefix, "lookup", "main"], state, family=family)
        dns_pref += 1

    # Keep all non-default/main specific routes (LAN, Docker, Tailscale, etc.) before VPN rule.
    add_rule(
        RULE_PREF_MAIN_SPECIFIC,
        ["lookup", "main", "suppress_prefixlength", "0"],
        state,
    )

    route_mode = route_mode.lower().strip()
    if route_mode == "full":
        add_rule(RULE_PREF_VPN_DEFAULT, ["lookup", str(table_id)], state)
        return

    if route_mode != "split":
        raise VPNError("route_mode must be 'full' or 'split'")

    # Split mode: route only traffic sourced from selected interface subnets via VPN table.
    if not split_interfaces:
        raise VPNError("Split mode selected but split_interfaces is empty")

    pref = RULE_PREF_SPLIT_BASE
    for iface in split_interfaces:
        addr_data = json.loads(run_cmd(["ip", "-j", "addr", "show", "dev", iface], check=False).stdout or "[]")
        if not addr_data:
            logging.warning("Interface not found for split mode: %s", iface)
            continue

        for addr in addr_data[0].get("addr_info", []):
            if addr.get("scope") not in {"global", "site"}:
                continue
            family = "-6" if addr.get("family") == "inet6" else "-4"
            local = addr.get("local")
            plen = addr.get("prefixlen")
            if not local or plen is None:
                continue
            cidr = str(ipaddress.ip_network(f"{local}/{plen}", strict=False))
            add_rule(pref, ["from", cidr, "lookup", str(table_id)], state, family=family)
            pref += 1

    if pref == RULE_PREF_SPLIT_BASE:
        raise VPNError("No valid source CIDRs found for split mode interfaces")


def remove_added_network(state: Dict[str, Any]) -> None:
    # Remove rules in reverse order to avoid priority collisions.
    for rule in reversed(state.get("added_rules", [])):
        family = rule.get("family")
        pref = str(rule.get("pref"))
        run_ip(["rule", "del", "pref", pref], family=family, check=False)

    table_id = state.get("table_id", DEFAULT_TABLE_ID)
    run_ip(["route", "flush", "table", str(table_id)], check=False)


def wait_for_tun_up(tun_name: str, timeout_sec: int = 12) -> None:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if run_cmd(["ip", "link", "show", tun_name], check=False).returncode == 0:
            # Ensure interface is UP.
            run_cmd(["ip", "link", "set", tun_name, "up"], check=False)
            return
        time.sleep(0.5)
    raise VPNError(f"TUN interface {tun_name} did not appear")


def xray_test_config(xray_bin: str, config_path: Path) -> None:
    attempts = [
        [xray_bin, "run", "-test", "-config", str(config_path)],
        [xray_bin, "-test", "-config", str(config_path)],
    ]
    errors: List[str] = []
    for cmd in attempts:
        res = run_cmd(cmd, check=False)
        if res.returncode == 0:
            return
        errors.append((res.stderr or res.stdout or "").strip())
    raise VPNError("Xray config validation failed: " + " | ".join(x for x in errors if x))


def start_xray_process(xray_bin: str, config_path: Path) -> int:
    log_fh = LOG_FILE.open("a", encoding="utf-8")
    proc = subprocess.Popen(
        [xray_bin, "run", "-config", str(config_path)],
        stdout=log_fh,
        stderr=log_fh,
        start_new_session=True,
        text=True,
    )
    time.sleep(0.8)
    if proc.poll() is not None:
        raise VPNError("Xray terminated immediately. Check log: /tmp/xray-system-vpn/vpn-client.log")
    return int(proc.pid)


def stop_xray_process(pid: Optional[int]) -> None:
    if not pid or not is_running(pid):
        return

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return

    deadline = time.time() + 8
    while time.time() < deadline:
        if not is_running(pid):
            return
        time.sleep(0.3)

    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def verify_default_through_tun(tun_name: str) -> bool:
    res = run_cmd(["ip", "route", "get", "1.1.1.1"], check=False)
    out = (res.stdout or "")
    return f"dev {tun_name}" in out


def route_to_ip_uses_tun(ip: str, tun_name: str) -> bool:
    if ":" in ip:
        res = run_cmd(["ip", "-6", "route", "get", ip], check=False)
    else:
        res = run_cmd(["ip", "-4", "route", "get", ip], check=False)
    out = (res.stdout or "")
    return f"dev {tun_name}" in out


def verify_bypass_targets(remote_ips: List[str], dns_servers: List[str], tun_name: str) -> None:
    for ip in remote_ips:
        if route_to_ip_uses_tun(ip, tun_name):
            raise VPNError(f"VPN upstream {ip} is routed to {tun_name}; refusing to keep broken route state")

    for dns_ip in dns_servers:
        if route_to_ip_uses_tun(dns_ip, tun_name):
            raise VPNError(f"DNS server {dns_ip} is routed to {tun_name}; refusing to keep broken route state")


def startup_preflight(cmd_name: str) -> None:
    ensure_layout()
    settings = load_settings()
    interfaces = list_interfaces()
    if cmd_name == "on" and not interfaces:
        raise VPNError("No network interfaces found")
    if cmd_name != "on" and not interfaces:
        logging.warning("Preflight warning: no network interfaces detected")

    profiles = sorted(PROFILES_DIR.glob("*.json"))
    if not profiles:
        raise VPNError(f"No Xray profiles found in {PROFILES_DIR}")

    active = settings.get("active_profile", "default.json")
    active_path = PROFILES_DIR / active

    if cmd_name == "on" and not active_path.exists():
        raise VPNError(f"Active profile does not exist: {active_path}")

    xray_path = ""
    if cmd_name == "on":
        xray_path = find_xray_binary(settings)
    else:
        try:
            xray_path = find_xray_binary(settings)
        except VPNError:
            logging.warning("Preflight warning: xray binary not found")

    logging.info(
        "Preflight: app_root=%s profiles=%s active=%s interfaces=%s",
        APP_ROOT,
        len(profiles),
        active,
        ",".join(interfaces) if interfaces else "-",
    )
    if xray_path:
        logging.info("Preflight: xray=%s", xray_path)


def command_on(args: argparse.Namespace) -> None:
    require_root()
    ensure_layout()
    settings = load_settings()

    if STATE_FILE.exists():
        current = load_json(STATE_FILE, default={})
        if is_running(current.get("pid")):
            raise VPNError("VPN already enabled. Use vpn-status or vpn-off first.")
        STATE_FILE.unlink(missing_ok=True)

    profile = profile_path(args.profile, settings)
    route_mode = (args.mode or settings.get("route_mode", "full")).strip().lower()
    split_interfaces = parse_list_param(args.split_interfaces) or settings.get("split_interfaces", [])
    tun_name = settings.get("tun_name", "xray0")
    tun_mtu = int(settings.get("tun_mtu", 1500))
    table_id = int(settings.get("table_id", DEFAULT_TABLE_ID))

    xray_bin = find_xray_binary(settings)
    ensure_xray_capabilities(xray_bin)

    raw_cfg = load_json(profile, default=None)
    if not isinstance(raw_cfg, dict):
        raise VPNError(f"Invalid JSON profile: {profile}")

    backup_ts = backup_stamp()
    backup_dir = save_backup_snapshot(backup_ts)
    dns_backup_entries = backup_dns_settings(backup_ts, backup_dir)
    config_backup_entries = backup_local_config_files(backup_ts, backup_dir, [SETTINGS_FILE, profile])
    prune_backup_storage(settings, current_profile=profile, keep=BACKUP_KEEP_COUNT)
    save_json(
        backup_dir / "manifest.json",
        {
            "created_at": dt.datetime.now().isoformat(),
            "timestamp": backup_ts,
            "profile": str(profile),
            "dns_backup_entries": dns_backup_entries,
            "config_backup_entries": config_backup_entries,
        },
    )
    uplink = detect_active_uplink(tun_name)
    uplink_src = uplink.get("src") or get_interface_source_ip(uplink["dev"])

    runtime_cfg = ensure_runtime_profile(raw_cfg, tun_name=tun_name, tun_mtu=tun_mtu, uplink_dev=uplink["dev"], uplink_src=uplink_src)
    remote_hosts = extract_remote_hosts(runtime_cfg)
    dns_servers = detect_dns_servers()
    remote_ips: List[str] = []
    for host in remote_hosts:
        remote_ips.extend(resolve_host_ips(host))
    remote_ips = sorted(set(remote_ips))
    if remote_hosts and not remote_ips:
        raise VPNError("Could not resolve outbound server IPs; refusing to enable VPN to avoid route loop")

    save_json(RUNTIME_CONFIG_FILE, runtime_cfg)
    xray_test_config(xray_bin, RUNTIME_CONFIG_FILE)

    state: Dict[str, Any] = {
        "started_at": dt.datetime.now().isoformat(),
        "profile": str(profile),
        "runtime_config": str(RUNTIME_CONFIG_FILE),
        "backup_dir": str(backup_dir),
        "backup_timestamp": backup_ts,
        "dns_backup_entries": dns_backup_entries,
        "config_backup_entries": config_backup_entries,
        "tun_name": tun_name,
        "table_id": table_id,
        "route_mode": route_mode,
        "split_interfaces": split_interfaces,
        "uplink": uplink,
        "remote_ips": remote_ips,
        "dns_servers": dns_servers,
        "added_rules": [],
    }

    try:
        pid = start_xray_process(xray_bin, RUNTIME_CONFIG_FILE)
        state["pid"] = pid

        wait_for_tun_up(tun_name)
        configure_routing(
            tun_name=tun_name,
            table_id=table_id,
            route_mode=route_mode,
            split_interfaces=split_interfaces,
            remote_ips=remote_ips,
            dns_servers=dns_servers,
            state=state,
        )
        verify_bypass_targets(remote_ips, dns_servers, tun_name)

        if route_mode == "full" and not verify_default_through_tun(tun_name):
            raise VPNError("Default route was not redirected to TUN after enabling VPN")

        save_json(STATE_FILE, state)
        reset_connectivity_cache()
        logging.info("VPN enabled: profile=%s uplink=%s mode=%s", profile.name, uplink["dev"], route_mode)

    except Exception:
        stop_xray_process(state.get("pid"))
        remove_added_network(state)
        restore_dns_settings(state.get("dns_backup_entries", []))
        raise


def command_off(_args: argparse.Namespace) -> None:
    require_root()
    state = load_json(STATE_FILE, default=None)
    if not isinstance(state, dict):
        logging.info("VPN is already disabled")
        return

    stop_xray_process(state.get("pid"))
    remove_added_network(state)
    restore_dns_settings(state.get("dns_backup_entries", []))
    reset_connectivity_cache()

    STATE_FILE.unlink(missing_ok=True)
    RUNTIME_CONFIG_FILE.unlink(missing_ok=True)
    logging.info("VPN disabled and network state restored")


def command_status(_args: argparse.Namespace) -> None:
    settings = load_settings()
    status_key, state = status_key_and_state(settings)
    active_profile = settings.get("active_profile", "default.json")
    active_path = PROFILES_DIR / active_profile
    p_state_key = profile_state_key(active_path)
    conn_ok, conn_detail = get_cached_connectivity(force=True, max_age_sec=0.0, timeout=1.2)

    print(f"{tr(settings, 'vpn_status')}: {paint_status_label(settings, status_key)}")
    print(f"{tr(settings, 'active_profile')}: {active_profile}")
    print(f"{tr(settings, 'profile_state')}: {tr(settings, p_state_key)}")
    print(f"{tr(settings, 'connection_test')}: {paint_status_label(settings, 'conn_ok' if conn_ok else 'conn_fail')} ({conn_detail})")

    if state:
        pid = state.get("pid")
        tun_name = state.get("tun_name", settings.get("tun_name", "xray0"))
        print(f"PID: {pid}")
        print(f"Profile: {Path(state.get('profile', '')).name}")
        print(f"Mode: {state.get('route_mode')}")
        print(f"Uplink: {state.get('uplink', {}).get('dev')}")
        print(f"TUN: {tun_name}")
    print(f"Log: {LOG_FILE}")


def command_list(_args: argparse.Namespace) -> None:
    settings = load_settings()
    active = settings.get("active_profile", "")
    if not PROFILES_DIR.exists():
        return
    for file in sorted(PROFILES_DIR.glob("*.json")):
        marker = "*" if file.name == active else " "
        print(f"{marker} {file.name}")


def command_use(args: argparse.Namespace) -> None:
    require_root()
    ensure_layout()
    settings = load_settings()
    name = args.profile
    if not name.endswith(".json"):
        name += ".json"
    path = PROFILES_DIR / name
    if not path.exists():
        raise VPNError(f"Profile not found: {path}")
    settings["active_profile"] = name
    save_settings(settings)
    logging.info("Active profile set: %s", name)


def command_import_link(args: argparse.Namespace) -> None:
    require_root()
    ensure_layout()

    profile_data, suggested_name = profile_from_share_link(args.link)
    filename = slugify_profile_name(args.name or suggested_name)
    out_path = PROFILES_DIR / filename
    save_json(out_path, profile_data)

    settings = load_settings()
    if args.activate:
        settings["active_profile"] = filename
        save_settings(settings)

    logging.info("Profile imported from link: %s", out_path)


def command_import_file(args: argparse.Namespace) -> None:
    require_root()
    ensure_layout()

    src = Path(args.path)
    if not src.exists():
        raise VPNError(f"File not found: {src}")

    data = load_json(src, default=None)
    if not isinstance(data, dict):
        raise VPNError("Input file is not a valid JSON object")

    filename = slugify_profile_name(args.name or src.stem)
    out_path = PROFILES_DIR / filename
    save_json(out_path, data)

    settings = load_settings()
    if args.activate:
        settings["active_profile"] = filename
        save_settings(settings)

    logging.info("Profile imported from file: %s", out_path)


def command_config(args: argparse.Namespace) -> None:
    require_root()
    ensure_layout()
    settings = load_settings()

    if args.route_mode:
        if args.route_mode not in {"full", "split"}:
            raise VPNError("route-mode must be full or split")
        settings["route_mode"] = args.route_mode

    if args.split_interfaces is not None:
        settings["split_interfaces"] = parse_list_param(args.split_interfaces)

    if args.profile:
        name = args.profile if args.profile.endswith(".json") else f"{args.profile}.json"
        if not (PROFILES_DIR / name).exists():
            raise VPNError(f"Profile not found: {PROFILES_DIR / name}")
        settings["active_profile"] = name

    if args.xray_bin:
        settings["xray_bin"] = args.xray_bin

    if args.language:
        settings["language"] = normalize_language(args.language)

    save_settings(settings)
    logging.info("Settings updated: %s", SETTINGS_FILE)


def render_menu_header(settings: Dict[str, Any]) -> None:
    status_key, _ = status_key_and_state(settings)
    active_profile = settings.get("active_profile", "default.json")
    p_state_key = profile_state_key(PROFILES_DIR / active_profile)
    conn_label, conn_detail = get_cached_connectivity_view(settings)

    print(paint("╔" + "═" * 70 + "╗", "36"))
    print(paint("║ " + f"{tr(settings, 'app_title'):<68}" + " ║", "36"))
    print(f"{tr(settings, 'app_subtitle')}")
    print(paint("╟" + "─" * 70 + "╢", "36"))
    print(f"{tr(settings, 'vpn_status')}: {paint_status_label(settings, status_key)}")
    print(f"{tr(settings, 'active_profile')}: {active_profile}")
    print(f"{tr(settings, 'profile_state')}: {tr(settings, p_state_key)}")
    print(f"{tr(settings, 'connection_test')}: {conn_label} ({conn_detail})")
    print(f"{tr(settings, 'language')}: {normalize_language(str(settings.get('language', 'ru'))).upper()}")
    print(paint("╚" + "═" * 70 + "╝", "36"))


def choose_profile_from_menu(settings: Dict[str, Any]) -> Optional[str]:
    profiles = list_profile_names()
    if not profiles:
        return None

    while True:
        clear_terminal()
        print(paint(f"┌─ {tr(settings, 'profile_select_title')}", "36"))
        print(f"{tr(settings, 'profile_select_current')}: {settings.get('active_profile', 'default.json')}")
        print()
        for idx, name in enumerate(profiles, 1):
            marker = "*" if name == settings.get("active_profile", "") else " "
            line = f"{idx}. [{marker}] {name}"
            print(paint(line, "32") if marker == "*" else line)
        print(paint(tr(settings, "profile_select_cancel"), "33"))

        choice = input(f"{tr(settings, 'profile_select_prompt')}: ").strip()
        if choice == "0":
            return None
        if not choice.isdigit():
            continue
        idx = int(choice) - 1
        if 0 <= idx < len(profiles):
            selected = profiles[idx]
            settings["active_profile"] = selected
            save_settings(settings)
            return selected


def choose_language_from_menu(settings: Dict[str, Any]) -> Optional[str]:
    while True:
        clear_terminal()
        print(paint(f"┌─ {tr(settings, 'language_title')}", "36"))
        print("1. Русский")
        print("2. English")
        print("0. " + tr(settings, "menu_back"))
        choice = input(f"{tr(settings, 'select_prompt')}: ").strip()
        if choice == "0":
            return None
        if choice == "1":
            settings["language"] = "ru"
            save_settings(settings)
            return "ru"
        if choice == "2":
            settings["language"] = "en"
            save_settings(settings)
            return "en"


def show_status_submenu(settings: Dict[str, Any]) -> None:
    while True:
        clear_terminal()
        command_status(argparse.Namespace())
        print()
        print(f"0. {tr(settings, 'menu_back')}")
        choice = input(f"{tr(settings, 'select_prompt')}: ").strip()
        if choice == "0":
            return


def import_link_submenu(settings: Dict[str, Any]) -> Optional[str]:
    clear_terminal()
    print(paint(f"┌─ {tr(settings, 'menu_import_link')}", "36"))
    print(tr(settings, "import_cancel_hint"))
    name = input(tr(settings, "import_name_prompt")).strip()
    if name == "0":
        return None
    link = input(tr(settings, "import_link_prompt")).strip()
    if link == "0":
        return None
    command_import_link(argparse.Namespace(name=name or None, link=link, activate=False))
    return tr(settings, "import_done")


def read_menu_choice_with_refresh(
    settings: Dict[str, Any],
    notice: str,
    options: List[Tuple[str, str]],
) -> str:
    # Draw once per menu cycle to avoid terminal flicker.
    clear_terminal()
    render_menu_header(settings)
    if notice:
        print(notice)
        print()
    print(paint(f"{tr(settings, 'menu_title')}:", "35"))
    for key, label in options:
        print(f"{key}. {label}")
    return input(f"{tr(settings, 'select_prompt')}: ").strip()


def command_menu(_args: argparse.Namespace) -> None:
    run_startup_screen()
    notice = ""
    while True:
        settings = load_settings()
        options = [
            ("1", tr(settings, "menu_on")),
            ("2", tr(settings, "menu_off")),
            ("3", tr(settings, "menu_status")),
            ("4", tr(settings, "menu_import_link")),
            ("5", tr(settings, "menu_select_profile")),
            ("6", tr(settings, "menu_switch_language")),
            ("0", tr(settings, "menu_exit")),
        ]
        choice = read_menu_choice_with_refresh(settings, notice, options)
        notice = ""

        try:
            if choice == "1":
                command_on(argparse.Namespace(profile=None, mode=None, split_interfaces=None))
                conn_ok, conn_detail = get_cached_connectivity(force=True, max_age_sec=0.0, timeout=1.2)
                notice = paint(
                    f"{tr(settings, 'vpn_enabled')} | {tr(settings, 'connection_test')}: "
                    f"{tr(settings, 'conn_ok' if conn_ok else 'conn_fail')} ({conn_detail})",
                    "32" if conn_ok else "33",
                )
                continue
            if choice == "2":
                command_off(argparse.Namespace())
                conn_ok, conn_detail = get_cached_connectivity(force=True, max_age_sec=0.0, timeout=1.2)
                notice = paint(
                    f"{tr(settings, 'vpn_disabled')} | {tr(settings, 'connection_test')}: "
                    f"{tr(settings, 'conn_ok' if conn_ok else 'conn_fail')} ({conn_detail})",
                    "32" if conn_ok else "33",
                )
                continue
            if choice == "3":
                show_status_submenu(settings)
                continue
            if choice == "4":
                imported = import_link_submenu(settings)
                if imported:
                    notice = paint(imported, "32")
                continue
            if choice == "5":
                selected = choose_profile_from_menu(settings)
                if selected:
                    notice = paint(f"{tr(settings, 'profile_select_saved')}: {selected}", "32")
                continue
            if choice == "6":
                lang = choose_language_from_menu(settings)
                if lang:
                    settings = load_settings()
                    notice = paint(f"{tr(settings, 'language_saved')}: {lang.upper()}", "32")
                continue
            if choice == "0":
                return
            notice = paint(tr(settings, "invalid_choice"), "33")
        except Exception as exc:
            notice = paint(f"{tr(settings, 'error')}: {exc}", "31")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="System VPN controller for Xray")
    sub = parser.add_subparsers(dest="cmd", required=False)

    p_on = sub.add_parser("on", help="Enable VPN")
    p_on.add_argument("--profile", help="Profile name or absolute path")
    p_on.add_argument("--mode", choices=["full", "split"], help="Route mode override")
    p_on.add_argument("--split-interfaces", help="Comma-separated interfaces for split mode")
    p_on.set_defaults(func=command_on)

    p_off = sub.add_parser("off", help="Disable VPN")
    p_off.set_defaults(func=command_off)

    p_status = sub.add_parser("status", help="Show VPN status")
    p_status.set_defaults(func=command_status)

    p_list = sub.add_parser("list", help="List profiles")
    p_list.set_defaults(func=command_list)

    p_use = sub.add_parser("use", help="Set active profile")
    p_use.add_argument("profile")
    p_use.set_defaults(func=command_use)

    p_import_link = sub.add_parser("import-link", help="Import profile from share link")
    p_import_link.add_argument("link", help="vmess:// or vless:// or reality:// link")
    p_import_link.add_argument("--name", help="Profile file name")
    p_import_link.add_argument("--activate", action="store_true", help="Set as active profile")
    p_import_link.set_defaults(func=command_import_link)

    p_import_file = sub.add_parser("import-file", help="Import JSON profile from file")
    p_import_file.add_argument("path", help="Path to JSON file")
    p_import_file.add_argument("--name", help="Profile file name")
    p_import_file.add_argument("--activate", action="store_true", help="Set as active profile")
    p_import_file.set_defaults(func=command_import_file)

    p_cfg = sub.add_parser("config", help="Update client settings")
    p_cfg.add_argument("--route-mode", choices=["full", "split"], help="Default route mode")
    p_cfg.add_argument("--split-interfaces", help="Comma-separated interfaces for split mode")
    p_cfg.add_argument("--profile", help="Set active profile")
    p_cfg.add_argument("--xray-bin", help="Override xray binary path")
    p_cfg.add_argument("--language", choices=["ru", "en"], help="UI language")
    p_cfg.set_defaults(func=command_config)

    p_menu = sub.add_parser("menu", help="Interactive menu")
    p_menu.set_defaults(func=command_menu)

    parser.set_defaults(cmd="menu", func=command_menu)
    return parser


def main() -> int:
    setup_logging()
    parser = build_parser()
    args = parser.parse_args()

    try:
        startup_preflight(args.cmd)
        args.func(args)
        return 0
    except VPNError as exc:
        logging.error(str(exc))
        return 2
    except KeyboardInterrupt:
        logging.error("Interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
