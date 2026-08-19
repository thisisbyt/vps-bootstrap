from __future__ import annotations

import os
import platform
import re
import shutil
import socket
from dataclasses import dataclass
from pathlib import Path

from app.command import run_command


@dataclass(frozen=True)
class MemoryInfo:
    ram_total_mb: int
    swap_total_mb: int


@dataclass(frozen=True)
class FilesystemInfo:
    total_gb: float
    free_gb: float


@dataclass(frozen=True)
class ServerInfo:
    ubuntu_version: str
    ubuntu_pretty: str
    hostname: str
    architecture: str
    cpu: str
    memory: MemoryInfo
    root_fs: FilesystemInfo
    ipv4: list[str]
    ipv6: list[str]
    timezone: str
    time_sync: str


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def parse_meminfo(text: str) -> MemoryInfo:
    values: dict[str, int] = {}
    for line in text.splitlines():
        match = re.match(r"^(MemTotal|SwapTotal):\s+(\d+)\s+kB$", line)
        if match:
            values[match.group(1)] = int(match.group(2)) // 1024
    return MemoryInfo(ram_total_mb=values.get("MemTotal", 0), swap_total_mb=values.get("SwapTotal", 0))


def get_ip_addresses() -> tuple[list[str], list[str]]:
    result = run_command(["ip", "-o", "addr", "show"], timeout=5)
    ipv4: list[str] = []
    ipv6: list[str] = []
    if not result.ok:
        return ipv4, ipv6
    for line in result.stdout.splitlines():
        parts = line.split()
        if "inet" in parts:
            addr = parts[parts.index("inet") + 1].split("/")[0]
            if not addr.startswith("127."):
                ipv4.append(addr)
        if "inet6" in parts:
            addr = parts[parts.index("inet6") + 1].split("/")[0]
            if addr != "::1" and not addr.lower().startswith("fe80:"):
                ipv6.append(addr)
    return sorted(set(ipv4)), sorted(set(ipv6))


def get_timezone() -> str:
    result = run_command(["timedatectl", "show", "--property=Timezone", "--value"], timeout=5)
    if result.ok and result.stdout:
        return result.stdout
    try:
        return os.readlink("/etc/localtime")
    except OSError:
        return "unknown"


def get_time_sync_status() -> str:
    result = run_command(["timedatectl", "show", "--property=NTPSynchronized", "--value"], timeout=5)
    if result.ok and result.stdout:
        return "synchronized" if result.stdout.lower() == "yes" else "not synchronized"
    return "unknown"


def collect_server_info() -> ServerInfo:
    os_release = parse_os_release(Path("/etc/os-release").read_text(encoding="utf-8"))
    memory = parse_meminfo(Path("/proc/meminfo").read_text(encoding="utf-8"))
    usage = shutil.disk_usage("/")
    ipv4, ipv6 = get_ip_addresses()
    cpu = platform.processor() or platform.machine()
    return ServerInfo(
        ubuntu_version=os_release.get("VERSION_ID", "unknown"),
        ubuntu_pretty=os_release.get("PRETTY_NAME", "unknown"),
        hostname=socket.gethostname(),
        architecture=platform.machine(),
        cpu=cpu,
        memory=memory,
        root_fs=FilesystemInfo(total_gb=usage.total / (1024**3), free_gb=usage.free / (1024**3)),
        ipv4=ipv4,
        ipv6=ipv6,
        timezone=get_timezone(),
        time_sync=get_time_sync_status(),
    )


def format_server_info(info: ServerInfo) -> str:
    return "\n".join(
        [
            "Server information",
            f"Ubuntu: {info.ubuntu_pretty}",
            f"Hostname: {info.hostname}",
            f"Architecture: {info.architecture}",
            f"CPU: {info.cpu}",
            f"RAM: {info.memory.ram_total_mb} MB",
            f"Swap: {info.memory.swap_total_mb} MB",
            f"Root filesystem: {info.root_fs.total_gb:.1f} GB total, {info.root_fs.free_gb:.1f} GB free",
            f"IPv4: {', '.join(info.ipv4) if info.ipv4 else 'not detected'}",
            f"IPv6: {', '.join(info.ipv6) if info.ipv6 else 'not detected'}",
            f"Timezone: {info.timezone}",
            f"Time sync: {info.time_sync}",
        ]
    )
