from __future__ import annotations

import os
import re
import shutil
import socket
import time
from dataclasses import dataclass
from pathlib import Path

from app.command import run_command
from app.config import compatibility
from app.filesystem import write_atomic


CHRONY_UNITS = ["chrony.service", "chronyd.service"]
TIMESYNCD_UNIT = "systemd-timesyncd.service"
MANAGED_HEADER = "# Managed by vps-bootstrap. Do not edit this block directly."
MANAGED_FOOTER = "# End managed by vps-bootstrap."


class TimeSyncError(RuntimeError):
    def __init__(self, message: str, diagnostics: list[str] | None = None) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics or time_sync_diagnostics()


@dataclass(frozen=True)
class TimeSyncStatus:
    time_sane: bool
    service_active: bool
    active_services: list[str]
    synchronized: bool
    raw_ntp_synchronized: str


@dataclass(frozen=True)
class NtpProbeResult:
    provider: str
    reachable: bool
    address: str = ""
    error: str = ""


def is_clock_synchronized() -> bool:
    result = run_command(["timedatectl", "show", "--property=NTPSynchronized", "--value"], timeout=5)
    return result.ok and result.stdout.strip().lower() == "yes"


def is_time_sane() -> bool:
    result = run_command(["date", "-u", "+%Y"], timeout=5)
    return result.ok and result.stdout.isdigit() and int(result.stdout) >= 2024


def detect_active_time_services() -> list[str]:
    services: list[str] = []
    for unit in [TIMESYNCD_UNIT, *CHRONY_UNITS]:
        result = run_command(["systemctl", "is-active", unit], timeout=5)
        if result.ok and result.stdout.strip() == "active":
            services.append(unit)
    return services


def collect_time_sync_status() -> TimeSyncStatus:
    raw = run_command(["timedatectl", "show", "--property=NTPSynchronized", "--value"], timeout=5)
    active_services = detect_active_time_services()
    return TimeSyncStatus(
        time_sane=is_time_sane(),
        service_active=bool(active_services),
        active_services=active_services,
        synchronized=raw.ok and raw.stdout.strip().lower() == "yes",
        raw_ntp_synchronized=raw.stdout.strip() if raw.ok else "unknown",
    )


def probe_ntp_provider(provider: str, timeout: int) -> NtpProbeResult:
    try:
        infos = socket.getaddrinfo(provider, 123, socket.AF_INET, socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        return NtpProbeResult(provider, False, error=str(exc))

    errors: list[str] = []
    for info in infos[:3]:
        address = info[4][0]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                packet = b"\x1b" + (b"\0" * 47)
                started = time.monotonic()
                sock.sendto(packet, (address, 123))
                data, _ = sock.recvfrom(48)
                elapsed_ms = int((time.monotonic() - started) * 1000)
                if len(data) >= 48:
                    return NtpProbeResult(provider, True, address=address, error=f"{elapsed_ms} ms")
                errors.append(f"{address}: short reply")
        except OSError as exc:
            errors.append(f"{address}: {exc}")
    return NtpProbeResult(provider, False, error="; ".join(errors))


def probe_ntp_providers(providers: list[str] | None = None, timeout: int | None = None) -> list[NtpProbeResult]:
    compat = compatibility()
    probe_timeout = timeout if timeout is not None else compat.ntp_probe_timeout_seconds
    return [probe_ntp_provider(provider, probe_timeout) for provider in providers or compat.ntp_providers]


def reachable_providers(probes: list[NtpProbeResult]) -> list[str]:
    return [probe.provider for probe in probes if probe.reachable]


def chrony_is_active(active_services: list[str]) -> bool:
    return any(unit in CHRONY_UNITS for unit in active_services)


def verify_time_sync_health() -> bool:
    status = collect_time_sync_status()
    if not (status.synchronized and status.service_active):
        return False
    if chrony_is_active(status.active_services):
        return verify_chrony_commands()
    return True


def install_chrony() -> None:
    result = run_command(["apt-get", "install", "-y", "--no-install-recommends", "chrony"], timeout=120)
    if not result.ok:
        raise TimeSyncError(f"Failed to install chrony: {result.stderr or result.stdout}")


def detect_chrony_unit() -> str:
    for unit in CHRONY_UNITS:
        result = run_command(["systemctl", "list-unit-files", unit, "--no-legend"], timeout=5)
        if result.ok and result.stdout.strip():
            return unit
    for unit in CHRONY_UNITS:
        result = run_command(["systemctl", "status", unit, "--no-pager", "-l"], timeout=5)
        if result.returncode != 4:
            return unit
    return CHRONY_UNITS[0]


def chrony_config_target() -> Path:
    chrony_conf = Path("/etc/chrony/chrony.conf")
    sources_dir = Path("/etc/chrony/sources.d")
    conf_dir = Path("/etc/chrony/conf.d")
    content = chrony_conf.read_text(encoding="utf-8") if chrony_conf.exists() else ""
    if sources_dir.is_dir() and "sourcedir /etc/chrony/sources.d" in content:
        return sources_dir / "vps-bootstrap.sources"
    if conf_dir.is_dir() and "confdir /etc/chrony/conf.d" in content:
        return conf_dir / "vps-bootstrap.conf"
    return chrony_conf


def render_chrony_sources(providers: list[str]) -> str:
    lines = [MANAGED_HEADER]
    for provider in providers:
        lines.append(f"server {provider} iburst")
    lines.append(MANAGED_FOOTER)
    lines.append("")
    return "\n".join(lines)


def backup_existing(path: Path) -> None:
    if not path.exists():
        return
    backup = path.with_name(f"{path.name}.bak-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}")
    shutil.copy2(path, backup)
    os.chmod(backup, 0o640)


def configure_chrony(providers: list[str]) -> None:
    target = chrony_config_target()
    content = render_chrony_sources(providers)
    if target.exists() and target.read_text(encoding="utf-8") == content:
        return
    if target.name == "chrony.conf":
        current = target.read_text(encoding="utf-8") if target.exists() else ""
        if MANAGED_HEADER in current and MANAGED_FOOTER in current:
            before = current.split(MANAGED_HEADER, 1)[0]
            after = current.split(MANAGED_FOOTER, 1)[1]
            backup_existing(target)
            write_atomic(target, before.rstrip() + "\n\n" + content + after.lstrip(), 0o644)
            return
        backup_existing(target)
        write_atomic(target, current.rstrip() + "\n\n" + content, 0o644)
        return
    backup_existing(target)
    write_atomic(target, content, 0o644)


def restart_chrony(unit: str) -> None:
    enable = run_command(["systemctl", "enable", unit], timeout=30)
    if not enable.ok:
        raise TimeSyncError(f"Failed to enable {unit}: {enable.stderr or enable.stdout}")
    restart = run_command(["systemctl", "restart", unit], timeout=30)
    if not restart.ok:
        raise TimeSyncError(f"Failed to restart {unit}: {restart.stderr or restart.stdout}")


def verify_chrony_commands() -> bool:
    tracking = run_command(["chronyc", "tracking"], timeout=10)
    sources = run_command(["chronyc", "sources", "-v"], timeout=10)
    if not (tracking.ok and sources.ok):
        return False
    return chrony_tracking_healthy(tracking.stdout) and chrony_has_selected_source(sources.stdout)


def chrony_tracking_healthy(output: str) -> bool:
    fields = parse_chrony_tracking(output)
    stratum = parse_positive_int(fields.get("stratum", ""))
    leap_status = fields.get("leap status", "").strip().lower()
    return bool(stratum and stratum > 0 and leap_status and leap_status not in {"not synchronised", "not synchronized"})


def chrony_has_selected_source(output: str) -> bool:
    for line in output.splitlines():
        marker = line.strip().split(maxsplit=1)[0] if line.strip() else ""
        if re.match(r"^[\^=#]\*", marker):
            return True
    return False


def parse_chrony_tracking(output: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip().lower()] = value.strip()
    return fields


def parse_positive_int(value: str) -> int | None:
    match = re.search(r"\d+", value)
    if not match:
        return None
    return int(match.group(0))


def wait_for_synchronization(timeout_seconds: int | None = None, interval_seconds: int = 5) -> bool:
    deadline = time.monotonic() + (timeout_seconds or compatibility().synchronization_wait_seconds)
    while time.monotonic() <= deadline:
        if verify_time_sync_health():
            return True
        time.sleep(interval_seconds)
    return verify_time_sync_health()


def ensure_time_synchronization() -> None:
    status = collect_time_sync_status()
    if status.synchronized and status.service_active and not chrony_is_active(status.active_services):
        return
    if status.synchronized and chrony_is_active(status.active_services) and verify_chrony_commands():
        return

    compat = compatibility()
    candidates = compat.ntp_providers
    probes = probe_ntp_providers(candidates, compat.ntp_probe_timeout_seconds)
    available = reachable_providers(probes)
    if not available:
        raise TimeSyncError("Clock is not synchronized and no configured NTP provider responded over IPv4 UDP/123.")
    if len(available) < 2:
        print(f"[WARN] NTP redundancy is low: only one provider responded ({available[0]})")

    install_chrony()
    configure_chrony(candidates)
    unit = detect_chrony_unit()
    restart_chrony(unit)

    if not wait_for_synchronization():
        raise TimeSyncError("Chrony was configured, but actual clock synchronization was not achieved.")


def time_sync_diagnostics() -> list[str]:
    commands = [
        "timedatectl",
        "timedatectl timesync-status",
        "systemctl status systemd-timesyncd --no-pager -l",
    ]
    if shutil.which("chronyc"):
        commands.extend(
            [
                "systemctl status chrony --no-pager -l",
                "systemctl status chronyd --no-pager -l",
                "chronyc tracking",
                "chronyc sources -v",
            ]
        )
    else:
        commands.append("dpkg -l chrony")
    return commands
