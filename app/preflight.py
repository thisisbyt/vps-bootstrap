from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path

from app.command import run_command
from app.config import SUPPORTED_ARCHES, Paths, compatibility
from app.results import CheckResult, Severity
from app.system_info import parse_meminfo, parse_os_release
from app.time_sync import collect_time_sync_status


IMPORTANT_SERVICES = [
    "ssh.service",
    "ssh.socket",
    "ufw.service",
    "fail2ban.service",
    "x-ui.service",
    "xray.service",
    "caddy.service",
    "postgresql.service",
    "warp-svc.service",
]


def run_preflight(paths: Paths | None = None) -> list[CheckResult]:
    paths = paths or Paths()
    checks = [
        check_ubuntu,
        check_architecture,
        check_privileges,
        check_dns_resolution,
        check_internet,
        check_release_source_availability,
        check_time_sane,
        check_ntp_service,
        check_clock_synchronized,
        check_disk,
        check_ram,
        check_swap,
        check_default_route,
        check_public_ipv4,
        check_ipv6,
        check_listening_ports,
        check_ufw,
        check_fail2ban,
        lambda: check_previous_install(paths),
        check_important_services,
    ]
    results: list[CheckResult] = []
    for check in checks:
        try:
            results.append(check())
        except Exception as exc:  # noqa: BLE001 - preflight should report, not crash.
            results.append(CheckResult(check.__name__, Severity.ERROR, f"{check.__name__} failed", str(exc)))
    return results


def check_ubuntu() -> CheckResult:
    path = Path("/etc/os-release")
    if not path.exists():
        return CheckResult("ubuntu", Severity.ERROR, "Ubuntu detection failed", "/etc/os-release not found")
    data = parse_os_release(path.read_text(encoding="utf-8"))
    if data.get("ID") != "ubuntu":
        return CheckResult("ubuntu", Severity.ERROR, "Unsupported OS", data.get("PRETTY_NAME", "unknown"))
    version = data.get("VERSION_ID", "unknown")
    compat = compatibility()
    if version not in compat.supported_ubuntu:
        supported = ", ".join(sorted(compat.supported_ubuntu))
        return CheckResult("ubuntu", Severity.ERROR, f"Ubuntu {version} unsupported", f"supported: {supported}")
    return CheckResult("ubuntu", Severity.OK, f"Ubuntu {version} supported")


def check_architecture() -> CheckResult:
    arch = platform.machine()
    if arch not in SUPPORTED_ARCHES:
        return CheckResult("architecture", Severity.ERROR, f"Architecture unsupported: {arch}")
    return CheckResult("architecture", Severity.OK, f"Architecture: {arch}")


def check_privileges() -> CheckResult:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return CheckResult("privileges", Severity.OK, "Root privileges available")
    if shutil.which("sudo"):
        sudo = run_command(["sudo", "-n", "true"], timeout=5)
        if sudo.ok:
            return CheckResult("privileges", Severity.OK, "Passwordless sudo available")
    return CheckResult("privileges", Severity.ERROR, "Root/sudo privileges unavailable")


def check_dns_resolution() -> CheckResult:
    result = run_command(["getent", "hosts", "ubuntu.com"], timeout=8)
    if result.ok and result.stdout:
        return CheckResult("dns", Severity.OK, "General DNS resolution", "ubuntu.com")
    return CheckResult("dns", Severity.ERROR, "General DNS resolution failed", "ubuntu.com")


def check_internet() -> CheckResult:
    curl = run_command(["curl", "-fsS", "--max-time", "8", "https://connectivity-check.ubuntu.com/"], timeout=10)
    if curl.ok:
        return CheckResult("internet", Severity.OK, "General HTTPS connectivity")
    return CheckResult("internet", Severity.ERROR, "Internet connectivity failed", curl.stderr or curl.stdout)


def check_release_source_availability() -> CheckResult:
    result = run_command(["curl", "-fsS", "--max-time", "8", "https://github.com/"], timeout=10)
    if result.ok:
        return CheckResult("release_source", Severity.OK, "GitHub release/source availability")
    return CheckResult("release_source", Severity.WARN, "GitHub release/source unavailable", result.stderr or result.stdout)


def check_time_sane() -> CheckResult:
    result = run_command(["date", "-u", "+%Y"], timeout=5)
    if not result.ok or not result.stdout.isdigit():
        return CheckResult("time_sane", Severity.WARN, "Cannot verify system time", result.stderr)
    year = int(result.stdout)
    if year < 2024:
        return CheckResult("time_sane", Severity.ERROR, "System time looks incorrect", f"UTC year is {year}")
    return CheckResult("time_sane", Severity.OK, "System time looks sane")


def check_ntp_service() -> CheckResult:
    status = collect_time_sync_status()
    if status.service_active:
        return CheckResult("ntp_service", Severity.OK, "NTP service active", ", ".join(status.active_services))
    return CheckResult("ntp_service", Severity.WARN, "NTP service inactive")


def check_clock_synchronized() -> CheckResult:
    status = collect_time_sync_status()
    if status.synchronized:
        return CheckResult("clock_synchronized", Severity.OK, "Clock synchronized")
    return CheckResult("clock_synchronized", Severity.WARN, "Clock not synchronized", f"NTPSynchronized={status.raw_ntp_synchronized}")


def check_disk() -> CheckResult:
    usage = shutil.disk_usage("/")
    free_gb = usage.free / (1024**3)
    if free_gb < 2:
        return CheckResult("disk", Severity.ERROR, f"Free disk: {free_gb:.1f} GB", "minimum for v0.1 is 2 GB")
    if free_gb < 5:
        return CheckResult("disk", Severity.WARN, f"Free disk: {free_gb:.1f} GB")
    return CheckResult("disk", Severity.OK, f"Free disk: {free_gb:.1f} GB")


def check_ram() -> CheckResult:
    mem = parse_meminfo(Path("/proc/meminfo").read_text(encoding="utf-8"))
    if mem.ram_total_mb < 512:
        return CheckResult("ram", Severity.ERROR, f"RAM: {mem.ram_total_mb} MB", "minimum for v0.1 is 512 MB")
    if mem.ram_total_mb < 1024:
        return CheckResult("ram", Severity.WARN, f"RAM: {mem.ram_total_mb} MB")
    return CheckResult("ram", Severity.OK, f"RAM: {mem.ram_total_mb} MB")


def check_swap() -> CheckResult:
    mem = parse_meminfo(Path("/proc/meminfo").read_text(encoding="utf-8"))
    if mem.swap_total_mb == 0:
        return CheckResult("swap", Severity.WARN, "Swap is not configured")
    return CheckResult("swap", Severity.OK, f"Swap: {mem.swap_total_mb} MB")


def check_default_route() -> CheckResult:
    result = run_command(["ip", "route", "show", "default"], timeout=5)
    if result.ok and result.stdout:
        return CheckResult("default_route", Severity.OK, "Default route", result.stdout.splitlines()[0])
    return CheckResult("default_route", Severity.ERROR, "Default route missing")


def check_public_ipv4() -> CheckResult:
    result = run_command(["curl", "-4", "-fsS", "--max-time", "8", "https://api.ipify.org"], timeout=10)
    if result.ok and result.stdout:
        return CheckResult("public_ipv4", Severity.OK, f"Public IPv4: {result.stdout}")
    return CheckResult("public_ipv4", Severity.WARN, "Public IPv4 could not be determined", result.stderr)


def check_ipv6() -> CheckResult:
    result = run_command(["ip", "-6", "addr", "show", "scope", "global"], timeout=5)
    if result.ok and result.stdout:
        return CheckResult("ipv6", Severity.OK, "IPv6 present")
    return CheckResult("ipv6", Severity.WARN, "IPv6 not detected")


def check_listening_ports() -> CheckResult:
    result = run_command(["ss", "-lntup"], timeout=5)
    if result.ok:
        tcp, udp = summarize_listening_sockets(result.stdout)
        return CheckResult("listening_ports", Severity.OK, f"Listening sockets: TCP {tcp}, UDP {udp}", "details: ss -lntup")
    return CheckResult("listening_ports", Severity.WARN, "Cannot list listening TCP/UDP ports", result.stderr)


def check_ufw() -> CheckResult:
    if not shutil.which("ufw"):
        return CheckResult("ufw", Severity.WARN, "UFW is not installed")
    result = run_command(["ufw", "status"], timeout=5)
    details = result.stdout or result.stderr
    if result.ok:
        return CheckResult("ufw", Severity.OK, "UFW installed and status available", result.stdout.splitlines()[0] if result.stdout else "")
    return CheckResult("ufw", Severity.WARN, "UFW installed but status command failed", details)


def check_fail2ban() -> CheckResult:
    if not shutil.which("fail2ban-client"):
        return CheckResult("fail2ban", Severity.WARN, "Fail2ban is not installed")
    result = run_command(["fail2ban-client", "ping"], timeout=5)
    severity = Severity.OK if result.ok else Severity.WARN
    return CheckResult("fail2ban", severity, "Fail2ban present", result.stdout or result.stderr)


def check_previous_install(paths: Paths) -> CheckResult:
    if paths.state_file.exists():
        return CheckResult("previous_install", Severity.WARN, "Previous VPS Bootstrap state exists", str(paths.state_file))
    return CheckResult("previous_install", Severity.OK, "No previous VPS Bootstrap state detected")


def check_important_services() -> CheckResult:
    if not shutil.which("systemctl"):
        return CheckResult("services", Severity.WARN, "systemctl unavailable")
    found: list[str] = []
    for service in IMPORTANT_SERVICES:
        active = run_command(["systemctl", "is-active", service], timeout=5)
        enabled = run_command(["systemctl", "is-enabled", service], timeout=5)
        if active.ok or enabled.ok or active.stdout.strip() or enabled.stdout.strip():
            found.append(format_service_status(service, active, enabled))
    return CheckResult("services", Severity.OK, f"Important system services found: {len(found)}", "; ".join(found))


def summarize_listening_sockets(output: str) -> tuple[int, int]:
    tcp = 0
    udp = 0
    for line in output.splitlines()[1:]:
        first = line.split(maxsplit=1)[0].lower() if line.split() else ""
        if first.startswith("tcp"):
            tcp += 1
        elif first.startswith("udp"):
            udp += 1
    return tcp, udp


def format_service_status(service: str, active, enabled) -> str:
    active_value = active.stdout.strip() if active.stdout.strip() else "unknown"
    enabled_value = enabled.stdout.strip() if enabled.stdout.strip() else "unknown"
    return f"{service}: active={active_value}, enabled={enabled_value}"


def format_report(results: list[CheckResult]) -> str:
    fatal = [result for result in results if result.severity == Severity.ERROR]
    warnings = [result for result in results if result.severity == Severity.WARN]
    lines = [result.format() for result in results]
    lines.append("")
    lines.append(f"Fatal errors: {len(fatal)}")
    lines.append(f"Warnings: {len(warnings)}")
    return "\n".join(lines)
