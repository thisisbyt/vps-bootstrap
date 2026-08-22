from __future__ import annotations

import os
import pwd
import random
import re
import shutil
import time
import unicodedata
from glob import glob
from dataclasses import dataclass, field
from pathlib import Path

from app.command import CommandResult, run_command
from app.filesystem import has_mode, write_atomic


MANAGED_SSHD_DROPIN = Path("/etc/ssh/sshd_config.d/10-vps-bootstrap.conf")
SSH_SOCKET_OVERRIDE = Path("/etc/systemd/system/ssh.socket.d/10-vps-bootstrap.conf")
SSHD_CONFIG = Path("/etc/ssh/sshd_config")
SSHD_CONFIG_D = Path("/etc/ssh/sshd_config.d")
SSH_SERVICE = "ssh.service"
SSH_SOCKET = "ssh.socket"
RANDOM_PORT_MIN = 20000
RANDOM_PORT_MAX = 60000
KNOWN_RESERVED_PORTS = {22, 80, 443, 5432}


class SSHHardeningError(RuntimeError):
    def __init__(self, message: str, diagnostics: list[str] | None = None) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics or ssh_diagnostics()


@dataclass(frozen=True)
class TCPListener:
    local_address: str
    port: int
    process: str = ""

    @property
    def looks_like_sshd(self) -> bool:
        return "sshd" in self.process.lower()

    @property
    def looks_like_systemd(self) -> bool:
        return "systemd" in self.process.lower()


@dataclass(frozen=True)
class SystemdUnitState:
    active: str = "unknown"
    enabled: str = "unknown"
    unit_file: str = ""
    triggered_by: str = ""
    listen_streams: list[int] = field(default_factory=list)


@dataclass(frozen=True)
class SSHDiscovery:
    openssh_server_installed: bool
    sshd_path: str
    service: SystemdUnitState
    socket: SystemdUnitState
    activation_mode: str
    effective_config: dict[str, list[str]]
    tcp_listeners: list[TCPListener]
    actual_listeners: set[int]
    actual_ssh_listeners: set[int]
    configured_ports: set[int]
    include_files: list[str]
    sshd_config_files: list[str]
    complex_config_reasons: list[str]
    managed_dropin_exists: bool
    systemd_overrides: list[str]
    current_user: str
    in_ssh_session: bool
    ssh_connection: str
    admin_user: str
    admin_authorized_keys_exists: bool
    admin_authorized_keys_count: int
    admin_ssh_permissions_ok: bool
    sudo_non_root_user_exists: bool
    ufw_installed: bool
    ufw_active: bool
    ufw_allowed_ports: set[int]


@dataclass(frozen=True)
class SSHPlan:
    old_ports: set[int]
    target_ports: set[int]
    final_ports: set[int]
    activation_mode: str
    auth_values: dict[str, str]
    transition_auth_values: dict[str, str] = field(default_factory=dict)
    requires_publickey_confirmation: bool = False
    blocked_reasons: list[str] = field(default_factory=list)
    requires_two_port_confirmation: bool = False
    requires_sudo_confirmation: bool = False


def parse_sshd_t(output: str) -> dict[str, list[str]]:
    config: dict[str, list[str]] = {}
    for line in output.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        key = parts[0].lower()
        value = " ".join(parts[1:])
        config.setdefault(key, []).append(value)
    return config


def effective_ports(config: dict[str, list[str]]) -> set[int]:
    values = config.get("port") or ["22"]
    return {int(value) for value in values if value.isdigit()}


def parse_ss_tcp_listeners(output: str) -> list[TCPListener]:
    listeners: list[TCPListener] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("state "):
            continue
        parts = stripped.split()
        state_index = 1 if parts[0].lower().startswith("tcp") else 0
        if len(parts) <= state_index + 4 or parts[state_index].upper() != "LISTEN":
            continue
        local = parts[state_index + 3]
        port = parse_listener_port(local)
        if port is None:
            continue
        process = " ".join(parts[state_index + 5:]) if len(parts) > state_index + 5 else ""
        listeners.append(TCPListener(local, port, process))
    return listeners


def parse_ss_listeners(output: str) -> set[int]:
    return {listener.port for listener in parse_ss_tcp_listeners(output)}


def parse_listener_port(local_address: str) -> int | None:
    text = local_address.strip()
    if text.startswith("[") and "]:" in text:
        port_text = text.rsplit("]:", 1)[1]
    elif ":" in text:
        port_text = text.rsplit(":", 1)[1]
    else:
        return None
    return int(port_text) if port_text.isdigit() else None


def parse_socket_listen_streams(output: str) -> list[int]:
    ports: list[int] = []
    for line in output.splitlines():
        if "ListenStream=" not in line:
            continue
        value = line.split("ListenStream=", 1)[1].strip()
        if value == "":
            ports = []
            continue
        if value.isdigit():
            ports.append(int(value))
    return ports


def parse_systemctl_show_listen_ports(output: str) -> list[int]:
    ports: list[int] = []
    for line in output.splitlines():
        if not line.startswith("Listen="):
            continue
        for match in re.finditer(r"(?:\[?[0-9a-fA-F:.]*\]?:)?(\d{1,5})\s*\(Stream\)", line):
            port = int(match.group(1))
            if 1 <= port <= 65535:
                ports.append(port)
    return ports


def parse_ufw_allowed_ports(output: str) -> set[int]:
    allowed: set[int] = set()
    for line in output.splitlines():
        match = re.search(r"\b(\d{1,5})/tcp\b", line)
        if match:
            allowed.add(int(match.group(1)))
    return allowed


def service_value(unit: str, property_name: str = "") -> str:
    args = ["systemctl", "show", unit, "--no-pager"]
    if property_name:
        args.append(f"--property={property_name}")
    result = run_command(args, timeout=5)
    if not result.ok:
        return ""
    if property_name and "=" in result.stdout:
        return result.stdout.split("=", 1)[1].strip()
    return result.stdout


def unit_state(unit: str) -> SystemdUnitState:
    active = run_command(["systemctl", "is-active", unit], timeout=5)
    enabled = run_command(["systemctl", "is-enabled", unit], timeout=5)
    unit_file = run_command(["systemctl", "cat", unit], timeout=5)
    show = run_command(["systemctl", "show", unit, "--property=TriggeredBy", "--property=Listen", "--no-pager"], timeout=5)
    triggered_by = ""
    listens = []
    if show.ok:
        triggered_by = extract_property(show.stdout, "TriggeredBy")
        listens = parse_systemctl_show_listen_ports(show.stdout) or parse_socket_listen_streams(f"{unit_file.stdout}\n{show.stdout}")
    return SystemdUnitState(active.stdout or "unknown", enabled.stdout or "unknown", unit_file.stdout, triggered_by, listens)


def extract_property(output: str, name: str) -> str:
    for line in output.splitlines():
        if line.startswith(f"{name}="):
            return line.split("=", 1)[1].strip()
    return ""


def detect_activation_mode(service: SystemdUnitState, socket: SystemdUnitState, overrides: list[str]) -> str:
    if overrides:
        return "custom"
    if socket.active == "active" or socket.enabled in {"enabled", "static"} or socket.listen_streams:
        return "socket"
    if service.active == "active" or service.enabled == "enabled":
        return "service"
    return "custom"


def discover_ssh() -> SSHDiscovery:
    sshd_path = shutil.which("sshd") or "/usr/sbin/sshd"
    installed = bool(shutil.which("sshd")) or Path("/usr/sbin/sshd").exists()
    service = unit_state(SSH_SERVICE)
    socket = unit_state(SSH_SOCKET)
    overrides = discover_systemd_overrides()
    activation = detect_activation_mode(service, socket, overrides)
    sshd_t = run_command([sshd_path, "-T"], timeout=10)
    effective = parse_sshd_t(sshd_t.stdout) if sshd_t.ok else {}
    ss = run_command(["ss", "-H", "-lntp"], timeout=5)
    tcp_listeners = parse_ss_tcp_listeners(ss.stdout) if ss.ok else []
    listeners = {listener.port for listener in tcp_listeners}
    ssh_listener_ports = actual_ssh_listener_ports(tcp_listeners, activation, socket.listen_streams)
    current_user = detect_current_user()
    admin_user = current_user if current_user != "root" else detect_sudo_non_root_user() or "root"
    keys = inspect_authorized_keys(admin_user)
    ufw_status = run_command(["ufw", "status"], timeout=5) if shutil.which("ufw") else CommandResult(["ufw"], 127, "", "")
    sshd_files, include_reasons = list_sshd_config_files()
    complex_reasons = include_reasons + detect_complex_ssh_config(sshd_files)
    return SSHDiscovery(
        openssh_server_installed=installed,
        sshd_path=sshd_path,
        service=service,
        socket=socket,
        activation_mode=activation,
        effective_config=effective,
        tcp_listeners=tcp_listeners,
        actual_listeners=listeners,
        actual_ssh_listeners=ssh_listener_ports,
        configured_ports=effective_ports(effective),
        include_files=effective.get("include", []),
        sshd_config_files=[str(path) for path in sshd_files],
        complex_config_reasons=complex_reasons,
        managed_dropin_exists=MANAGED_SSHD_DROPIN.exists(),
        systemd_overrides=overrides,
        current_user=current_user,
        in_ssh_session=bool(os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_CLIENT")),
        ssh_connection=os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_CLIENT", ""),
        admin_user=admin_user,
        admin_authorized_keys_exists=keys[0],
        admin_authorized_keys_count=keys[1],
        admin_ssh_permissions_ok=keys[2],
        sudo_non_root_user_exists=bool(detect_sudo_non_root_user()),
        ufw_installed=bool(shutil.which("ufw")),
        ufw_active=ufw_status.ok and "Status: active" in ufw_status.stdout,
        ufw_allowed_ports=parse_ufw_allowed_ports(ufw_status.stdout),
    )


def actual_ssh_listener_ports(listeners: list[TCPListener], activation: str, socket_ports: list[int]) -> set[int]:
    ports: set[int] = set()
    socket_port_set = set(socket_ports)
    for listener in listeners:
        if listener.looks_like_sshd:
            ports.add(listener.port)
        elif activation == "socket" and listener.port in socket_port_set and listener.looks_like_systemd:
            ports.add(listener.port)
    return ports


def list_sshd_config_files() -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    reasons: list[str] = []
    visited: set[Path] = set()

    def add_file(path: Path, depth: int) -> None:
        resolved = path.resolve()
        if resolved in visited:
            return
        if depth > 8:
            reasons.append(f"Include recursion depth exceeded at {path}")
            return
        if not path.exists():
            reasons.append(f"Included SSH config does not exist: {path}")
            return
        if not path.is_file():
            reasons.append(f"Included SSH config is not a regular file: {path}")
            return
        visited.add(resolved)
        files.append(path)
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            reasons.append(f"Cannot read included SSH config {path}: {exc}")
            return
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if not parts or parts[0].lower() != "include":
                continue
            for pattern in parts[1:]:
                include_pattern = Path(pattern)
                if not include_pattern.is_absolute():
                    include_pattern = path.parent / include_pattern
                matches = sorted(Path(match) for match in glob(str(include_pattern)))
                if not matches:
                    reasons.append(f"Include pattern did not match: {pattern} in {path}")
                    continue
                for match in matches:
                    add_file(match, depth + 1)

    if SSHD_CONFIG.exists():
        add_file(SSHD_CONFIG, 0)
    if SSHD_CONFIG_D.is_dir():
        for item in sorted(SSHD_CONFIG_D.glob("*.conf")):
            add_file(item, 0)
    return files, reasons


def detect_complex_ssh_config(files: list[Path]) -> list[str]:
    reasons: list[str] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            key = stripped.split(None, 1)[0].lower()
            if key == "match":
                reasons.append(f"Match block in {path}")
            elif key == "authenticationmethods":
                reasons.append(f"AuthenticationMethods in {path}")
            elif key in {"allowusers", "allowgroups", "denyusers", "denygroups"}:
                reasons.append(f"{key} in {path}")
    early_dropins = [path for path in files if path.parent.name == "sshd_config.d" and path.name < MANAGED_SSHD_DROPIN.name and path.name.endswith(".conf")]
    if early_dropins:
        reasons.append("Earlier sshd_config.d drop-in may override first-value settings: " + ", ".join(str(path) for path in early_dropins))
    return reasons


def discover_systemd_overrides() -> list[str]:
    roots = [
        Path("/etc/systemd/system/ssh.socket.d"),
        Path("/etc/systemd/system/ssh.service.d"),
        Path("/run/systemd/system/ssh.socket.d"),
        Path("/run/systemd/system/ssh.service.d"),
    ]
    overrides: list[str] = []
    for root in roots:
        if not root.is_dir():
            continue
        for item in root.glob("*.conf"):
            if item != SSH_SOCKET_OVERRIDE:
                overrides.append(str(item))
    return sorted(overrides)


def detect_current_user() -> str:
    for key in ("SUDO_USER", "USER", "LOGNAME"):
        value = os.environ.get(key)
        if value:
            return value
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return "root"


def detect_sudo_non_root_user() -> str | None:
    for line in Path("/etc/passwd").read_text(encoding="utf-8").splitlines() if Path("/etc/passwd").exists() else []:
        parts = line.split(":")
        if len(parts) < 7 or parts[0] == "root":
            continue
        groups = run_command(["id", "-nG", parts[0]], timeout=5)
        if groups.ok and "sudo" in groups.stdout.split():
            return parts[0]
    return None


def inspect_authorized_keys(user: str) -> tuple[bool, int, bool]:
    try:
        home = Path(pwd.getpwnam(user).pw_dir)
    except KeyError:
        return False, 0, False
    ssh_dir = home / ".ssh"
    keys = ssh_dir / "authorized_keys"
    if not keys.exists():
        return False, 0, False
    count = sum(1 for line in keys.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip() and not line.strip().startswith("#"))
    perms_ok = has_mode(ssh_dir, 0o700) and has_mode(keys, 0o600)
    return True, count, perms_ok


def choose_random_port(occupied_ports: set[int], reserved_ports: set[int] | None = None) -> int:
    blocked = occupied_ports | (reserved_ports or KNOWN_RESERVED_PORTS)
    candidates = [port for port in range(RANDOM_PORT_MIN, RANDOM_PORT_MAX + 1) if port not in blocked]
    if not candidates:
        raise SSHHardeningError("No free high SSH port candidate is available.")
    return random.SystemRandom().choice(candidates)


def validate_port(port: int, occupied_ports: set[int]) -> None:
    if port < 1 or port > 65535:
        raise SSHHardeningError("SSH port must be in range 1..65535.")
    if port in occupied_ports:
        raise SSHHardeningError(f"SSH port {port} is already used by another listener.")


def build_ssh_plan(
    discovery: SSHDiscovery,
    selected_port: int | None,
    keep_current_port: bool = False,
    publickey_confirmed: bool = False,
    request_root_disable: bool = False,
    sudo_confirmed: bool = False,
) -> SSHPlan:
    if not discovery.openssh_server_installed:
        return SSHPlan(set(), set(), set(), discovery.activation_mode, {}, blocked_reasons=["openssh-server is not installed"])
    if discovery.activation_mode == "custom":
        return SSHPlan(
            discovery.configured_ports,
            discovery.configured_ports,
            discovery.configured_ports,
            "custom",
            {},
            blocked_reasons=["custom or ambiguous SSH systemd configuration"],
        )

    old_ports = discovery.configured_ports or {22}
    final_ports = set(old_ports) if keep_current_port or selected_port is None else {selected_port}
    transition_ports = old_ports | final_ports
    blocked: list[str] = []
    if selected_port is not None:
        validate_port(selected_port, discovery.actual_listeners - old_ports)
        if discovery.ufw_active and selected_port not in discovery.ufw_allowed_ports:
            blocked.append(f"UFW is active and port {selected_port}/tcp is not allowed")

    transition_auth = current_auth_values(discovery)
    final_auth = propose_auth_values(discovery, publickey_confirmed=publickey_confirmed, request_root_disable=request_root_disable, sudo_confirmed=sudo_confirmed)
    if publickey_confirmed and transition_auth.get("PubkeyAuthentication", "").lower() == "no":
        transition_auth["PubkeyAuthentication"] = "yes"
    root_disable_requested = final_auth.get("PermitRootLogin") == "no"
    if request_root_disable and not discovery.sudo_non_root_user_exists:
        blocked.append("PermitRootLogin no blocked: no discovered sudo-capable non-root user")
    if auth_hardening_requested(transition_auth, final_auth) and not publickey_confirmed:
        blocked.append("Auth hardening requires explicit publickey-only second-session confirmation")
    if auth_hardening_requested(transition_auth, final_auth) and discovery.complex_config_reasons:
        blocked.append("Auth hardening blocked by complex SSH config: " + "; ".join(discovery.complex_config_reasons))

    return SSHPlan(
        old_ports=old_ports,
        target_ports=transition_ports,
        final_ports=final_ports,
        activation_mode=discovery.activation_mode,
        auth_values=final_auth,
        transition_auth_values=transition_auth,
        requires_publickey_confirmation=auth_hardening_requested(current_auth_values(discovery), final_auth),
        blocked_reasons=blocked,
        requires_two_port_confirmation=final_ports != old_ports,
        requires_sudo_confirmation=root_disable_requested and not sudo_confirmed,
    )


def current_auth_values(discovery: SSHDiscovery) -> dict[str, str]:
    current = lambda key, default: (discovery.effective_config.get(key.lower()) or [default])[0]
    return {
        "PubkeyAuthentication": current("pubkeyauthentication", "yes"),
        "PasswordAuthentication": current("passwordauthentication", "yes"),
        "KbdInteractiveAuthentication": current("kbdinteractiveauthentication", "yes"),
        "PermitRootLogin": current("permitrootlogin", "prohibit-password"),
    }


def propose_auth_values(discovery: SSHDiscovery, publickey_confirmed: bool = False, request_root_disable: bool = False, sudo_confirmed: bool = False) -> dict[str, str]:
    values = current_auth_values(discovery)
    if publickey_confirmed:
        values["PubkeyAuthentication"] = "yes"
        values["PasswordAuthentication"] = "no"
        values["KbdInteractiveAuthentication"] = "no"
    if discovery.sudo_non_root_user_exists and discovery.admin_user != "root" and publickey_confirmed and request_root_disable and sudo_confirmed:
        values["PermitRootLogin"] = "no"
    elif discovery.sudo_non_root_user_exists and discovery.admin_user != "root" and publickey_confirmed and request_root_disable:
        values["PermitRootLogin"] = "no"
    return values


def auth_hardening_requested(current: dict[str, str], final: dict[str, str]) -> bool:
    sensitive_keys = ("PubkeyAuthentication", "PasswordAuthentication", "KbdInteractiveAuthentication", "PermitRootLogin")
    return any(current.get(key, "").lower() != final.get(key, "").lower() for key in sensitive_keys)


def render_sshd_dropin(ports: set[int], auth_values: dict[str, str]) -> str:
    lines = ["# Managed by vps-bootstrap. Do not edit this file directly."]
    for port in sorted(ports):
        lines.append(f"Port {port}")
    for key in ("PubkeyAuthentication", "PasswordAuthentication", "KbdInteractiveAuthentication", "PermitRootLogin"):
        value = auth_values.get(key)
        if value:
            lines.append(f"{key} {value}")
    return "\n".join(lines) + "\n"


def render_socket_override(ports: set[int]) -> str:
    lines = ["# Managed by vps-bootstrap. Do not edit this file directly.", "[Socket]", "ListenStream="]
    lines.extend(f"ListenStream={port}" for port in sorted(ports))
    return "\n".join(lines) + "\n"


def verify_expected_ssh_state(data: dict) -> bool:
    if not data:
        return False
    discovery = discover_ssh()
    return verify_discovered_ssh_state(discovery, data)


def verify_discovered_ssh_state(discovery: SSHDiscovery, data: dict) -> bool:
    expected_ports = {int(port) for port in data.get("ports", [])}
    if not expected_ports:
        return False
    syntax = run_command([discovery.sshd_path, "-t"], timeout=10)
    if not syntax.ok:
        return False
    if discovery.configured_ports != expected_ports:
        return False
    expected_activation = data.get("activation_mode")
    old_ports = {int(port) for port in data.get("old_ports", [])}
    stale_old_ports = old_ports - expected_ports
    if expected_activation == "socket":
        if discovery.socket.active != "active":
            return False
        socket_ports = set(discovery.socket.listen_streams)
        if socket_ports != expected_ports:
            return False
        if stale_old_ports & socket_ports:
            return False
        if stale_old_ports & discovery.actual_ssh_listeners:
            return False
        if discovery.actual_ssh_listeners != expected_ports:
            return False
    if expected_activation == "service" and discovery.service.active != "active":
        return False
    if expected_activation == "service":
        if discovery.actual_ssh_listeners != expected_ports:
            return False
        if stale_old_ports & discovery.actual_ssh_listeners:
            return False
    for key, expected in data.get("auth_values", {}).items():
        actual = (discovery.effective_config.get(key.lower()) or [""])[0].lower()
        if actual != str(expected).lower():
            return False
    if data.get("managed_dropin") and not MANAGED_SSHD_DROPIN.exists():
        return False
    return True


def ensure_ssh_hardening_from_state(data: dict, save_state=None, force_reconfigure: bool = False) -> dict:
    if data and data.get("mode") == "migration" and data.get("interrupted_migration"):
        recovered = recover_interrupted_migration(data)
        if save_state:
            save_state(recovered)
        if recovered.get("mode") == "skipped":
            return recovered
        raise SSHHardeningError("Interrupted SSH migration requires manual validation or rollback before resume can continue.")
    discovery = discover_ssh()
    if data and data.get("mode") == "managed" and not force_reconfigure:
        apply_ssh_plan_data(data)
        return data

    print_ssh_summary(discovery)
    print("[1] Change to random high port (recommended)")
    print("[2] Keep current port")
    print("[3] Specify custom port")
    print("Default is [2] keep current port for safety; choose [1] to apply the recommended random high port migration.")
    choice = input("Select option [2]: ").strip() or "2"
    selected_port: int | None = None
    keep = choice == "2"
    if choice == "1":
        selected_port = choose_random_port(discovery.actual_listeners | discovery.configured_ports)
        print(f"Selected SSH port: {selected_port}")
        if not confirm("Apply this SSH port? [y/N]: "):
            return {"mode": "skipped", "reason": "user did not confirm SSH port change"}
    elif choice == "3":
        raw = input("SSH port: ").strip()
        if not raw.isdigit():
            raise SSHHardeningError("SSH port must be numeric.")
        selected_port = int(raw)
    request_auth_hardening = confirm("Attempt auth hardening after publickey-only second-session validation? [y/N]: ")
    request_root_disable = False
    if request_auth_hardening and discovery.sudo_non_root_user_exists and discovery.admin_user != "root":
        request_root_disable = confirm("Also disable root SSH login after publickey-only login and sudo validation? [y/N]: ")
    plan = build_ssh_plan(discovery, selected_port, keep, publickey_confirmed=request_auth_hardening, request_root_disable=request_root_disable)
    if plan.blocked_reasons:
        raise SSHHardeningError("SSH hardening blocked: " + "; ".join(plan.blocked_reasons))
    print_ssh_plan(plan)
    if not confirm("Apply SSH hardening? [y/N]: "):
        return {"mode": "skipped", "reason": "user did not confirm SSH hardening"}
    data = apply_ssh_plan(plan, save_state=save_state, discovery=discovery)
    return data


def recover_interrupted_migration(data: dict) -> dict:
    print("Interrupted SSH migration detected.")
    print(f"Stage: {data.get('migration_stage', 'unknown')}")
    print(f"Old ports: {data.get('old_ports', [])}")
    print("")
    print("[1] Leave current SSH state unchanged and exit (default/safest)")
    print("[2] Roll back to pre-migration SSH state using saved backups")
    choice = input("Select option [1]: ").strip() or "1"
    if choice != "2":
        raise SSHHardeningError("Interrupted SSH migration left unchanged by user choice.")
    activation = str(data.get("activation_mode"))
    validate_activation_mode(activation)
    old_ports = {int(port) for port in data.get("old_ports", [])}
    if not old_ports:
        raise SSHHardeningError("Interrupted SSH migration rollback blocked: old ports are missing from state.")
    backups = backup_paths_from_metadata(data.get("backup_metadata", {}), activation)
    rollback_ssh(backups, activation, old_ports)
    return {
        "mode": "skipped",
        "reason": "interrupted SSH migration rolled back; run vps-bootstrap ssh explicitly to retry",
        "interrupted_migration": False,
        "rollback_completed": True,
        "old_ports": sorted(old_ports),
        "activation_mode": activation,
    }


def print_ssh_summary(discovery: SSHDiscovery) -> None:
    auth = discovery.effective_config
    print("Current SSH:")
    print(f"  Ports: {sorted(discovery.configured_ports or {22})}")
    print(f"  Actual listeners: {sorted(discovery.actual_listeners)}")
    print(f"  Activation mode: {discovery.activation_mode}")
    for key in ["pubkeyauthentication", "passwordauthentication", "kbdinteractiveauthentication", "permitrootlogin"]:
        print(f"  {key}: {(auth.get(key) or ['unknown'])[0]}")


def print_ssh_plan(plan: SSHPlan) -> None:
    print("Proposed SSH hardening:")
    print("Transition:")
    print(f"  Ports: {sorted(plan.target_ports)}")
    print(f"  Auth policy: {plan.transition_auth_values}")
    print("Final:")
    print(f"  Ports: {sorted(plan.final_ports)}")
    print(f"  Auth policy: {plan.auth_values}")
    print(f"Activation mode: {plan.activation_mode}")
    print("Potential risks:")
    print("  SSH changes can lock you out if provider firewall/security group blocks the new port.")
    print("  DO NOT CLOSE THE CURRENT SSH SESSION until a second SSH session is verified.")


def apply_ssh_plan(plan: SSHPlan, save_state=None, discovery: SSHDiscovery | None = None) -> dict:
    validate_activation_mode(plan.activation_mode)
    no_port_change = plan.target_ports == plan.old_ports == plan.final_ports
    if no_port_change and not plan.requires_publickey_confirmation:
        final_state = {
            "mode": "managed",
            "ports": sorted(plan.final_ports),
            "old_ports": sorted(plan.old_ports),
            "activation_mode": plan.activation_mode,
            "auth_values": plan.auth_values,
            "interrupted_migration": False,
        }
        verified = verify_discovered_ssh_state(discovery, final_state) if discovery else verify_expected_ssh_state(final_state)
        if not verified:
            raise SSHHardeningError("Current SSH state did not pass verification; no changes were applied.")
        save_migration_state(save_state, final_state)
        return final_state
    migration_state = {
        "mode": "migration",
        "interrupted_migration": True,
        "old_ports": sorted(plan.old_ports),
        "transition_ports": sorted(plan.target_ports),
        "new_port": next(iter(plan.final_ports - plan.old_ports), None),
        "activation_mode": plan.activation_mode,
        "transition_auth_values": plan.transition_auth_values,
        "final_auth_values": plan.auth_values,
        "migration_stage": "planned",
    }
    save_migration_state(save_state, migration_state)
    backups = backup_ssh_files(plan.activation_mode)
    migration_state["backup_metadata"] = backup_metadata(backups)
    save_migration_state(save_state, migration_state)
    rolled_back = False
    try:
        migration_state["migration_stage"] = "transition_applying"
        save_migration_state(save_state, migration_state)
        write_atomic(MANAGED_SSHD_DROPIN, render_sshd_dropin(plan.target_ports, plan.transition_auth_values), 0o600)
        if plan.activation_mode == "socket":
            write_atomic(SSH_SOCKET_OVERRIDE, render_socket_override(plan.target_ports), 0o600)
        validate_candidate_effective(plan.target_ports, plan.transition_auth_values, discovery.sshd_path if discovery else "sshd")
        apply_systemd_ssh(plan.activation_mode)
        if not verify_transition_listeners(plan.target_ports, plan.activation_mode):
            raise SSHHardeningError("New SSH listener did not appear after applying transition config.")
        migration_state["migration_stage"] = "transition_active"
        save_migration_state(save_state, migration_state)
        if plan.requires_two_port_confirmation:
            migration_state["migration_stage"] = "awaiting_second_session"
            save_migration_state(save_state, migration_state)
            print("\nНЕ ЗАКРЫВАЙТЕ ТЕКУЩУЮ SSH-СЕССИЮ")
            print("Open a SECOND terminal and connect using:")
            print(f"  {second_session_validation_command(plan, discovery)}")
            print("If provider firewall/security group exists, allow NEW_PORT/TCP there first.")
            if plan.requires_publickey_confirmation:
                prompt = "Successfully logged in via the new SSH port using the publickey-only command? [y/N]: "
            else:
                prompt = "Successfully logged in via the new SSH port? [y/N]: "
            if not confirm(prompt):
                rollback_ssh(backups, plan.activation_mode, plan.old_ports)
                rolled_back = True
                save_automatic_rollback_state(save_state, migration_state, plan)
                raise SSHHardeningError("New SSH login was not confirmed; old SSH state was restored.")
            if plan.requires_sudo_confirmation:
                print_sudo_validation_instruction()
                if not confirm("Did publickey-only login AND sudo validation succeed? [y/N]: "):
                    rollback_ssh(backups, plan.activation_mode, plan.old_ports)
                    rolled_back = True
                    save_automatic_rollback_state(save_state, migration_state, plan)
                    raise SSHHardeningError("Sudo validation was not confirmed; root SSH login was not disabled.")
        elif plan.requires_publickey_confirmation:
            print("\nPublickey-only validation is required before auth hardening.")
            print(f"  {second_session_validation_command(plan, discovery)}")
            if not confirm("Did the publickey-only second SSH session succeed? [y/N]: "):
                rollback_ssh(backups, plan.activation_mode, plan.old_ports)
                rolled_back = True
                save_automatic_rollback_state(save_state, migration_state, plan)
                raise SSHHardeningError("Publickey-only SSH login was not confirmed; auth hardening was not applied.")
            if plan.requires_sudo_confirmation:
                print_sudo_validation_instruction()
                if not confirm("Did publickey-only login AND sudo validation succeed? [y/N]: "):
                    rollback_ssh(backups, plan.activation_mode, plan.old_ports)
                    rolled_back = True
                    save_automatic_rollback_state(save_state, migration_state, plan)
                    raise SSHHardeningError("Sudo validation was not confirmed; root SSH login was not disabled.")
        if plan.requires_two_port_confirmation or plan.requires_publickey_confirmation:
            migration_state["migration_stage"] = "finalizing"
            save_migration_state(save_state, migration_state)
            write_atomic(MANAGED_SSHD_DROPIN, render_sshd_dropin(plan.final_ports, plan.auth_values), 0o600)
            if plan.activation_mode == "socket":
                write_atomic(SSH_SOCKET_OVERRIDE, render_socket_override(plan.final_ports), 0o600)
            validate_candidate_effective(plan.final_ports, plan.auth_values, discovery.sshd_path if discovery else "sshd")
            apply_systemd_ssh(plan.activation_mode)
        final_state = {
            "mode": "managed",
            "ports": sorted(plan.final_ports),
            "old_ports": sorted(plan.old_ports),
            "activation_mode": plan.activation_mode,
            "auth_values": plan.auth_values,
            "managed_dropin": str(MANAGED_SSHD_DROPIN),
            "interrupted_migration": False,
        }
        if not verify_expected_ssh_state(final_state):
            raise SSHHardeningError("Final SSH verifier detected configured/effective/actual mismatch.")
        save_migration_state(save_state, {**final_state, "migration_stage": "done"})
        return final_state
    except (Exception, KeyboardInterrupt):
        if not rolled_back:
            rollback_ssh(backups, plan.activation_mode, plan.old_ports)
            save_automatic_rollback_state(save_state, migration_state, plan)
        raise


def save_migration_state(callback, data: dict) -> None:
    if callback:
        callback(dict(data))


def save_automatic_rollback_state(callback, migration_state: dict, plan: SSHPlan) -> None:
    rolled_back_state = {
        **migration_state,
        "interrupted_migration": False,
        "migration_stage": "rolled_back",
        "rolled_back": True,
        "ports": sorted(plan.old_ports),
        "old_ports": sorted(plan.old_ports),
        "transition_ports": sorted(plan.target_ports),
        "activation_mode": plan.activation_mode,
    }
    save_migration_state(callback, rolled_back_state)


def backup_paths_from_metadata(metadata: dict, activation: str) -> dict[str, Path | None]:
    validate_activation_mode(activation)
    if not isinstance(metadata, dict):
        raise SSHHardeningError("Interrupted SSH migration rollback blocked: backup metadata is missing.")
    required_keys = ["dropin"] + (["socket"] if activation == "socket" else [])
    for key in required_keys:
        if key not in metadata:
            raise SSHHardeningError(f"Interrupted SSH migration rollback blocked: backup metadata key is missing: {key}")
    backups = {
        "dropin": trusted_backup_path(metadata.get("dropin"), MANAGED_SSHD_DROPIN),
        "socket": None,
    }
    if activation == "socket":
        backups["socket"] = trusted_backup_path(metadata.get("socket"), SSH_SOCKET_OVERRIDE)
    return backups


def trusted_backup_path(value, target: Path) -> Path | None:
    if value is None:
        return None
    path = Path(str(value))
    expected_prefix = f"{target.name}.bak-"
    try:
        trusted_parent = path.parent.resolve() == target.parent.resolve()
    except OSError as exc:
        raise SSHHardeningError(f"Interrupted SSH migration rollback blocked: cannot validate backup path {path}: {exc}") from exc
    if not path.is_absolute() or not trusted_parent or not path.name.startswith(expected_prefix):
        raise SSHHardeningError(f"Interrupted SSH migration rollback blocked: untrusted backup path {path}")
    if not path.exists() or not path.is_file():
        raise SSHHardeningError(f"Interrupted SSH migration rollback blocked: backup file does not exist: {path}")
    return path


def validate_activation_mode(activation: str) -> None:
    if activation not in {"socket", "service"}:
        raise SSHHardeningError(f"Unsupported SSH activation mode for managed operation: {activation or 'missing'}")


def backup_metadata(backups: dict[str, Path | None]) -> dict[str, str | None]:
    return {name: str(path) if path else None for name, path in backups.items()}


def validate_candidate_effective(expected_ports: set[int], expected_auth: dict[str, str], sshd_path: str = "sshd") -> None:
    syntax = run_command([sshd_path, "-t"], timeout=10)
    if not syntax.ok:
        raise SSHHardeningError(f"sshd -t failed before restart: {syntax.stderr or syntax.stdout}")
    effective = run_command([sshd_path, "-T"], timeout=10)
    if not effective.ok:
        raise SSHHardeningError(f"sshd -T failed before restart: {effective.stderr or effective.stdout}")
    parsed = parse_sshd_t(effective.stdout)
    ports = effective_ports(parsed)
    if ports != expected_ports:
        raise SSHHardeningError(f"Candidate effective ports mismatch: expected {sorted(expected_ports)}, got {sorted(ports)}")
    for key, expected in expected_auth.items():
        actual = (parsed.get(key.lower()) or [""])[0].lower()
        if actual != str(expected).lower():
            raise SSHHardeningError(f"Candidate effective {key} mismatch: expected {expected}, got {actual or 'unset'}")


def second_session_validation_command(plan: SSHPlan, discovery: SSHDiscovery | None) -> str:
    port = next(iter(plan.final_ports))
    if plan.requires_publickey_confirmation:
        return publickey_only_second_session_command(discovery, port)
    return ordinary_second_session_command(discovery, port)


def ordinary_second_session_command(discovery: SSHDiscovery | None, port: int) -> str:
    return f"ssh -p {port} {ssh_target(discovery)}"


def publickey_only_second_session_command(discovery: SSHDiscovery | None, port: int) -> str:
    return f"ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no -p {port} {ssh_target(discovery)}"


def second_session_command(discovery: SSHDiscovery | None, port: int) -> str:
    return publickey_only_second_session_command(discovery, port)


def ssh_target(discovery: SSHDiscovery | None) -> str:
    user = discovery.admin_user if discovery and discovery.admin_user else "USER"
    host = server_address_from_ssh_connection(discovery.ssh_connection if discovery else "")
    return f"{user}@{format_ssh_host(host)}" if host else f"{user}@SERVER_IP"


def parse_confirmation(value: str, default: bool = False) -> bool | None:
    normalized = unicodedata.normalize("NFKC", value).strip().lower()
    if not normalized:
        return default
    if normalized in {"y", "yes"}:
        return True
    if normalized in {"n", "no"}:
        return False
    return None


def confirm(prompt: str, default: bool = False) -> bool:
    while True:
        try:
            value = input(prompt)
        except EOFError:
            return default
        parsed = parse_confirmation(value, default=default)
        if parsed is not None:
            return parsed
        print(f"Unrecognized confirmation input (code points: {format_codepoints(value)}).")
        print("Please enter y/yes or n/no.")


def format_codepoints(value: str) -> str:
    return " ".join(f"U+{ord(char):04X}" for char in value) or "<empty>"


def print_sudo_validation_instruction() -> None:
    print("\nBefore disabling root SSH login, verify sudo in the SECOND session:")
    print("  sudo -v")
    print("  sudo -n true")


def server_address_from_ssh_connection(value: str) -> str:
    parts = value.split()
    return parts[2] if len(parts) >= 4 else ""


def format_ssh_host(host: str) -> str:
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        return f"[{host}]"
    return host


def apply_ssh_plan_data(data: dict) -> None:
    if data.get("interrupted_migration"):
        raise SSHHardeningError("Interrupted SSH migration requires manual confirmation; old port will not be disabled automatically.")
    ports = {int(port) for port in data.get("ports", [])}
    auth_values = dict(data.get("auth_values", {}))
    activation = str(data.get("activation_mode"))
    validate_activation_mode(activation)
    original = discover_ssh()
    original_ports = original.actual_ssh_listeners or original.configured_ports or ports
    backups = backup_ssh_files(activation)
    try:
        write_atomic(MANAGED_SSHD_DROPIN, render_sshd_dropin(ports, auth_values), 0o600)
        if activation == "socket":
            write_atomic(SSH_SOCKET_OVERRIDE, render_socket_override(ports), 0o600)
        validate_candidate_effective(ports, auth_values, original.sshd_path)
        apply_systemd_ssh(activation)
        if not verify_transition_listeners(ports, activation):
            raise SSHHardeningError("Expected SSH listener is not active.")
    except Exception:
        rollback_ssh(backups, activation, original_ports)
        raise


def backup_ssh_files(activation: str) -> dict[str, Path | None]:
    validate_activation_mode(activation)
    return {
        "dropin": backup_file(MANAGED_SSHD_DROPIN),
        "socket": backup_file(SSH_SOCKET_OVERRIDE) if activation == "socket" else None,
    }


def backup_file(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup = path.with_name(f"{path.name}.bak-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}")
    shutil.copy2(path, backup)
    os.chmod(backup, 0o600)
    return backup


def apply_systemd_ssh(activation: str) -> None:
    validate_activation_mode(activation)
    test = run_command(["sshd", "-t"], timeout=10)
    if not test.ok:
        raise SSHHardeningError(f"sshd -t failed: {test.stderr or test.stdout}")
    if activation == "socket":
        reload_result = run_command(["systemctl", "daemon-reload"], timeout=30)
        if not reload_result.ok:
            raise SSHHardeningError(f"systemctl daemon-reload failed: {reload_result.stderr or reload_result.stdout}")
        restart = run_command(["systemctl", "restart", SSH_SOCKET], timeout=30)
    else:
        restart = run_command(["systemctl", "reload-or-restart", SSH_SERVICE], timeout=30)
    if not restart.ok:
        raise SSHHardeningError(f"Failed to apply SSH {activation} configuration: {restart.stderr or restart.stdout}")


def verify_transition_listeners(expected_ports: set[int], activation_mode: str) -> bool:
    result = run_command(["ss", "-H", "-lntp"], timeout=5)
    if not result.ok:
        return False
    listeners = parse_ss_tcp_listeners(result.stdout)
    ssh_ports = actual_ssh_listener_ports(listeners, activation_mode, list(expected_ports))
    return expected_ports.issubset(ssh_ports)


def rollback_ssh(backups: dict[str, Path | None], activation: str, old_ports: set[int]) -> None:
    validate_activation_mode(activation)
    restore_file(MANAGED_SSHD_DROPIN, backups.get("dropin"))
    if activation == "socket":
        restore_file(SSH_SOCKET_OVERRIDE, backups.get("socket"))
    try:
        apply_systemd_ssh(activation)
    finally:
        if not verify_transition_listeners(old_ports, activation):
            raise SSHHardeningError("CRITICAL: rollback could not verify old SSH listener.", manual_rollback_commands(old_ports, activation, backups))


def restore_file(path: Path, backup: Path | None) -> None:
    if backup and backup.exists():
        shutil.copy2(backup, path)
        os.chmod(path, 0o600)
    elif path.exists():
        path.unlink()


def manual_rollback_commands(old_ports: set[int], activation: str, backups: dict[str, Path | None] | None = None) -> list[str]:
    validate_activation_mode(activation)
    backups = backups or {}
    ports = " ".join(str(port) for port in sorted(old_ports))
    commands = manual_restore_commands(MANAGED_SSHD_DROPIN, backups.get("dropin"))
    commands.append("sudo sshd -t")
    if activation == "socket":
        commands = manual_restore_commands(SSH_SOCKET_OVERRIDE, backups.get("socket")) + commands
        commands.extend(["sudo systemctl daemon-reload", "sudo systemctl restart ssh.socket"])
    else:
        commands.append("sudo systemctl reload-or-restart ssh.service")
    commands.append(f"sudo ss -H -lntp | grep -E ':(%s)\\b'" % "|".join(str(port) for port in sorted(old_ports)))
    commands.append(f"# Expected old SSH port(s): {ports}")
    return commands


def manual_restore_commands(target: Path, backup: Path | None) -> list[str]:
    if backup is not None:
        return [f"sudo install -m 600 {backup} {target}"]
    return [f"sudo rm -f {target}"]


def ssh_diagnostics() -> list[str]:
    return ["sshd -t", "sshd -T", "systemctl status ssh.service --no-pager -l", "systemctl status ssh.socket --no-pager -l", "systemctl cat ssh.socket", "ss -H -lntp", "ufw status"]
