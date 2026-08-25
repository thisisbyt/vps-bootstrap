from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from app.command import run_command
from app.filesystem import write_atomic


MANAGED_COMMENT = "vps-bootstrap:ssh"
MANAGED_UFW_STATE = Path(os.environ.get("VPS_BOOTSTRAP_UFW_STATE", "/var/lib/vps-bootstrap/ufw-managed.json"))


class FirewallError(RuntimeError):
    def __init__(self, message: str, diagnostics: list[str] | None = None) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics or ["ufw status verbose", "ufw status numbered", "ss -H -lntp"]


@dataclass(frozen=True)
class UFWRule:
    port: int
    protocol: str = "tcp"
    action: str = "ALLOW"
    managed: bool = False


@dataclass(frozen=True)
class FirewallDiscovery:
    installed: bool
    active: bool
    default_incoming: str
    default_outgoing: str
    rules: list[UFWRule]
    inactive_existing_rules: list[str] | None = None

    def managed_ports(self) -> set[int]:
        return {rule.port for rule in self.rules if rule.managed and rule.protocol == "tcp"}

    def allowed_tcp_ports(self) -> set[int]:
        return {rule.port for rule in self.rules if rule.protocol == "tcp" and rule.action.upper() == "ALLOW"}


def parse_ufw_status(output: str) -> FirewallDiscovery:
    active = "Status: active" in output
    default_in = ""
    default_out = ""
    rules: list[UFWRule] = []
    for raw in output.splitlines():
        line = raw.strip()
        if line.startswith("Default:"):
            defaults = line.removeprefix("Default:").split(",")
            if defaults:
                default_in = defaults[0].strip()
            if len(defaults) > 1:
                default_out = defaults[1].strip()
        parts = line.split()
        if not parts or "/tcp" not in parts[0]:
            continue
        port_text = parts[0].split("/", 1)[0]
        if not port_text.isdigit():
            continue
        action = parts[1] if len(parts) > 1 else "ALLOW"
        rules.append(UFWRule(int(port_text), "tcp", action, MANAGED_COMMENT in line))
    return FirewallDiscovery(True, active, default_in, default_out, rules, [])


def parse_ufw_added(output: str) -> list[str]:
    rules: list[str] = []
    for raw in output.splitlines():
        line = raw.strip()
        if line.startswith("ufw "):
            rules.append(line)
    return rules


def discover_firewall() -> FirewallDiscovery:
    installed = shutil.which("ufw") is not None
    if not installed:
        return FirewallDiscovery(False, False, "", "", [])
    result = run_command(["ufw", "status", "verbose"], timeout=10)
    if not result.ok:
        raise FirewallError(f"ufw status failed: {result.stderr or result.stdout}")
    discovery = parse_ufw_status(result.stdout)
    if not discovery.active:
        added = run_command(["ufw", "show", "added"], timeout=10)
        inactive_rules = parse_ufw_added(added.stdout) if added.ok else []
        discovery = FirewallDiscovery(discovery.installed, discovery.active, discovery.default_incoming, discovery.default_outgoing, discovery.rules, inactive_rules)
    return discovery


def current_ssh_ports() -> set[int]:
    from app.ssh_hardening import discover_ssh

    discovery = discover_ssh()
    return discovery.actual_ssh_listeners or discovery.configured_ports or {22}


def install_ufw_if_missing() -> None:
    if shutil.which("ufw"):
        return
    result = run_command(["apt-get", "install", "-y", "ufw"], timeout=120)
    if not result.ok:
        raise FirewallError(f"Failed to install ufw: {result.stderr or result.stdout}")


def allow_managed_port(port: int) -> None:
    discovery = discover_firewall()
    if port in discovery.managed_ports():
        return
    if any(rule.port == port and not rule.managed for rule in discovery.rules):
        raise FirewallError(f"Cannot add managed UFW rule for {port}/tcp: unmanaged equivalent rule already exists.")
    result = run_command(["ufw", "allow", "proto", "tcp", "to", "any", "port", str(port), "comment", MANAGED_COMMENT], timeout=30)
    if not result.ok:
        raise FirewallError(f"Failed to allow SSH port {port}/tcp: {result.stderr or result.stdout}")


def delete_managed_port(port: int) -> None:
    discovery = discover_firewall()
    managed_matches = [rule for rule in discovery.rules if rule.port == port and rule.managed]
    if not managed_matches:
        return
    result = run_command(
        ["ufw", "--force", "delete", "allow", "proto", "tcp", "to", "any", "port", str(port), "comment", MANAGED_COMMENT],
        timeout=30,
    )
    if not result.ok:
        raise FirewallError(f"Failed to delete managed UFW rule for {port}/tcp: {result.stderr or result.stdout}")


def delete_exact_managed_port(port: int) -> None:
    result = run_command(
        ["ufw", "--force", "delete", "allow", "proto", "tcp", "to", "any", "port", str(port), "comment", MANAGED_COMMENT],
        timeout=30,
    )
    if not result.ok:
        raise FirewallError(f"Failed to remove the vps-bootstrap UFW rule for {port}/tcp: {result.stderr or result.stdout}")


def ensure_firewall_from_state(data: dict, force_reconfigure: bool = False) -> dict:
    if data and data.get("mode") == "managed" and not force_reconfigure and verify_firewall_state(data):
        return data
    ports = sorted(current_ssh_ports())
    print("Managed UFW firewall setup")
    print("Recommended policy: deny incoming, allow outgoing, allow current SSH port(s) only.")
    print(f"Current SSH port(s): {ports}")
    print("Proposed policy:")
    print("  default incoming: deny")
    print("  default outgoing: allow")
    print(f"  managed SSH allow: {ports}")
    if not confirm_firewall_apply():
        return {"mode": "skipped", "reason": "user skipped firewall setup"}
    install_ufw_if_missing()
    before = discover_firewall()
    if not before.active and before.inactive_existing_rules:
        raise FirewallError("UFW has pre-existing inactive rules; refusing to enable automatically without review.")
    attempted_new_ports: list[int] = []
    marker_existed = MANAGED_UFW_STATE.exists()
    try:
        for port in ports:
            if port not in before.allowed_tcp_ports():
                attempted_new_ports.append(port)
                allow_managed_port(port)
        run_or_raise(["ufw", "default", "deny", "incoming"], "Failed to set default incoming policy")
        run_or_raise(["ufw", "default", "allow", "outgoing"], "Failed to set default outgoing policy")
        discovery = discover_firewall()
        if not discovery.active:
            run_or_raise(["ufw", "--force", "enable"], "Failed to enable UFW")
        state = {"mode": "managed", "ssh_ports": ports, "default_incoming": "deny", "default_outgoing": "allow"}
        if not verify_firewall_state(state):
            raise FirewallError("Managed UFW verification failed after apply.")
        write_managed_state(state)
        return state
    except Exception:
        cleanup_errors: list[str] = []
        for port in reversed(attempted_new_ports):
            try:
                delete_exact_managed_port(port)
            except FirewallError as exc:
                cleanup_errors.append(str(exc))
        if not marker_existed and MANAGED_UFW_STATE.exists():
            MANAGED_UFW_STATE.unlink()
        if cleanup_errors:
            raise FirewallError("Firewall apply failed and partial managed rule cleanup is pending: " + "; ".join(cleanup_errors))
        raise


def confirm_firewall_apply() -> bool:
    from app.ssh_hardening import confirm

    return confirm("Apply managed UFW policy? [Y/n]: ", default=True)


def run_or_raise(args: list[str], message: str) -> None:
    result = run_command(args, timeout=30)
    if not result.ok:
        raise FirewallError(f"{message}: {result.stderr or result.stdout}")


def verify_firewall_state(data: dict) -> bool:
    if data.get("mode") == "skipped":
        return True
    if data.get("mode") != "managed":
        return False
    try:
        discovery = discover_firewall()
    except FirewallError:
        return False
    expected = {int(port) for port in data.get("ssh_ports", [])}
    incoming_ok = discovery.default_incoming.lower().startswith("deny")
    outgoing_ok = discovery.default_outgoing.lower().startswith("allow")
    return (
        discovery.installed
        and discovery.active
        and incoming_ok
        and outgoing_ok
        and expected.issubset(discovery.allowed_tcp_ports())
        and expected.issubset(discovery.managed_ports())
    )


def write_managed_state(data: dict) -> None:
    write_atomic(MANAGED_UFW_STATE, json.dumps(data, indent=2) + "\n", 0o640)


def managed_firewall_exists() -> bool:
    state = load_managed_state()
    return state is not None and verify_firewall_state(state)


def load_managed_state() -> dict | None:
    if not MANAGED_UFW_STATE.is_file():
        return None
    try:
        data = json.loads(MANAGED_UFW_STATE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or data.get("mode") != "managed":
        return None
    ports = data.get("ssh_ports")
    if not isinstance(ports, list) or not ports:
        return None
    try:
        normalized_ports = sorted({int(port) for port in ports})
    except (TypeError, ValueError):
        return None
    if any(port < 1 or port > 65535 for port in normalized_ports):
        return None
    if str(data.get("default_incoming", "")).lower() != "deny" or str(data.get("default_outgoing", "")).lower() != "allow":
        return None
    return {**data, "ssh_ports": normalized_ports}


def prepare_ssh_migration(old_ports: set[int], transition_ports: set[int]) -> dict:
    original_state = load_managed_state()
    if original_state is None or not verify_firewall_state(original_state):
        return {"managed": False}
    added: list[int] = []
    discovery = discover_firewall()
    for port in sorted(transition_ports - discovery.allowed_tcp_ports()):
        allow_managed_port(port)
        added.append(port)
    metadata = {
        "managed": True,
        "added_ports": added,
        "old_ports": sorted(old_ports),
        "old_managed_ports": sorted(discovery.managed_ports() & old_ports),
        "transition_ports": sorted(transition_ports),
        "original_state": original_state,
        "removed_old_ports": [],
    }
    return metadata


def finalize_ssh_migration(final_ports: set[int], old_ports: set[int], metadata: dict) -> dict | None:
    if not metadata.get("managed"):
        return None
    final_state = {"mode": "managed", "ssh_ports": sorted(final_ports), "default_incoming": "deny", "default_outgoing": "allow"}
    metadata["old_ports_to_remove"] = sorted(old_ports - final_ports)
    pending: list[int] = []
    removed: list[int] = []
    for port in sorted(old_ports - final_ports):
        try:
            delete_managed_port(port)
            removed.append(port)
        except FirewallError:
            pending.append(port)
    metadata["removed_old_ports"] = removed
    if pending:
        metadata["cleanup_pending"] = pending
    else:
        metadata.pop("cleanup_pending", None)
    write_managed_state(final_state)
    metadata["final_state"] = final_state
    return final_state


def restore_old_ssh_access(metadata: dict, old_ports: set[int]) -> None:
    if not metadata.get("managed"):
        return
    original_state = metadata.get("original_state")
    if not isinstance(original_state, dict):
        raise FirewallError("Managed UFW rollback metadata is missing the original state.")
    expected_managed = {int(port) for port in metadata.get("old_managed_ports", [])}
    discovery = discover_firewall()
    if not discovery.active:
        raise FirewallError("Managed UFW is not active during SSH rollback; refusing to remove the new access path.")
    for port in sorted(old_ports):
        if port in expected_managed and port not in discovery.managed_ports():
            allow_managed_port(port)
            discovery = discover_firewall()
        elif port not in discovery.allowed_tcp_ports():
            allow_managed_port(port)
            discovery = discover_firewall()
    if not old_ports.issubset(discovery.allowed_tcp_ports()):
        raise FirewallError("Old SSH port is not allowed by UFW after rollback preparation.")
    if expected_managed and not expected_managed.issubset(discovery.managed_ports()):
        raise FirewallError("Old vps-bootstrap-managed UFW rule could not be restored.")
    metadata["old_access_restored"] = True


def verify_old_ssh_access(metadata: dict, old_ports: set[int]) -> bool:
    if not metadata.get("managed"):
        return True
    try:
        discovery = discover_firewall()
    except FirewallError:
        return False
    expected_managed = {int(port) for port in metadata.get("old_managed_ports", [])}
    return discovery.active and old_ports.issubset(discovery.allowed_tcp_ports()) and expected_managed.issubset(discovery.managed_ports())


def rollback_ssh_migration(metadata: dict) -> None:
    if not metadata.get("managed"):
        return
    pending: list[int] = []
    for port in sorted(metadata.get("added_ports", [])):
        try:
            delete_managed_port(int(port))
        except FirewallError:
            pending.append(int(port))
    if pending:
        metadata["cleanup_pending"] = pending
    else:
        metadata.pop("cleanup_pending", None)
    original_state = metadata.get("original_state")
    if isinstance(original_state, dict):
        write_managed_state(original_state)
        metadata["rollback_state"] = original_state
