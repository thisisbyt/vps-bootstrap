from __future__ import annotations

import os
import re
import shlex
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from app.admin_user import SUPPORTED_KEY_TYPES, fingerprint_public_key, verify_admin_user_state
from app.command import run_command
from app.config import Paths
from app.filesystem import chown_root_if_possible, ensure_directory, has_mode, write_atomic


ROOT_SSH_DIR = Path(os.environ.get("VPS_BOOTSTRAP_ROOT_SSH_DIR", "/root/.ssh"))
ROOT_AUTHORIZED_KEYS = Path(os.environ.get("VPS_BOOTSTRAP_ROOT_AUTHORIZED_KEYS", str(ROOT_SSH_DIR / "authorized_keys")))
GROUP_FILE = Path(os.environ.get("VPS_BOOTSTRAP_GROUP_FILE", "/etc/group"))
PASSWD_FILE = Path(os.environ.get("VPS_BOOTSTRAP_PASSWD_FILE", "/etc/passwd"))
SUDOERS_FILE = Path(os.environ.get("VPS_BOOTSTRAP_SUDOERS_FILE", "/etc/sudoers"))
SUDOERS_D = Path(os.environ.get("VPS_BOOTSTRAP_SUDOERS_D", "/etc/sudoers.d"))


class RootHardeningError(RuntimeError):
    def __init__(self, message: str, diagnostics: list[str] | None = None) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics or [
            "sudo passwd -S root",
            "sudo ls -ld /root/.ssh /root/.ssh/authorized_keys",
            "sudo visudo -cf /etc/sudoers",
            "getent group admin",
        ]


@dataclass(frozen=True)
class RootAuthorizedKey:
    index: int
    original_line: str
    key_type: str
    fingerprint: str
    comment: str
    has_options: bool


@dataclass(frozen=True)
class AdminGroupAudit:
    exists: bool
    gid: int | None
    members: list[str]
    sudo_privilege: bool


def root_owned(path: Path) -> bool:
    try:
        stat_result = path.stat()
        return stat_result.st_uid == 0 and stat_result.st_gid == 0
    except OSError:
        return False


def parse_root_authorized_keys(content: str) -> list[RootAuthorizedKey]:
    keys: list[RootAuthorizedKey] = []
    for raw_line in content.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            parts = shlex.split(stripped, comments=False, posix=True)
        except ValueError:
            continue
        key_index = next((index for index, token in enumerate(parts) if token in SUPPORTED_KEY_TYPES), -1)
        if key_index < 0 or key_index + 1 >= len(parts):
            continue
        try:
            fingerprint = fingerprint_public_key(stripped)
        except Exception:
            continue
        comment = sanitize_comment(" ".join(parts[key_index + 2 :]))
        keys.append(
            RootAuthorizedKey(
                index=len(keys) + 1,
                original_line=raw_line,
                key_type=parts[key_index],
                fingerprint=fingerprint,
                comment=comment,
                has_options=key_index > 0,
            )
        )
    return keys


def sanitize_comment(value: str) -> str:
    return "".join(character for character in value if character.isprintable()).strip()


def discover_root_authorized_keys() -> list[RootAuthorizedKey]:
    try:
        content = ROOT_AUTHORIZED_KEYS.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return parse_root_authorized_keys(content)


def root_authorized_keys_inventory() -> tuple[list[RootAuthorizedKey], int]:
    if ROOT_SSH_DIR.is_symlink() or ROOT_AUTHORIZED_KEYS.is_symlink():
        raise RootHardeningError("Refusing to inspect symlinked root SSH paths.")
    try:
        content = ROOT_AUTHORIZED_KEYS.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return [], 0
    keys = parse_root_authorized_keys(content)
    material_lines = sum(
        1 for line in content.splitlines() if line.strip() and not line.lstrip().startswith("#")
    )
    return keys, max(0, material_lines - len(keys))


def display_root_key_audit(keys: list[RootAuthorizedKey]) -> None:
    print("Root SSH authorized_keys audit")
    if not keys:
        print("No valid root SSH authorized keys were found.")
        return
    for key in keys:
        details = [f"{key.index}. {key.key_type}", key.fingerprint]
        if key.comment:
            details.append(f"comment={key.comment}")
        if key.has_options:
            details.append("options/restrictions=yes")
        print("  " + " | ".join(details))


def choose_root_key_action(keys: list[RootAuthorizedKey]) -> tuple[str, set[int]]:
    if not keys:
        return "no_keys", set()
    print("")
    print("[1] Remove all root authorized_keys (recommended)")
    print("[2] Select keys to keep")
    print("[3] Keep root authorized_keys unchanged")
    choice = input("Select option [1]: ").strip() or "1"
    if choice == "1":
        return "remove_all", set()
    if choice == "3":
        return "keep_unchanged", {key.index for key in keys}
    if choice != "2":
        raise RootHardeningError("Unknown root authorized_keys audit option.")
    raw = input("Enter key indexes to keep, comma-separated: ").strip()
    if not raw:
        raise RootHardeningError("No root key indexes were selected; choose remove-all explicitly instead.")
    indexes: set[int] = set()
    for token in re.split(r"[\s,]+", raw):
        if not token.isdigit() or int(token) not in {key.index for key in keys}:
            raise RootHardeningError(f"Invalid root authorized key index: {token}")
        indexes.add(int(token))
    return "keep_selected", indexes


def root_backup_directory(paths: Paths) -> Path:
    return paths.state_dir / "backups" / "root-hardening"


def create_root_keys_backup(paths: Paths) -> Path | None:
    if not ROOT_AUTHORIZED_KEYS.is_file():
        return None
    backup_root = root_backup_directory(paths)
    ensure_directory(paths.state_dir, 0o700)
    ensure_directory(paths.state_dir / "backups", 0o700)
    ensure_directory(backup_root, 0o700)
    operation_dir = backup_root / f"authorized-keys-{time.time_ns()}"
    ensure_directory(operation_dir, 0o700)
    backup = operation_dir / "authorized_keys"
    shutil.copy2(ROOT_AUTHORIZED_KEYS, backup)
    chown_root_if_possible(backup)
    os.chmod(backup, 0o600)
    return backup


def trusted_root_keys_backup(value: object, paths: Paths) -> Path | None:
    if not value:
        return None
    backup = Path(str(value))
    try:
        root = root_backup_directory(paths).resolve()
        resolved = backup.resolve()
        trusted = resolved.is_relative_to(root)
    except (OSError, ValueError):
        return None
    if not backup.is_absolute() or not trusted or backup.name != "authorized_keys" or not backup.is_file():
        return None
    backup_root = root_backup_directory(paths)
    if not has_mode(backup, 0o600) or not has_mode(backup.parent, 0o700) or not has_mode(backup_root, 0o700):
        return None
    if not root_owned(backup) or not root_owned(backup.parent) or not root_owned(backup_root):
        return None
    return backup


def ensure_root_ssh_permissions() -> None:
    if ROOT_SSH_DIR.is_symlink() or ROOT_AUTHORIZED_KEYS.is_symlink():
        raise RootHardeningError("Refusing to manage symlinked root SSH paths.")
    ROOT_SSH_DIR.mkdir(parents=True, exist_ok=True)
    chown_root_if_possible(ROOT_SSH_DIR)
    os.chmod(ROOT_SSH_DIR, 0o700)
    if ROOT_AUTHORIZED_KEYS.exists():
        chown_root_if_possible(ROOT_AUTHORIZED_KEYS)
        os.chmod(ROOT_AUTHORIZED_KEYS, 0o600)


def restore_root_authorized_keys(backup: Path | None, existed: bool) -> None:
    if backup:
        ROOT_SSH_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup, ROOT_AUTHORIZED_KEYS)
        ensure_root_ssh_permissions()
    elif not existed and ROOT_AUTHORIZED_KEYS.exists():
        ROOT_AUTHORIZED_KEYS.unlink()


def apply_root_key_action(action: str, keep_indexes: set[int], keys: list[RootAuthorizedKey], paths: Paths) -> dict:
    if ROOT_SSH_DIR.is_symlink() or ROOT_AUTHORIZED_KEYS.is_symlink():
        raise RootHardeningError("Refusing to manage symlinked root SSH paths.")
    existed = ROOT_AUTHORIZED_KEYS.exists()
    backup = create_root_keys_backup(paths) if existed else None
    selected = [key for key in keys if key.index in keep_indexes]
    try:
        if action == "remove_all":
            if ROOT_AUTHORIZED_KEYS.exists():
                ROOT_AUTHORIZED_KEYS.unlink()
        elif action == "keep_selected":
            ROOT_SSH_DIR.mkdir(parents=True, exist_ok=True)
            content = "\n".join(key.original_line for key in selected) + "\n"
            write_atomic(ROOT_AUTHORIZED_KEYS, content, 0o600)
        elif action not in {"keep_unchanged", "no_keys"}:
            raise RootHardeningError(f"Unsupported root key action: {action}")
        ensure_root_ssh_permissions()
        state = {
            "action": action,
            "initial_count": len(keys),
            "remaining_count": len(selected) if action == "keep_selected" else len(keys) if action == "keep_unchanged" else 0,
            "fingerprints": [key.fingerprint for key in selected] if action == "keep_selected" else [key.fingerprint for key in keys] if action == "keep_unchanged" else [],
            "backup": str(backup) if backup else None,
            "verified": True,
        }
        if not verify_root_key_state(state, paths):
            raise RootHardeningError("Root authorized_keys verification failed after apply.")
        return state
    except (Exception, KeyboardInterrupt) as original_error:
        try:
            restore_root_authorized_keys(backup, existed)
        except (Exception, KeyboardInterrupt) as rollback_error:
            raise RootHardeningError(
                f"CRITICAL: root authorized_keys update failed and the original file could not be restored: {rollback_error}"
            ) from original_error
        raise


def verify_root_key_state(data: dict, paths: Paths) -> bool:
    if not data.get("verified"):
        return False
    expected = list(data.get("fingerprints", []))
    try:
        discovered, unparsed = root_authorized_keys_inventory()
    except RootHardeningError:
        return False
    if unparsed:
        return False
    actual = [key.fingerprint for key in discovered]
    if actual != expected:
        return False
    if ROOT_SSH_DIR.exists() and (not has_mode(ROOT_SSH_DIR, 0o700) or not root_owned(ROOT_SSH_DIR)):
        return False
    if ROOT_AUTHORIZED_KEYS.exists() and (
        not has_mode(ROOT_AUTHORIZED_KEYS, 0o600) or not root_owned(ROOT_AUTHORIZED_KEYS)
    ):
        return False
    backup_value = data.get("backup")
    return not backup_value or trusted_root_keys_backup(backup_value, paths) is not None


def password_status(username: str) -> str:
    result = run_command(["passwd", "-S", username], timeout=10)
    parts = result.stdout.split()
    if not result.ok or len(parts) < 2:
        raise RootHardeningError(f"Could not determine local password status for {username}.")
    return parts[1].upper()


def choose_root_password_policy(admin_has_local_password: bool) -> str:
    print("Root local password:")
    print("[1] Lock root local password")
    print("[2] Keep root local password for console recovery")
    default = "1" if admin_has_local_password else "2"
    if not admin_has_local_password:
        print("[WARN] The non-root admin has no verified local password; locking root would remove the normal password-based console recovery path.")
    choice = input(f"Select option [{default}]: ").strip() or default
    if choice == "1":
        return "lock"
    if choice == "2":
        return "keep"
    raise RootHardeningError("Unknown root local password option.")


def apply_root_password_policy(action: str) -> dict:
    before = password_status("root")
    if action == "lock":
        result = run_command(["passwd", "-l", "root"], timeout=15)
        if not result.ok:
            raise RootHardeningError(f"Failed to lock root local password: {result.stderr or result.stdout}")
        after = password_status("root")
        if after != "L":
            raise RootHardeningError("Root password lock command completed but passwd -S did not report a locked password.")
    elif action == "keep":
        after = before
    else:
        raise RootHardeningError(f"Unsupported root password action: {action}")
    return {"action": action, "status": after, "locked": after == "L", "verified": True}


def verify_root_password_state(data: dict) -> bool:
    if not data.get("verified") or data.get("action") not in {"lock", "keep"}:
        return False
    try:
        current = password_status("root")
    except RootHardeningError:
        return False
    if data.get("action") == "lock":
        return current == "L" and data.get("locked") is True
    return current == data.get("status")


def parse_admin_group(group_content: str, passwd_content: str) -> AdminGroupAudit:
    group_fields: list[str] | None = None
    for raw in group_content.splitlines():
        fields = raw.split(":")
        if len(fields) >= 4 and fields[0] == "admin":
            group_fields = fields
            break
    if not group_fields or not group_fields[2].isdigit():
        return AdminGroupAudit(False, None, [], False)
    gid = int(group_fields[2])
    members = {name for name in group_fields[3].split(",") if name and name != "root"}
    for raw in passwd_content.splitlines():
        fields = raw.split(":")
        if len(fields) >= 4 and fields[0] != "root" and fields[3].isdigit() and int(fields[3]) == gid:
            members.add(fields[0])
    return AdminGroupAudit(True, gid, sorted(members), False)


def sudoers_grants_admin_group() -> bool:
    candidates = [SUDOERS_FILE]
    if SUDOERS_D.is_dir():
        candidates.extend(sorted(path for path in SUDOERS_D.iterdir() if path.is_file()))
    for path in candidates:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for raw in lines:
            line = raw.strip()
            if line and not line.startswith("#") and re.match(r"^%admin(?:\s|$)", line):
                return True
    return False


def audit_admin_group() -> AdminGroupAudit:
    try:
        parsed = parse_admin_group(
            GROUP_FILE.read_text(encoding="utf-8", errors="ignore"),
            PASSWD_FILE.read_text(encoding="utf-8", errors="ignore"),
        )
    except OSError:
        return AdminGroupAudit(False, None, [], False)
    granted = sudoers_grants_admin_group() if parsed.exists and parsed.members else False
    audit = AdminGroupAudit(parsed.exists, parsed.gid, parsed.members, granted)
    if audit.members and audit.sudo_privilege:
        print("[WARN] Non-root users receive sudo through the legacy admin group: " + ", ".join(audit.members))
        print("vps-bootstrap will not modify the admin group or package-owned sudoers policy.")
    return audit


def admin_group_state(audit: AdminGroupAudit) -> dict:
    return {
        "exists": audit.exists,
        "gid": audit.gid,
        "members": list(audit.members),
        "sudo_privilege": audit.sudo_privilege,
        "warning_only": bool(audit.members and audit.sudo_privilege),
    }


def ensure_root_hardening_from_state(
    data: dict,
    admin_data: dict,
    paths: Paths,
    force_reconfigure: bool = False,
    save_state=None,
) -> dict:
    if data and data.get("mode") == "managed" and not force_reconfigure and verify_root_hardening_state(data, admin_data, paths):
        return data
    if not verify_admin_user_state(admin_data):
        return {"mode": "skipped", "reason": "validated non-root admin access is required before root hardening"}

    audit = audit_admin_group()
    existing_key_state = data.get("root_authorized_keys", {}) if data.get("mode") == "running" else {}
    if existing_key_state and verify_root_key_state(existing_key_state, paths):
        key_state = dict(existing_key_state)
    else:
        keys, unparsed = root_authorized_keys_inventory()
        if unparsed:
            raise RootHardeningError(
                "Root authorized_keys contains non-comment entries that could not be safely parsed; no root key was changed."
            )
        display_root_key_audit(keys)
        action, indexes = choose_root_key_action(keys)
        key_state = apply_root_key_action(action, indexes, keys, paths)
    progress = {
        "mode": "running",
        "admin_username": admin_data.get("username"),
        "admin_validated": True,
        "root_authorized_keys": key_state,
        "admin_group_audit": admin_group_state(audit),
    }
    if save_state:
        save_state(progress)

    password_action = choose_root_password_policy(bool(admin_data.get("local_password_usable")))
    password_state = apply_root_password_policy(password_action)
    result = {
        **progress,
        "mode": "managed",
        "root_password": password_state,
    }
    if not verify_root_hardening_state(result, admin_data, paths):
        raise RootHardeningError("Root hardening verification failed after apply.")
    return result


def verify_root_hardening_state(data: dict, admin_data: dict, paths: Paths) -> bool:
    if data.get("mode") == "skipped":
        return True
    if data.get("mode") != "managed" or not data.get("admin_validated"):
        return False
    if data.get("admin_username") != admin_data.get("username") or not verify_admin_user_state(admin_data):
        return False
    root_keys = data.get("root_authorized_keys")
    root_password = data.get("root_password")
    return (
        isinstance(root_keys, dict)
        and isinstance(root_password, dict)
        and verify_root_key_state(root_keys, paths)
        and verify_root_password_state(root_password)
    )
