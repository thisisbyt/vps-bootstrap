from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from app.config import Paths, compatibility, project_root
from app.filesystem import ManagedPath, ensure_directory, ensure_file, verify_managed_path, write_atomic
from app.time_sync import ensure_time_synchronization, verify_time_sync_health


CONFIG_MODE = 0o640
LOG_FILE_MODE = 0o640


def managed_directories(paths: Paths) -> list[ManagedPath]:
    return [
        ManagedPath(paths.etc_dir, 0o750),
        ManagedPath(paths.config_dir, 0o750),
        ManagedPath(paths.secrets_dir, 0o700),
        ManagedPath(paths.state_dir, 0o750),
        ManagedPath(paths.log_dir, 0o750),
    ]


def ensure_runtime_directories(paths: Paths) -> None:
    for item in managed_directories(paths):
        ensure_directory(item.path, item.mode)


def verify_runtime_directories(paths: Paths) -> bool:
    return all(verify_managed_path(item) for item in managed_directories(paths))


def default_config_payload() -> dict:
    compat = compatibility()
    return {
        "project": "vps-bootstrap",
        "version": compat.project_version,
        "target_ubuntu": compat.primary_ubuntu,
        "managed_by": "vps-bootstrap",
        "v0_1_policy": {
            "change_ssh": False,
            "change_firewall": False,
            "change_fail2ban": False,
            "change_hostname": False,
            "change_swap": False,
        },
    }


def is_managed_config(data: dict) -> bool:
    return data.get("project") == "vps-bootstrap" and data.get("managed_by") == "vps-bootstrap"


def timestamp_suffix() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def ensure_default_config(paths: Paths) -> None:
    ensure_directory(paths.etc_dir, 0o750)
    ensure_directory(paths.config_dir, 0o750)
    payload = default_config_payload()
    if paths.config_file.exists():
        try:
            current = json.loads(paths.config_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            raise RuntimeError(f"Manual intervention required: config is not valid JSON: {paths.config_file}") from None
        if verify_default_config(paths):
            os.chmod(paths.config_file, CONFIG_MODE)
            return
        if not is_managed_config(current):
            raise RuntimeError(f"Manual intervention required: unmanaged config exists: {paths.config_file}")
        backup = paths.config_file.with_name(f"{paths.config_file.name}.bak-{timestamp_suffix()}")
        shutil.copy2(paths.config_file, backup)
        os.chmod(backup, CONFIG_MODE)
    write_atomic(paths.config_file, json.dumps(payload, indent=2, ensure_ascii=False) + "\n", CONFIG_MODE)


def verify_default_config(paths: Paths) -> bool:
    if not paths.config_file.exists():
        return False
    try:
        data = json.loads(paths.config_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    expected = default_config_payload()
    return data == expected and os.stat(paths.config_file).st_mode & 0o777 == CONFIG_MODE


def ensure_logging(paths: Paths) -> None:
    ensure_directory(paths.log_dir, 0o750)
    ensure_file(paths.log_file, LOG_FILE_MODE)


def verify_logging(paths: Paths) -> bool:
    return verify_managed_path(ManagedPath(paths.log_dir, 0o750)) and verify_managed_path(ManagedPath(paths.log_file, LOG_FILE_MODE, "file"))


def verify_time_sync() -> bool:
    return verify_time_sync_health()


def ensure_time_sync() -> None:
    ensure_time_synchronization()


def ensure_journald_structure(paths: Paths) -> None:
    ensure_directory(paths.etc_dir, 0o750)
    ensure_directory(paths.config_dir, 0o750)
    target = paths.config_dir / "journald-vps-bootstrap.conf.example"
    template = project_root() / "templates" / "journald-vps-bootstrap.conf"
    if target.exists() and target.read_text(encoding="utf-8") == template.read_text(encoding="utf-8"):
        os.chmod(target, 0o640)
        return
    write_atomic(target, template.read_text(encoding="utf-8"), 0o640)


def verify_journald_structure(paths: Paths) -> bool:
    target = paths.config_dir / "journald-vps-bootstrap.conf.example"
    template = project_root() / "templates" / "journald-vps-bootstrap.conf"
    return target.exists() and target.read_text(encoding="utf-8") == template.read_text(encoding="utf-8") and os.stat(target).st_mode & 0o777 == 0o640


def ensure_ansible_foundation(project_root: Path) -> None:
    playbook = project_root / "ansible" / "playbook.yml"
    if not playbook.exists():
        raise FileNotFoundError(playbook)


def verify_ansible_foundation(project_root: Path) -> bool:
    return (project_root / "ansible" / "playbook.yml").exists()


def available_base_tools() -> dict[str, bool]:
    tools = ["curl", "git", "jq", "openssl", "dig", "ip", "ss"]
    return {tool: shutil.which(tool) is not None for tool in tools}
