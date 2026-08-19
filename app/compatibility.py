from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Compatibility:
    primary_ubuntu: str
    supported_ubuntu: set[str]
    python_minimum: str
    project_version: str
    ntp_providers: list[str]
    ntp_probe_timeout_seconds: int
    synchronization_wait_seconds: int


DEFAULT_COMPATIBILITY = Compatibility(
    primary_ubuntu="24.04",
    supported_ubuntu={"24.04"},
    python_minimum="3.12",
    project_version="0.1.2",
    ntp_providers=[],
    ntp_probe_timeout_seconds=2,
    synchronization_wait_seconds=60,
)


def load_compatibility(project_root: Path) -> Compatibility:
    path = project_root / "versions.yml"
    if not path.exists():
        return DEFAULT_COMPATIBILITY
    return parse_versions_yml(path.read_text(encoding="utf-8"))


def parse_versions_yml(text: str) -> Compatibility:
    project_version = _scalar(text, "version") or DEFAULT_COMPATIBILITY.project_version
    primary = _nested_scalar(text, ["os", "ubuntu"], "primary") or DEFAULT_COMPATIBILITY.primary_ubuntu
    supported = _nested_list(text, ["os", "ubuntu"], "supported") or sorted(DEFAULT_COMPATIBILITY.supported_ubuntu)
    python_minimum = _section_scalar(text, "python", "minimum") or DEFAULT_COMPATIBILITY.python_minimum
    ntp_providers = _section_list(text, "time_sync", "providers") or DEFAULT_COMPATIBILITY.ntp_providers
    ntp_timeout = _section_int(text, "time_sync", "ntp_probe_timeout_seconds", DEFAULT_COMPATIBILITY.ntp_probe_timeout_seconds)
    sync_wait = _section_int(text, "time_sync", "synchronization_wait_seconds", DEFAULT_COMPATIBILITY.synchronization_wait_seconds)
    return Compatibility(
        primary_ubuntu=primary,
        supported_ubuntu=set(supported),
        python_minimum=python_minimum,
        project_version=project_version,
        ntp_providers=ntp_providers,
        ntp_probe_timeout_seconds=ntp_timeout,
        synchronization_wait_seconds=sync_wait,
    )


def _scalar(text: str, key: str) -> str | None:
    prefix = f"  {key}:"
    for line in text.splitlines():
        if line.startswith(prefix):
            return _clean_value(line.split(":", 1)[1])
    return None


def _section_scalar(text: str, section: str, key: str) -> str | None:
    lines = text.splitlines()
    in_section = False
    prefix = f"{key}:"
    for line in lines:
        if line == f"{section}:":
            in_section = True
            continue
        if in_section and line and not line.startswith(" "):
            return None
        if in_section and line.strip().startswith(prefix):
            return _clean_value(line.split(":", 1)[1])
    return None


def _section_int(text: str, section: str, key: str, default: int) -> int:
    value = _section_scalar(text, section, key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _section_list(text: str, section: str, key: str) -> list[str]:
    lines = text.splitlines()
    values: list[str] = []
    in_section = False
    in_list = False
    for line in lines:
        if line == f"{section}:":
            in_section = True
            continue
        if in_section and line and not line.startswith(" "):
            break
        if in_section and line.strip() == f"{key}:":
            in_list = True
            continue
        if in_list and line.strip().startswith("- "):
            values.append(_clean_value(line.strip()[2:]))
            continue
        if in_list and line.strip():
            break
    return values


def _nested_scalar(text: str, path: list[str], key: str) -> str | None:
    lines = text.splitlines()
    in_path = False
    for line in lines:
        if line == f"{path[0]}:":
            in_path = True
            continue
        if in_path and line and not line.startswith(" "):
            return None
        if in_path and len(path) > 1 and line == f"  {path[1]}:":
            continue
        if in_path and line.strip().startswith(f"{key}:"):
            return _clean_value(line.split(":", 1)[1])
    return None


def _nested_list(text: str, path: list[str], key: str) -> list[str]:
    lines = text.splitlines()
    values: list[str] = []
    in_path = False
    in_list = False
    for line in lines:
        if line == f"{path[0]}:":
            in_path = True
            continue
        if in_path and line and not line.startswith(" "):
            break
        if in_path and len(path) > 1 and line == f"  {path[1]}:":
            continue
        if in_path and line.strip() == f"{key}:":
            in_list = True
            continue
        if in_list and line.strip().startswith("- "):
            values.append(_clean_value(line.strip()[2:]))
            continue
        if in_list and line.strip():
            break
    return values


def _clean_value(value: str) -> str:
    return value.strip().strip('"').strip("'")
