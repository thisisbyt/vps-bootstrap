from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from app.compatibility import DEFAULT_COMPATIBILITY, load_compatibility


@dataclass(frozen=True)
class Paths:
    etc_dir: Path = Path(os.environ.get("VPS_BOOTSTRAP_ETC", "/etc/vps-bootstrap"))
    config_dir: Path = Path(os.environ.get("VPS_BOOTSTRAP_CONFIG_DIR", "/etc/vps-bootstrap/config"))
    secrets_dir: Path = Path(os.environ.get("VPS_BOOTSTRAP_SECRETS_DIR", "/etc/vps-bootstrap/secrets"))
    state_dir: Path = Path(os.environ.get("VPS_BOOTSTRAP_STATE_DIR", "/var/lib/vps-bootstrap"))
    log_dir: Path = Path(os.environ.get("VPS_BOOTSTRAP_LOG_DIR", "/var/log/vps-bootstrap"))

    @property
    def state_file(self) -> Path:
        return self.state_dir / "state.json"

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.json"

    @property
    def log_file(self) -> Path:
        return self.log_dir / "vps-bootstrap.log"


def project_root() -> Path:
    return Path(os.environ.get("VPS_BOOTSTRAP_PROJECT_ROOT", Path(__file__).resolve().parent.parent))


def compatibility():
    return load_compatibility(project_root())


DEFAULT_PHASES = [
    "preflight",
    "runtime_directories",
    "logging",
    "config",
    "time_sync",
    "journald_structure",
    "ansible_foundation",
]

SUPPORTED_UBUNTU = DEFAULT_COMPATIBILITY.supported_ubuntu
SUPPORTED_ARCHES = {"x86_64", "amd64", "aarch64", "arm64"}
