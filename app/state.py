from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from app.config import DEFAULT_PHASES
from app.filesystem import ensure_directory, write_atomic

STATE_VERSION = "0.1.3"


class PhaseStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PhaseState:
    name: str
    status: PhaseStatus = PhaseStatus.PENDING
    updated_at: str = ""
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "status": self.status.value,
            "updated_at": self.updated_at,
            "message": self.message,
        }
        if self.data:
            payload["data"] = self.data
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PhaseState":
        return cls(
            name=str(data["name"]),
            status=PhaseStatus(str(data.get("status", PhaseStatus.PENDING.value))),
            updated_at=str(data.get("updated_at", "")),
            message=str(data.get("message", "")),
            data=dict(data.get("data", {})),
        )


@dataclass
class InstallState:
    version: str = STATE_VERSION
    phases: dict[str, PhaseState] = field(default_factory=dict)
    phase_order: list[str] = field(default_factory=list)

    @classmethod
    def fresh(cls, phases: list[str] | None = None) -> "InstallState":
        phase_names = phases or DEFAULT_PHASES
        return cls(phases={name: PhaseState(name=name) for name in phase_names}, phase_order=list(phase_names))

    @classmethod
    def load(cls, path: Path, phases: list[str] | None = None) -> "InstallState":
        if not path.exists():
            return cls.fresh(phases)
        data = json.loads(path.read_text(encoding="utf-8"))
        state = cls(version=STATE_VERSION)
        state.phases = {item["name"]: PhaseState.from_dict(item) for item in data.get("phases", [])}
        migrate_phases(state.phases)
        saved_order = [str(name) for name in data.get("phase_order", [])]
        if saved_order:
            state.phase_order = saved_order
        elif phases is None:
            state.phase_order = list(state.phases.keys())
        else:
            state.phase_order = list(phases)
        for name in state.phase_order:
            state.phases.setdefault(name, PhaseState(name=name))
        return state

    def save(self, path: Path) -> None:
        ensure_directory(path.parent, 0o750)
        payload = {
            "version": self.version,
            "updated_at": now(),
            "phase_order": self.phase_order or list(self.phases.keys()),
            "phases": [phase.to_dict() for phase in self.phases.values()],
        }
        write_atomic(path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n", 0o640)

    def set_phase(self, name: str, status: PhaseStatus, message: str = "") -> None:
        self.phases.setdefault(name, PhaseState(name=name))
        self.phases[name].status = status
        self.phases[name].updated_at = now()
        self.phases[name].message = message

    def update_phase_data(self, name: str, data: dict[str, Any]) -> None:
        self.phases.setdefault(name, PhaseState(name=name))
        self.phases[name].data = dict(data)
        self.phases[name].updated_at = now()

    def first_incomplete(self, order: list[str] | None = None) -> str | None:
        for name in order or list(self.phases.keys()):
            status = self.phases[name].status
            if status in {PhaseStatus.PENDING, PhaseStatus.RUNNING, PhaseStatus.FAILED}:
                return name
        return None

    def as_text(self) -> str:
        lines = ["Current VPS Bootstrap state:"]
        for phase in self.phases.values():
            message = f" - {phase.message}" if phase.message else ""
            lines.append(f"  {phase.name}: {phase.status.value}{message}")
        return "\n".join(lines)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def migrate_phases(phases: dict[str, PhaseState]) -> None:
    old = phases.pop("time_sync_check", None)
    if old and "time_sync" not in phases:
        phases["time_sync"] = PhaseState(
            name="time_sync",
            status=old.status,
            updated_at=old.updated_at,
            message=f"migrated from time_sync_check: {old.message}".strip().rstrip(":"),
        )
