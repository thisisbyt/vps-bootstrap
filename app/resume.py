from __future__ import annotations

from pathlib import Path
from time import monotonic
from typing import Callable

from app.base_setup import (
    ensure_ansible_foundation,
    ensure_default_config,
    ensure_journald_structure,
    ensure_logging,
    ensure_runtime_directories,
    verify_ansible_foundation,
    verify_default_config,
    verify_journald_structure,
    verify_logging,
    verify_runtime_directories,
    ensure_time_sync,
    verify_time_sync,
)
from app.config import DEFAULT_PHASES, Paths
from app.preflight import run_preflight
from app.results import Severity
from app.safe_logging import add_file_handler
from app.state import InstallState, PhaseStatus
from app.time_sync import TimeSyncError


Verifier = Callable[[], bool]
Executor = Callable[[], None]


class SetupError(RuntimeError):
    def __init__(self, stage: str, message: str, diagnostics: list[str] | None = None) -> None:
        super().__init__(message)
        self.stage = stage
        self.diagnostics = diagnostics or []


def build_phase_handlers(paths: Paths, project_root: Path) -> dict[str, tuple[Verifier, Executor]]:
    return {
        "preflight": (lambda: not any(r.severity == Severity.ERROR for r in run_preflight(paths)), lambda: _execute_preflight(paths)),
        "runtime_directories": (lambda: verify_runtime_directories(paths), lambda: ensure_runtime_directories(paths)),
        "logging": (lambda: verify_logging(paths), lambda: ensure_logging(paths)),
        "config": (lambda: verify_default_config(paths), lambda: ensure_default_config(paths)),
        "time_sync": (verify_time_sync, ensure_time_sync),
        "journald_structure": (lambda: verify_journald_structure(paths), lambda: ensure_journald_structure(paths)),
        "ansible_foundation": (lambda: verify_ansible_foundation(project_root), lambda: ensure_ansible_foundation(project_root)),
    }


def _execute_preflight(paths: Paths) -> None:
    results = run_preflight(paths)
    fatal = [result for result in results if result.severity == Severity.ERROR]
    if fatal:
        raise SetupError(
            "preflight",
            "Preflight failed",
            ["resolvectl status", "getent hosts ubuntu.com", "curl -fsS --max-time 8 https://connectivity-check.ubuntu.com/", "ip route show default", "timedatectl status"],
        )


def run_setup(paths: Paths, project_root: Path, state: InstallState | None = None, logger=None) -> list[str]:
    state = state or InstallState.load(paths.state_file, DEFAULT_PHASES)
    handlers = build_phase_handlers(paths, project_root)
    output: list[str] = []

    for phase in DEFAULT_PHASES:
        verifier, executor = handlers[phase]
        status = state.phases[phase].status
        drift_detected = False
        if status == PhaseStatus.SKIPPED:
            output.append(f"SKIP {phase} [marked skipped]")
            continue
        if status == PhaseStatus.DONE:
            started = monotonic()
            if verifier():
                if logger:
                    logger.info("verify completed phase", extra={"stage": phase, "result": "skip", "duration": monotonic() - started})
                output.append(f"SKIP {phase} [already configured]")
                continue
            drift_detected = True
            if logger:
                logger.info("drift detected", extra={"stage": phase, "result": "recheck"})

        state.set_phase(phase, PhaseStatus.RUNNING)
        if phase != "preflight":
            state.save(paths.state_file)
        started = monotonic()
        if logger:
            logger.info("phase started", extra={"stage": phase, "result": "running"})
        try:
            executor()
            if verifier():
                state.set_phase(phase, PhaseStatus.DONE, "verified")
                if phase == "logging" and logger:
                    add_file_handler(logger, paths.log_file)
                if logger:
                    logger.info("phase verified", extra={"stage": phase, "result": "done", "duration": monotonic() - started})
                if drift_detected:
                    output.append(f"RECHECK / REPAIR {phase}")
                output.append(f"DONE {phase}")
            else:
                state.set_phase(phase, PhaseStatus.FAILED, "verification failed")
                state.save(paths.state_file)
                if logger:
                    logger.error("phase verification failed", extra={"stage": phase, "result": "failed", "duration": monotonic() - started})
                raise SetupError(phase, f"Verification failed for phase: {phase}", ["sudo vps-bootstrap resume"])
        except SetupError as exc:
            state.set_phase(phase, PhaseStatus.FAILED, str(exc))
            state.save(paths.state_file)
            if logger:
                logger.error(str(exc), extra={"stage": phase, "result": "failed", "duration": monotonic() - started})
            raise
        except TimeSyncError as exc:
            state.set_phase(phase, PhaseStatus.FAILED, str(exc))
            state.save(paths.state_file)
            if logger:
                logger.error(str(exc), extra={"stage": phase, "result": "failed", "duration": monotonic() - started})
            raise SetupError(phase, str(exc), exc.diagnostics) from exc
        except Exception as exc:
            state.set_phase(phase, PhaseStatus.FAILED, str(exc))
            state.save(paths.state_file)
            if logger:
                logger.error(str(exc), extra={"stage": phase, "result": "failed", "duration": monotonic() - started})
            raise SetupError(phase, str(exc), ["sudo vps-bootstrap resume"]) from exc
        state.save(paths.state_file)

    return output
