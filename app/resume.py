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
from app.config import BASE_PHASES, DEFAULT_PHASES, Paths
from app.preflight import run_preflight
from app.results import Severity
from app.safe_logging import add_file_handler
from app.ssh_hardening import SSHHardeningError, ensure_ssh_hardening_from_state, verify_expected_ssh_state
from app.state import InstallState, PhaseStatus
from app.swap import SwapError, ensure_swap_from_state, verify_swap_state
from app.time_sync import TimeSyncError


Verifier = Callable[[], bool]
Executor = Callable[[], None]


class SetupError(RuntimeError):
    def __init__(
        self,
        stage: str,
        message: str,
        diagnostics: list[str] | None = None,
        retry_command: str = "sudo vps-bootstrap resume",
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.diagnostics = diagnostics or []
        self.retry_command = retry_command


class PhaseSkipped(RuntimeError):
    def __init__(self, stage: str, message: str) -> None:
        super().__init__(message)
        self.stage = stage


def has_interrupted_ssh_migration(state: InstallState) -> bool:
    phase = state.phases.get("ssh_hardening")
    return bool(phase and phase.data.get("interrupted_migration"))


def apply_phase_scope(state: InstallState, requested_order: list[str], scope: str | None) -> list[str]:
    if has_interrupted_ssh_migration(state) and scope in {"base", "full"}:
        raise SetupError(
            "ssh_hardening",
            "Interrupted SSH migration must be resolved before changing setup scope.",
            ["sudo vps-bootstrap resume"],
        )
    if scope == "resume":
        if not state.phase_order:
            state.phase_order = list(state.phases.keys())
        if has_interrupted_ssh_migration(state) and "ssh_hardening" not in state.phase_order:
            state.phase_order.append("ssh_hardening")
        return state.phase_order
    if scope == "base":
        state.phase_order = list(BASE_PHASES)
        for name in state.phase_order:
            state.phases.setdefault(name, InstallState.fresh([name]).phases[name])
        return state.phase_order
    if scope == "full":
        state.phase_order = list(DEFAULT_PHASES)
        for name in state.phase_order:
            state.phases.setdefault(name, InstallState.fresh([name]).phases[name])
        return state.phase_order
    if not state.phase_order:
        state.phase_order = list(requested_order)
    for name in state.phase_order:
        state.phases.setdefault(name, InstallState.fresh([name]).phases[name])
    return state.phase_order


def build_phase_handlers(paths: Paths, project_root: Path, state: InstallState | None = None) -> dict[str, tuple[Verifier, Executor]]:
    state = state or InstallState.fresh(DEFAULT_PHASES)
    return {
        "preflight": (lambda: not any(r.severity == Severity.ERROR for r in run_preflight(paths)), lambda: _execute_preflight(paths)),
        "runtime_directories": (lambda: verify_runtime_directories(paths), lambda: ensure_runtime_directories(paths)),
        "logging": (lambda: verify_logging(paths), lambda: ensure_logging(paths)),
        "config": (lambda: verify_default_config(paths), lambda: ensure_default_config(paths)),
        "time_sync": (verify_time_sync, ensure_time_sync),
        "swap": (lambda: verify_swap_state(state.phases["swap"].data), lambda: _execute_swap(state)),
        "ssh_hardening": (lambda: verify_expected_ssh_state(state.phases["ssh_hardening"].data), lambda: _execute_ssh_hardening(state, paths)),
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


def _execute_swap(state: InstallState) -> None:
    data = ensure_swap_from_state(state.phases["swap"].data)
    state.update_phase_data("swap", data)
    if data.get("mode") == "skipped":
        raise PhaseSkipped("swap", data.get("reason", "swap skipped"))


def _execute_ssh_hardening(state: InstallState, paths: Paths) -> None:
    def save_migration(data: dict) -> None:
        state.update_phase_data("ssh_hardening", data)
        state.save(paths.state_file)

    data = ensure_ssh_hardening_from_state(state.phases["ssh_hardening"].data, save_state=save_migration)
    state.update_phase_data("ssh_hardening", data)
    if data.get("mode") == "skipped":
        raise PhaseSkipped("ssh_hardening", data.get("reason", "SSH hardening skipped"))


def run_ssh_reconfigure(paths: Paths, logger=None) -> list[str]:
    state = InstallState.load(paths.state_file) if paths.state_file.exists() else InstallState.fresh(DEFAULT_PHASES)
    state.phases.setdefault("ssh_hardening", InstallState.fresh(["ssh_hardening"]).phases["ssh_hardening"])

    def save_migration(data: dict) -> None:
        state.update_phase_data("ssh_hardening", data)
        state.save(paths.state_file)

    try:
        data = ensure_ssh_hardening_from_state(
            state.phases["ssh_hardening"].data,
            save_state=save_migration,
            force_reconfigure=True,
        )
    except SSHHardeningError as exc:
        state.set_phase("ssh_hardening", PhaseStatus.FAILED, str(exc))
        state.save(paths.state_file)
        if logger:
            logger.error(str(exc), extra={"stage": "ssh_hardening", "result": "failed"})
        raise SetupError("ssh_hardening", str(exc), exc.diagnostics, retry_command="sudo vps-bootstrap ssh") from exc

    state.update_phase_data("ssh_hardening", data)
    if data.get("mode") == "skipped":
        state.set_phase("ssh_hardening", PhaseStatus.SKIPPED, data.get("reason", "SSH hardening skipped"))
        state.save(paths.state_file)
        return [f"SKIP ssh_hardening [{data.get('reason', 'SSH hardening skipped')}]"]

    if verify_expected_ssh_state(data):
        state.set_phase("ssh_hardening", PhaseStatus.DONE, "verified")
        state.save(paths.state_file)
        if logger:
            logger.info("explicit SSH reconfigure verified", extra={"stage": "ssh_hardening", "result": "done"})
        return ["DONE ssh_hardening"]

    state.set_phase("ssh_hardening", PhaseStatus.FAILED, "verification failed")
    state.save(paths.state_file)
    raise SetupError(
        "ssh_hardening",
        "Verification failed for SSH reconfigure",
        ["sudo vps-bootstrap ssh"],
        retry_command="sudo vps-bootstrap ssh",
    )


def run_setup(paths: Paths, project_root: Path, state: InstallState | None = None, logger=None, phases: list[str] | None = None, scope: str | None = None) -> list[str]:
    requested_order = phases or DEFAULT_PHASES
    if state is None:
        state = InstallState.load(paths.state_file, None) if paths.state_file.exists() else InstallState.fresh(requested_order)
    phase_order = apply_phase_scope(state, requested_order, scope)
    handlers = build_phase_handlers(paths, project_root, state)
    output: list[str] = []

    for phase in phase_order:
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
        except PhaseSkipped as exc:
            state.set_phase(phase, PhaseStatus.SKIPPED, str(exc))
            state.save(paths.state_file)
            if logger:
                logger.info(str(exc), extra={"stage": phase, "result": "skipped", "duration": monotonic() - started})
            output.append(f"SKIP {phase} [{exc}]")
            continue
        except (SwapError, SSHHardeningError) as exc:
            state.set_phase(phase, PhaseStatus.FAILED, str(exc))
            state.save(paths.state_file)
            if logger:
                logger.error(str(exc), extra={"stage": phase, "result": "failed", "duration": monotonic() - started})
            raise SetupError(phase, str(exc), exc.diagnostics) from exc
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
