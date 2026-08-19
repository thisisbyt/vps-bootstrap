from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import app.resume as resume
from app.config import Paths
from app.state import InstallState, PhaseStatus


def make_paths(tmp_path: Path) -> Paths:
    return Paths(
        etc_dir=tmp_path / "etc",
        config_dir=tmp_path / "etc" / "config",
        secrets_dir=tmp_path / "etc" / "secrets",
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "log",
    )


class ResumeTests(unittest.TestCase):
    def test_done_phase_is_verified_and_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(["preflight"])
            state.set_phase("preflight", PhaseStatus.DONE)
            with patch.object(resume, "DEFAULT_PHASES", ["preflight"]), patch.object(
                resume,
                "build_phase_handlers",
                return_value={"preflight": (lambda: True, lambda: None)},
            ):
                output = resume.run_setup(paths, tmp_path, state)

        self.assertEqual(output, ["SKIP preflight [already configured]"])

    def test_done_phase_drift_is_repaired(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(["config"])
            state.set_phase("config", PhaseStatus.DONE)
            calls = {"verify": 0, "execute": 0}

            def verify() -> bool:
                calls["verify"] += 1
                return calls["verify"] > 1

            def execute() -> None:
                calls["execute"] += 1

            with patch.object(resume, "DEFAULT_PHASES", ["config"]), patch.object(
                resume,
                "build_phase_handlers",
                return_value={"config": (verify, execute)},
            ):
                output = resume.run_setup(paths, tmp_path, state)

        self.assertEqual(output, ["RECHECK / REPAIR config", "DONE config"])
        self.assertEqual(calls["execute"], 1)

    def test_skipped_phase_is_not_executed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(["future_phase"])
            state.set_phase("future_phase", PhaseStatus.SKIPPED)
            calls = {"execute": 0}

            def execute() -> None:
                calls["execute"] += 1

            with patch.object(resume, "DEFAULT_PHASES", ["future_phase"]), patch.object(
                resume,
                "build_phase_handlers",
                return_value={"future_phase": (lambda: False, execute)},
            ):
                output = resume.run_setup(paths, tmp_path, state)

        self.assertEqual(output, ["SKIP future_phase [marked skipped]"])
        self.assertEqual(calls["execute"], 0)

    def test_time_sync_drift_is_repaired(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(["time_sync"])
            state.set_phase("time_sync", PhaseStatus.DONE)
            calls = {"verify": 0, "execute": 0}

            def verify() -> bool:
                calls["verify"] += 1
                return calls["verify"] > 1

            def execute() -> None:
                calls["execute"] += 1

            with patch.object(resume, "DEFAULT_PHASES", ["time_sync"]), patch.object(
                resume,
                "build_phase_handlers",
                return_value={"time_sync": (verify, execute)},
            ):
                output = resume.run_setup(paths, tmp_path, state)

        self.assertEqual(output, ["RECHECK / REPAIR time_sync", "DONE time_sync"])
        self.assertEqual(calls["execute"], 1)

    def test_done_time_sync_is_not_skipped_when_verifier_detects_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(["time_sync"])
            state.set_phase("time_sync", PhaseStatus.DONE)
            calls = {"execute": 0}

            def execute() -> None:
                calls["execute"] += 1

            verifier_results = iter([False, True])
            with patch.object(resume, "DEFAULT_PHASES", ["time_sync"]), patch.object(
                resume,
                "build_phase_handlers",
                return_value={"time_sync": (lambda: next(verifier_results), execute)},
            ):
                output = resume.run_setup(paths, tmp_path, state)

        self.assertEqual(output, ["RECHECK / REPAIR time_sync", "DONE time_sync"])
        self.assertEqual(calls["execute"], 1)
