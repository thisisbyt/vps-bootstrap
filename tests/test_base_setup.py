import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.base_setup import ensure_default_config, ensure_runtime_directories, verify_default_config, verify_runtime_directories
from app.config import Paths
from app.filesystem import write_atomic
from app.resume import SetupError, run_setup
from app.state import InstallState, PhaseStatus


def make_paths(tmp_path: Path) -> Paths:
    return Paths(
        etc_dir=tmp_path / "etc" / "vps-bootstrap",
        config_dir=tmp_path / "etc" / "vps-bootstrap" / "config",
        secrets_dir=tmp_path / "etc" / "vps-bootstrap" / "secrets",
        state_dir=tmp_path / "var" / "lib" / "vps-bootstrap",
        log_dir=tmp_path / "var" / "log" / "vps-bootstrap",
    )


@unittest.skipIf(os.name == "nt", "POSIX permission bits require Linux/Unix filesystem semantics")
class BaseSetupPermissionTests(unittest.TestCase):
    def test_runtime_directory_permission_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = make_paths(Path(directory))
            ensure_runtime_directories(paths)

            self.assertTrue(verify_runtime_directories(paths))

            os.chmod(paths.secrets_dir, 0o755)
            self.assertFalse(verify_runtime_directories(paths))

    def test_config_drift_repair_for_managed_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = make_paths(Path(directory))
            ensure_runtime_directories(paths)
            ensure_default_config(paths)
            data = json.loads(paths.config_file.read_text(encoding="utf-8"))
            data["target_ubuntu"] = "broken"
            paths.config_file.write_text(json.dumps(data), encoding="utf-8")

            ensure_default_config(paths)

            self.assertTrue(verify_default_config(paths))
            backups = list(paths.config_dir.glob("config.json.bak-*"))
            self.assertEqual(len(backups), 1)

    def test_unmanaged_config_requires_manual_intervention(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = make_paths(Path(directory))
            ensure_runtime_directories(paths)
            paths.config_file.write_text('{"project": "someone-else"}\n', encoding="utf-8")

            with self.assertRaises(RuntimeError):
                ensure_default_config(paths)

    def test_resume_manual_intervention_does_not_report_repair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(["config"])
            state.set_phase("config", PhaseStatus.DONE)

            with patch("app.resume.DEFAULT_PHASES", ["config"]), patch(
                "app.resume.build_phase_handlers",
                return_value={"config": (lambda: False, lambda: (_ for _ in ()).throw(RuntimeError("manual intervention required")))},
            ):
                with self.assertRaises(SetupError):
                    run_setup(paths, tmp_path, state)


class BaseSetupAtomicTests(unittest.TestCase):
    def test_default_config_uses_atomic_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = make_paths(Path(directory))
            with patch("app.base_setup.write_atomic") as atomic_write:
                ensure_default_config(paths)

        atomic_write.assert_called_once()
        self.assertEqual(atomic_write.call_args.args[0], paths.config_file)

    def test_write_atomic_replaces_complete_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text('{"old": true}\n', encoding="utf-8")

            write_atomic(path, '{"new": true}\n')

            self.assertEqual(path.read_text(encoding="utf-8"), '{"new": true}\n')
