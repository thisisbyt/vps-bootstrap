from pathlib import Path
import os
import stat
import json
import unittest

from app.state import InstallState, PhaseStatus


class StateTests(unittest.TestCase):
    def test_state_roundtrip(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            state = InstallState.fresh(["one", "two"])
            state.set_phase("one", PhaseStatus.DONE, "verified")
            state.save(path)

            loaded = InstallState.load(path, ["one", "two"])

        self.assertEqual(loaded.phases["one"].status, PhaseStatus.DONE)
        self.assertEqual(loaded.phases["one"].message, "verified")
        self.assertEqual(loaded.first_incomplete(["one", "two"]), "two")

    def test_running_phase_is_incomplete(self) -> None:
        state = InstallState.fresh(["one"])
        state.set_phase("one", PhaseStatus.RUNNING)

        self.assertEqual(state.first_incomplete(["one"]), "one")

    def test_phase_data_roundtrip(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            state = InstallState.fresh(["swap"])
            state.update_phase_data("swap", {"mode": "managed", "path": "/swapfile", "size_bytes": 2147483648})
            state.set_phase("swap", PhaseStatus.DONE, "verified")
            state.save(path)

            loaded = InstallState.load(path, ["swap"])

        self.assertEqual(loaded.phases["swap"].data["mode"], "managed")
        self.assertEqual(loaded.phases["swap"].data["path"], "/swapfile")

    def test_phase_order_roundtrip_preserves_base_scope(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            state = InstallState.fresh(["preflight", "time_sync"])
            state.save(path)

            loaded = InstallState.load(path, ["preflight", "time_sync", "swap", "ssh_hardening"])

        self.assertEqual(loaded.phase_order, ["preflight", "time_sync"])
        self.assertNotIn("swap", loaded.phases)
        self.assertNotIn("ssh_hardening", loaded.phases)

    def test_legacy_state_without_phase_order_uses_existing_phases_only(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(
                json.dumps(
                    {
                        "version": "0.1.2",
                        "phases": [
                            {"name": "preflight", "status": "done"},
                            {"name": "time_sync", "status": "done"},
                            {"name": "journald_structure", "status": "done"},
                        ],
                    }
                ),
                encoding="utf-8",
            )

            loaded = InstallState.load(path)

        self.assertEqual(loaded.phase_order, ["preflight", "time_sync", "journald_structure"])
        self.assertNotIn("swap", loaded.phases)
        self.assertNotIn("ssh_hardening", loaded.phases)

    def test_state_migrates_time_sync_check_to_time_sync(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(
                json.dumps(
                    {
                        "version": "0.1.1",
                        "phases": [
                            {
                                "name": "time_sync_check",
                                "status": "done",
                                "updated_at": "2026-08-18T00:00:00+00:00",
                                "message": "verified",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            loaded = InstallState.load(path, ["time_sync"])

        self.assertIn("time_sync", loaded.phases)
        self.assertNotIn("time_sync_check", loaded.phases)
        self.assertEqual(loaded.phases["time_sync"].status, PhaseStatus.DONE)

    @unittest.skipIf(os.name == "nt", "POSIX permission bits require Linux/Unix filesystem semantics")
    def test_state_save_creates_secure_directory_and_file(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing" / "state.json"
            state = InstallState.fresh(["one"])
            state.save(path)

            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o750)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
