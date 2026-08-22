import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from app import cli
from app.config import BASE_PHASES, DEFAULT_PHASES, Paths
from app.resume import SetupError


class CLITests(unittest.TestCase):
    def test_base_uses_base_phase_scope(self) -> None:
        captured = {}

        def fake_run_setup(paths, project_root, logger=None, phases=None, scope=None):
            captured["phases"] = phases
            captured["scope"] = scope
            return ["DONE"]

        with patch("app.cli.run_setup", side_effect=fake_run_setup), patch("app.cli.project_root", return_value="."):
            self.assertEqual(cli.run_command("base", Paths(), logger=None), 0)

        self.assertEqual(captured["phases"], BASE_PHASES)
        self.assertEqual(captured["scope"], "base")

    def test_full_uses_full_phase_scope(self) -> None:
        captured = {}

        def fake_run_setup(paths, project_root, logger=None, phases=None, scope=None):
            captured["phases"] = phases
            captured["scope"] = scope
            return ["DONE"]

        with patch("app.cli.run_setup", side_effect=fake_run_setup), patch("app.cli.project_root", return_value="."):
            self.assertEqual(cli.run_command("full", Paths(), logger=None), 0)

        self.assertEqual(captured["phases"], DEFAULT_PHASES)
        self.assertEqual(captured["scope"], "full")

    def test_resume_uses_saved_scope_without_default_phases(self) -> None:
        captured = {}

        def fake_run_setup(paths, project_root, logger=None, phases=None, scope=None):
            captured["phases"] = phases
            captured["scope"] = scope
            return ["DONE"]

        with patch("app.cli.run_setup", side_effect=fake_run_setup), patch("app.cli.project_root", return_value="."):
            self.assertEqual(cli.run_command("resume", Paths(), logger=None), 0)

        self.assertIsNone(captured["phases"])
        self.assertEqual(captured["scope"], "resume")

    def test_ssh_command_runs_explicit_reconfigure(self) -> None:
        with patch("app.cli.run_ssh_reconfigure", return_value=["DONE ssh_hardening"]) as reconfigure:
            self.assertEqual(cli.run_command("ssh", Paths(), logger=None), 0)

        reconfigure.assert_called_once()

    def test_help_lists_ssh_command(self) -> None:
        buffer = StringIO()
        with redirect_stdout(buffer), self.assertRaises(SystemExit) as exc:
            cli.main(["--help"])

        self.assertEqual(exc.exception.code, 0)
        self.assertIn("ssh", buffer.getvalue())

    def test_base_error_recommends_resume_and_preserves_exit_code(self) -> None:
        buffer = StringIO()
        with patch("app.cli.run_setup", side_effect=SetupError("base", "boom")), redirect_stdout(buffer):
            code = cli.main(["base"])

        self.assertEqual(code, 1)
        self.assertIn("sudo vps-bootstrap resume", buffer.getvalue())
        self.assertNotIn("sudo vps-bootstrap ssh", buffer.getvalue())

    def test_ssh_error_recommends_explicit_ssh_retry_and_preserves_exit_code(self) -> None:
        buffer = StringIO()
        error = SetupError("ssh_hardening", "boom", retry_command="sudo vps-bootstrap ssh")
        with patch("app.cli.run_ssh_reconfigure", side_effect=error), redirect_stdout(buffer):
            code = cli.main(["ssh"])

        self.assertEqual(code, 1)
        self.assertIn("sudo vps-bootstrap ssh", buffer.getvalue())
        self.assertNotIn("sudo vps-bootstrap resume", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
