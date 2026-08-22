from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import app.resume as resume
from app.config import BASE_PHASES, DEFAULT_PHASES, Paths
from app.ssh_hardening import SSHDiscovery, SystemdUnitState, TCPListener
from app.state import InstallState, PhaseStatus


def make_paths(tmp_path: Path) -> Paths:
    return Paths(
        etc_dir=tmp_path / "etc",
        config_dir=tmp_path / "etc" / "config",
        secrets_dir=tmp_path / "etc" / "secrets",
        state_dir=tmp_path / "state",
        log_dir=tmp_path / "log",
    )


def ssh_discovery(ports: set[int], listeners: set[int], ssh_listeners: set[int]) -> SSHDiscovery:
    return SSHDiscovery(
        openssh_server_installed=True,
        sshd_path="/usr/sbin/sshd",
        service=SystemdUnitState("active", "enabled"),
        socket=SystemdUnitState("inactive", "disabled"),
        activation_mode="service",
        effective_config={
            "port": [str(port) for port in sorted(ports)],
            "pubkeyauthentication": ["yes"],
            "passwordauthentication": ["yes"],
            "kbdinteractiveauthentication": ["no"],
            "permitrootlogin": ["yes"],
        },
        tcp_listeners=[TCPListener(f"0.0.0.0:{port}", port, 'users:(("sshd",pid=1,fd=3))') for port in listeners],
        actual_listeners=listeners,
        actual_ssh_listeners=ssh_listeners,
        configured_ports=ports,
        include_files=[],
        sshd_config_files=[],
        complex_config_reasons=[],
        managed_dropin_exists=True,
        systemd_overrides=[],
        current_user="example-user",
        in_ssh_session=True,
        ssh_connection="192.0.2.1 55555 192.0.2.10 27503",
        admin_user="example-user",
        admin_authorized_keys_exists=True,
        admin_authorized_keys_count=1,
        admin_ssh_permissions_ok=True,
        sudo_non_root_user_exists=True,
        ufw_installed=True,
        ufw_active=False,
        ufw_allowed_ports=set(),
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

    def test_skipped_ssh_hardening_full_does_not_open_wizard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(["ssh_hardening"])
            state.set_phase("ssh_hardening", PhaseStatus.SKIPPED, "user skipped")
            executed = {"ssh": 0}
            handlers = {"ssh_hardening": (lambda: False, lambda: executed.__setitem__("ssh", executed["ssh"] + 1))}

            with patch.object(resume, "DEFAULT_PHASES", ["ssh_hardening"]), patch.object(resume, "build_phase_handlers", return_value=handlers):
                output = resume.run_setup(paths, tmp_path, state, phases=["ssh_hardening"], scope="full")

        self.assertEqual(output, ["SKIP ssh_hardening [marked skipped]"])
        self.assertEqual(executed["ssh"], 0)

    def test_skipped_ssh_hardening_resume_does_not_open_wizard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(["ssh_hardening"])
            state.set_phase("ssh_hardening", PhaseStatus.SKIPPED, "user skipped")
            state.save(paths.state_file)
            executed = {"ssh": 0}
            handlers = {"ssh_hardening": (lambda: False, lambda: executed.__setitem__("ssh", executed["ssh"] + 1))}

            with patch.object(resume, "build_phase_handlers", return_value=handlers):
                output = resume.run_setup(paths, tmp_path, phases=["ssh_hardening"], scope="resume")

        self.assertEqual(output, ["SKIP ssh_hardening [marked skipped]"])
        self.assertEqual(executed["ssh"], 0)

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

    def test_phase_can_mark_itself_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(["swap"])

            def skip() -> None:
                raise resume.PhaseSkipped("swap", "user skipped swap configuration")

            with patch.object(resume, "DEFAULT_PHASES", ["swap"]), patch.object(
                resume,
                "build_phase_handlers",
                return_value={"swap": (lambda: False, skip)},
            ):
                output = resume.run_setup(paths, tmp_path, state)

        self.assertEqual(output, ["SKIP swap [user skipped swap configuration]"])
        self.assertEqual(state.phases["swap"].status, PhaseStatus.SKIPPED)

    def test_resume_after_base_state_does_not_expand_to_swap_or_ssh(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(["preflight", "time_sync"])
            state.set_phase("preflight", PhaseStatus.DONE)
            state.save(paths.state_file)
            executed: list[str] = []
            verified = {"time_sync": False}

            handlers = {
                "preflight": (lambda: True, lambda: executed.append("preflight")),
                "time_sync": (lambda: verified["time_sync"], lambda: (executed.append("time_sync"), verified.__setitem__("time_sync", True))),
                "swap": (lambda: False, lambda: executed.append("swap")),
                "ssh_hardening": (lambda: False, lambda: executed.append("ssh_hardening")),
            }

            with patch.object(resume, "build_phase_handlers", return_value=handlers):
                output = resume.run_setup(paths, tmp_path, phases=["preflight", "time_sync", "swap", "ssh_hardening"])

        self.assertEqual(output, ["SKIP preflight [already configured]", "DONE time_sync"])
        self.assertEqual(executed, ["time_sync"])

    def test_legacy_v012_state_resume_does_not_add_swap_or_ssh(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            paths.state_dir.mkdir(parents=True)
            paths.state_file.write_text(
                '{"version":"0.1.2","phases":[{"name":"preflight","status":"done"},{"name":"time_sync","status":"done"}]}\n',
                encoding="utf-8",
            )
            executed: list[str] = []
            handlers = {
                "preflight": (lambda: True, lambda: executed.append("preflight")),
                "time_sync": (lambda: True, lambda: executed.append("time_sync")),
                "swap": (lambda: False, lambda: executed.append("swap")),
                "ssh_hardening": (lambda: False, lambda: executed.append("ssh_hardening")),
            }

            with patch.object(resume, "build_phase_handlers", return_value=handlers):
                output = resume.run_setup(paths, tmp_path, scope="resume")

        self.assertEqual(output, ["SKIP preflight [already configured]", "SKIP time_sync [already configured]"])
        self.assertEqual(executed, [])

    def test_base_state_explicit_full_expands_to_swap_and_ssh(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(BASE_PHASES)
            state.save(paths.state_file)
            executed: list[str] = []
            handlers = {name: (lambda: True, lambda name=name: executed.append(name)) for name in DEFAULT_PHASES}

            with patch.object(resume, "build_phase_handlers", return_value=handlers):
                resume.run_setup(paths, tmp_path, phases=DEFAULT_PHASES, scope="full")
            loaded = InstallState.load(paths.state_file)

        self.assertEqual(loaded.phase_order, DEFAULT_PHASES)
        self.assertIn("swap", loaded.phases)
        self.assertIn("ssh_hardening", loaded.phases)

    def test_full_state_explicit_base_does_not_execute_swap_or_ssh(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(DEFAULT_PHASES)
            state.save(paths.state_file)
            executed: list[str] = []
            handlers = {name: (lambda: True, lambda name=name: executed.append(name)) for name in DEFAULT_PHASES}

            with patch.object(resume, "build_phase_handlers", return_value=handlers):
                resume.run_setup(paths, tmp_path, phases=BASE_PHASES, scope="base")

        self.assertNotIn("swap", executed)
        self.assertNotIn("ssh_hardening", executed)

    def test_interrupted_ssh_migration_blocks_base_or_full_scope_change(self) -> None:
        for scope, phases in (("base", BASE_PHASES), ("full", DEFAULT_PHASES)):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as directory:
                tmp_path = Path(directory)
                paths = make_paths(tmp_path)
                state = InstallState.fresh(DEFAULT_PHASES)
                state.update_phase_data("ssh_hardening", {"mode": "migration", "interrupted_migration": True})
                state.save(paths.state_file)

                with self.assertRaisesRegex(resume.SetupError, "Interrupted SSH migration"):
                    resume.run_setup(paths, tmp_path, phases=phases, scope=scope)

    def test_explicit_ssh_reconfigure_runs_after_skipped_phase(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(DEFAULT_PHASES)
            state.set_phase("ssh_hardening", PhaseStatus.SKIPPED, "user skipped")
            state.update_phase_data("ssh_hardening", {"mode": "skipped", "reason": "user skipped"})
            state.save(paths.state_file)

            with patch.object(
                resume,
                "ensure_ssh_hardening_from_state",
                return_value={"mode": "managed", "ports": [25000], "activation_mode": "service", "auth_values": {}},
            ) as ensure, patch.object(resume, "verify_expected_ssh_state", return_value=True):
                output = resume.run_ssh_reconfigure(paths)
            loaded = InstallState.load(paths.state_file)

        self.assertEqual(output, ["DONE ssh_hardening"])
        ensure.assert_called_once()
        self.assertTrue(ensure.call_args.kwargs["force_reconfigure"])
        self.assertEqual(loaded.phases["ssh_hardening"].status, PhaseStatus.DONE)

    def test_explicit_ssh_reconfigure_runs_after_done_phase(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(DEFAULT_PHASES)
            state.set_phase("ssh_hardening", PhaseStatus.DONE, "verified")
            state.update_phase_data("ssh_hardening", {"mode": "managed", "ports": [22], "activation_mode": "service", "auth_values": {}})
            state.save(paths.state_file)

            with patch.object(
                resume,
                "ensure_ssh_hardening_from_state",
                return_value={"mode": "managed", "ports": [25000], "old_ports": [22], "activation_mode": "service", "auth_values": {}},
            ) as ensure, patch.object(resume, "verify_expected_ssh_state", return_value=True):
                output = resume.run_ssh_reconfigure(paths)

        self.assertEqual(output, ["DONE ssh_hardening"])
        self.assertEqual(ensure.call_args.args[0]["ports"], [22])
        self.assertTrue(ensure.call_args.kwargs["force_reconfigure"])

    def test_explicit_ssh_reconfigure_uses_fresh_discovery_not_old_state_ports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(DEFAULT_PHASES)
            state.update_phase_data("ssh_hardening", {"mode": "managed", "ports": [22], "activation_mode": "service", "auth_values": {}})
            state.set_phase("ssh_hardening", PhaseStatus.DONE, "verified")
            state.save(paths.state_file)

            with patch.object(resume, "verify_expected_ssh_state", return_value=True), patch("app.ssh_hardening.discover_ssh", return_value=ssh_discovery(ports={27503}, listeners={27503}, ssh_listeners={27503})), patch(
                "app.ssh_hardening.choose_random_port", return_value=41872
            ), patch("app.ssh_hardening.apply_ssh_plan", return_value={"mode": "managed", "ports": [41872], "old_ports": [27503], "activation_mode": "service", "auth_values": {}}) as apply, patch(
                "builtins.input", side_effect=["1", "y", "n", "y"]
            ):
                resume.run_ssh_reconfigure(paths)

        plan = apply.call_args.args[0]
        self.assertEqual(plan.old_ports, {27503})
        self.assertEqual(plan.target_ports, {27503, 41872})
        self.assertEqual(plan.final_ports, {41872})

    def test_explicit_ssh_reconfigure_interrupted_migration_uses_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(DEFAULT_PHASES)
            state.update_phase_data("ssh_hardening", {"mode": "migration", "interrupted_migration": True, "old_ports": [22], "activation_mode": "service"})
            state.save(paths.state_file)

            with patch("app.ssh_hardening.discover_ssh") as discover, patch("builtins.input", return_value="1"):
                with self.assertRaisesRegex(resume.SetupError, "Interrupted SSH migration"):
                    resume.run_ssh_reconfigure(paths)

        discover.assert_not_called()
