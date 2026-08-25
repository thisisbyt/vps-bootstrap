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
            state.update_phase_data("admin_user", {"mode": "managed", "sudo_mode": "nopasswd"})
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
        self.assertEqual(ensure.call_args.kwargs["sudo_mode"], "nopasswd")
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

    def test_full_migration_synchronizes_components_and_second_full_skips_all(self) -> None:
        phases = ["firewall", "fail2ban", "ssh_hardening"]
        firewall_old = {"mode": "managed", "ssh_ports": [22], "default_incoming": "deny", "default_outgoing": "allow"}
        firewall_new = {"mode": "managed", "ssh_ports": [25000], "default_incoming": "deny", "default_outgoing": "allow"}
        fail2ban_old = {"mode": "managed", "ports": [22], "maxretry": 5, "findtime": "10m", "bantime": "1h", "ignoreip": []}
        fail2ban_new = {**fail2ban_old, "ports": [25000]}
        ssh_new = {
            "mode": "managed",
            "ports": [25000],
            "old_ports": [22],
            "activation_mode": "service",
            "auth_values": {"PubkeyAuthentication": "yes"},
            "component_states": {"firewall": firewall_new, "fail2ban": fail2ban_new},
        }
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(phases)
            state.update_phase_data("firewall", firewall_old)
            state.update_phase_data("fail2ban", fail2ban_old)
            state.set_phase("firewall", PhaseStatus.DONE)
            state.set_phase("fail2ban", PhaseStatus.DONE)
            state.save(paths.state_file)

            with patch.object(resume, "DEFAULT_PHASES", phases), patch.object(
                resume, "verify_firewall_state", side_effect=lambda data: data.get("ssh_ports") in ([22], [25000])
            ), patch.object(resume, "verify_fail2ban_state", side_effect=lambda data: data.get("ports") in ([22], [25000])), patch.object(
                resume, "ensure_firewall_from_state"
            ) as firewall_wizard, patch.object(resume, "ensure_fail2ban_from_state") as fail2ban_wizard, patch.object(
                resume, "ensure_ssh_hardening_from_state", return_value=ssh_new
            ) as ssh_wizard, patch.object(resume, "verify_expected_ssh_state", return_value=True):
                first = resume.run_setup(paths, tmp_path, phases=phases, scope="full")

            loaded = InstallState.load(paths.state_file)
            self.assertEqual(loaded.phases["firewall"].data, firewall_new)
            self.assertEqual(loaded.phases["fail2ban"].data, fail2ban_new)
            self.assertEqual(loaded.phases["ssh_hardening"].data["ports"], [25000])
            firewall_wizard.assert_not_called()
            fail2ban_wizard.assert_not_called()
            ssh_wizard.assert_called_once()
            self.assertIn("DONE ssh_hardening", first)

            with patch.object(resume, "DEFAULT_PHASES", phases), patch.object(
                resume, "verify_firewall_state", side_effect=lambda data: data == firewall_new
            ), patch.object(resume, "verify_fail2ban_state", side_effect=lambda data: data == fail2ban_new), patch.object(
                resume, "verify_expected_ssh_state", return_value=True
            ), patch.object(resume, "ensure_firewall_from_state") as firewall_wizard, patch.object(
                resume, "ensure_fail2ban_from_state"
            ) as fail2ban_wizard, patch.object(resume, "ensure_ssh_hardening_from_state") as ssh_wizard:
                second = resume.run_setup(paths, tmp_path, phases=phases, scope="full")

        self.assertEqual(second, [
            "SKIP firewall [already configured]",
            "SKIP fail2ban [already configured]",
            "SKIP ssh_hardening [already configured]",
        ])
        firewall_wizard.assert_not_called()
        fail2ban_wizard.assert_not_called()
        ssh_wizard.assert_not_called()

    def test_explicit_repeated_ssh_reconfigure_persists_component_ports(self) -> None:
        def ssh_state(old_port: int, new_port: int) -> dict:
            return {
                "mode": "managed",
                "ports": [new_port],
                "old_ports": [old_port],
                "activation_mode": "service",
                "auth_values": {"PubkeyAuthentication": "yes"},
                "component_states": {
                    "firewall": {"mode": "managed", "ssh_ports": [new_port], "default_incoming": "deny", "default_outgoing": "allow"},
                    "fail2ban": {"mode": "managed", "ports": [new_port], "maxretry": 5, "findtime": "10m", "bantime": "1h", "ignoreip": []},
                },
            }

        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(DEFAULT_PHASES)
            state.save(paths.state_file)
            with patch.object(resume, "ensure_ssh_hardening_from_state", side_effect=[ssh_state(22, 25000), ssh_state(25000, 26000)]), patch.object(
                resume, "verify_expected_ssh_state", return_value=True
            ):
                resume.run_ssh_reconfigure(paths)
                resume.run_ssh_reconfigure(paths)
            loaded = InstallState.load(paths.state_file)

        self.assertEqual(loaded.phases["ssh_hardening"].data["ports"], [26000])
        self.assertEqual(loaded.phases["firewall"].data["ssh_ports"], [26000])
        self.assertEqual(loaded.phases["fail2ban"].data["ports"], [26000])

    def test_interrupted_resume_recovers_ssh_before_component_verifiers(self) -> None:
        phases = ["firewall", "fail2ban", "ssh_hardening"]
        stages = ["firewall_prepared", "transition_active", "fail2ban_prepared", "firewall_finalizing"]
        for stage in stages:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                tmp_path = Path(directory)
                paths = make_paths(tmp_path)
                state = InstallState.fresh(phases)
                state.set_phase("firewall", PhaseStatus.DONE)
                state.set_phase("fail2ban", PhaseStatus.DONE)
                state.set_phase("ssh_hardening", PhaseStatus.FAILED)
                state.update_phase_data(
                    "ssh_hardening",
                    {"mode": "migration", "interrupted_migration": True, "migration_stage": stage},
                )
                state.save(paths.state_file)
                events: list[str] = []
                recovery = {
                    "mode": "skipped",
                    "reason": "rolled back",
                    "interrupted_migration": False,
                    "rollback_completed": True,
                    "component_states": {
                        "firewall": {"mode": "managed", "ssh_ports": [22]},
                        "fail2ban": {"mode": "managed", "ports": [22]},
                    },
                }

                with patch.object(resume, "ensure_ssh_hardening_from_state", side_effect=lambda *args, **kwargs: events.append("ssh-recovery") or recovery), patch.object(
                    resume, "verify_firewall_state", side_effect=lambda data: events.append("firewall-verify") or True
                ), patch.object(resume, "verify_fail2ban_state", side_effect=lambda data: events.append("fail2ban-verify") or True), patch.object(
                    resume, "verify_expected_ssh_state", return_value=False
                ):
                    output = resume.run_setup(paths, tmp_path, scope="resume")

                self.assertEqual(events[0], "ssh-recovery")
                self.assertLess(events.index("ssh-recovery"), events.index("firewall-verify"))
                self.assertLess(events.index("ssh-recovery"), events.index("fail2ban-verify"))
                self.assertIn("SKIP ssh_hardening [rolled back]", output)

    def test_interrupted_done_ssh_state_bypasses_normal_verifier_and_enters_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(["ssh_hardening"])
            state.set_phase("ssh_hardening", PhaseStatus.DONE)
            state.update_phase_data(
                "ssh_hardening",
                {"mode": "migration", "interrupted_migration": True, "migration_stage": "transition_active"},
            )
            state.save(paths.state_file)
            recovery = {
                "mode": "skipped",
                "reason": "rolled back",
                "interrupted_migration": False,
                "rollback_completed": True,
            }
            with patch.object(resume, "verify_expected_ssh_state") as normal_verify, patch.object(
                resume, "ensure_ssh_hardening_from_state", return_value=recovery
            ) as recover:
                output = resume.run_setup(paths, tmp_path, scope="resume")

        normal_verify.assert_not_called()
        recover.assert_called_once()
        self.assertEqual(output[0], "SKIP ssh_hardening [rolled back]")

    def test_interrupted_finalization_rollback_persists_old_component_states(self) -> None:
        phases = ["firewall", "fail2ban", "ssh_hardening"]
        firewall_old = {"mode": "managed", "ssh_ports": [22], "default_incoming": "deny", "default_outgoing": "allow"}
        fail2ban_old = {"mode": "managed", "ports": [22], "maxretry": 5, "findtime": "10m", "bantime": "1h", "ignoreip": []}
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(phases)
            state.set_phase("firewall", PhaseStatus.DONE)
            state.set_phase("fail2ban", PhaseStatus.DONE)
            state.set_phase("ssh_hardening", PhaseStatus.FAILED)
            state.update_phase_data("firewall", {**firewall_old, "ssh_ports": [25000]})
            state.update_phase_data("fail2ban", {**fail2ban_old, "ports": [25000]})
            state.update_phase_data(
                "ssh_hardening",
                {
                    "mode": "migration",
                    "interrupted_migration": True,
                    "migration_stage": "firewall_finalizing",
                    "old_ports": [22],
                    "activation_mode": "service",
                    "backup_metadata": {"dropin": None},
                    "component_metadata": {"firewall": {"managed": True}, "fail2ban": {"managed": True}},
                },
            )
            state.save(paths.state_file)
            rollback_result = {
                "rollback_completed": True,
                "cleanup_pending": [],
                "component_states": {"firewall": firewall_old, "fail2ban": fail2ban_old},
            }
            with patch("builtins.input", return_value="2"), patch(
                "app.ssh_hardening.rollback_ssh_transaction", return_value=rollback_result
            ) as rollback, patch.object(resume, "verify_firewall_state", side_effect=lambda data: data == firewall_old), patch.object(
                resume, "verify_fail2ban_state", side_effect=lambda data: data == fail2ban_old
            ):
                output = resume.run_setup(paths, tmp_path, scope="resume")
            loaded = InstallState.load(paths.state_file)

        rollback.assert_called_once()
        self.assertEqual(loaded.phases["firewall"].data, firewall_old)
        self.assertEqual(loaded.phases["fail2ban"].data, fail2ban_old)
        self.assertFalse(loaded.phases["ssh_hardening"].data["interrupted_migration"])
        self.assertTrue(loaded.phases["ssh_hardening"].data["rollback_completed"])
        self.assertEqual(output[0], "SKIP ssh_hardening [interrupted SSH migration rolled back; run vps-bootstrap ssh explicitly to retry]")

    def test_normal_full_does_not_auto_repair_managed_ssh_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(["ssh_hardening"])
            state.set_phase("ssh_hardening", PhaseStatus.DONE)
            state.update_phase_data(
                "ssh_hardening",
                {"mode": "managed", "ports": [25000], "activation_mode": "service", "auth_values": {"PubkeyAuthentication": "yes"}},
            )
            drifted = ssh_discovery(ports={22}, listeners={22}, ssh_listeners={22})
            with patch.object(resume, "DEFAULT_PHASES", ["ssh_hardening"]), patch.object(
                resume, "verify_expected_ssh_state", return_value=False
            ), patch("app.ssh_hardening.discover_ssh", return_value=drifted), patch("app.ssh_hardening.write_atomic") as write, patch(
                "app.ssh_hardening.apply_systemd_ssh"
            ) as systemd:
                with self.assertRaisesRegex(resume.SetupError, "sudo vps-bootstrap ssh"):
                    resume.run_setup(paths, tmp_path, state=state, phases=["ssh_hardening"], scope="full")

        write.assert_not_called()
        systemd.assert_not_called()

    def test_greenfield_hardening_order_persists_and_second_run_skips(self) -> None:
        phases = ["admin_user", "root_hardening", "firewall", "fail2ban", "ssh_hardening", "security_updates"]
        admin_data = {
            "mode": "managed",
            "username": "adminuser",
            "fingerprint": "SHA256:admin",
            "validated": True,
            "sudo_mode": "nopasswd",
            "sudo_validated": True,
            "local_password_status": "configured",
            "local_password_usable": True,
        }
        root_data = {
            "mode": "managed",
            "admin_username": "adminuser",
            "admin_validated": True,
            "root_authorized_keys": {"action": "remove_all", "fingerprints": [], "verified": True},
            "root_password": {"action": "lock", "status": "L", "locked": True, "verified": True},
        }
        component_data = {
            "firewall": {"mode": "managed", "ssh_ports": [22]},
            "fail2ban": {"mode": "managed", "ports": [22]},
            "ssh_hardening": {
                "mode": "managed",
                "ports": [25000],
                "activation_mode": "socket",
                "auth_values": {
                    "PubkeyAuthentication": "yes",
                    "PasswordAuthentication": "no",
                    "KbdInteractiveAuthentication": "no",
                    "PermitRootLogin": "no",
                    "PermitEmptyPasswords": "no",
                },
            },
            "security_updates": {"mode": "managed", "enabled": True, "automatic_reboot": False},
        }
        order: list[str] = []

        def ensured(name: str, value: dict):
            def inner(*args, **kwargs):
                order.append(name)
                return value

            return inner

        with tempfile.TemporaryDirectory() as directory:
            tmp_path = Path(directory)
            paths = make_paths(tmp_path)
            state = InstallState.fresh(phases)
            with patch.object(resume, "ensure_admin_user_from_state", side_effect=ensured("admin", admin_data)) as admin, patch.object(
                resume, "ensure_root_hardening_from_state", side_effect=ensured("root", root_data)
            ) as root, patch.object(
                resume, "ensure_firewall_from_state", side_effect=ensured("firewall", component_data["firewall"])
            ) as firewall, patch.object(
                resume, "ensure_fail2ban_from_state", side_effect=ensured("fail2ban", component_data["fail2ban"])
            ) as fail2ban, patch.object(
                resume, "ensure_ssh_hardening_from_state", side_effect=ensured("ssh", component_data["ssh_hardening"])
            ) as ssh, patch.object(
                resume, "ensure_security_updates_from_state", side_effect=ensured("security", component_data["security_updates"])
            ) as security, patch.object(
                resume, "verify_admin_user_state", side_effect=lambda data: data == admin_data
            ), patch.object(
                resume, "verify_root_hardening_state", side_effect=lambda data, admin_state, paths_arg: data == root_data and admin_state == admin_data
            ), patch.object(
                resume, "verify_firewall_state", side_effect=lambda data: data == component_data["firewall"]
            ), patch.object(
                resume, "verify_fail2ban_state", side_effect=lambda data: data == component_data["fail2ban"]
            ), patch.object(
                resume, "verify_expected_ssh_state", side_effect=lambda data: data == component_data["ssh_hardening"]
            ), patch.object(
                resume, "verify_security_updates_state", side_effect=lambda data: data == component_data["security_updates"]
            ):
                first = resume.run_setup(paths, tmp_path, state=state, phases=phases)
                second = resume.run_setup(paths, tmp_path, scope="resume")
                loaded = InstallState.load(paths.state_file)

        self.assertEqual(order, ["admin", "root", "firewall", "fail2ban", "ssh", "security"])
        self.assertEqual(first, [f"DONE {phase}" for phase in phases])
        self.assertEqual(second, [f"SKIP {phase} [already configured]" for phase in phases])
        for phase in phases:
            self.assertEqual(loaded.phases[phase].status, PhaseStatus.DONE)
        for mocked in (admin, root, firewall, fail2ban, ssh, security):
            self.assertEqual(mocked.call_count, 1)
        self.assertEqual(ssh.call_args.kwargs["sudo_mode"], "nopasswd")

    def test_explicit_root_hardening_failure_preserves_saved_backup_progress(self) -> None:
        progress = {
            "mode": "running",
            "admin_username": "adminuser",
            "admin_validated": True,
            "root_authorized_keys": {
                "action": "remove_all",
                "fingerprints": [],
                "backup": "/var/lib/vps-bootstrap/backups/root-hardening/operation/authorized_keys",
                "verified": True,
            },
        }

        def fail_after_backup(data, admin_data, paths, force_reconfigure=False, save_state=None):
            save_state(progress)
            raise resume.RootHardeningError("root password verification failed")

        with tempfile.TemporaryDirectory() as directory:
            paths = make_paths(Path(directory))
            state = InstallState.fresh(["admin_user", "root_hardening"])
            state.update_phase_data(
                "admin_user",
                {"mode": "managed", "username": "adminuser", "validated": True, "sudo_validated": True},
            )
            state.set_phase("admin_user", PhaseStatus.DONE)
            state.save(paths.state_file)
            with patch.object(resume, "ensure_root_hardening_from_state", side_effect=fail_after_backup):
                with self.assertRaisesRegex(resume.SetupError, "root password verification failed"):
                    resume.run_root_hardening_reconfigure(paths)

            loaded = InstallState.load(paths.state_file)

        self.assertEqual(loaded.phases["root_hardening"].status, PhaseStatus.FAILED)
        self.assertEqual(loaded.phases["root_hardening"].data, progress)
