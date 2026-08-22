import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.command import CommandResult
from app.ssh_hardening import (
    SSHDiscovery,
    SSHHardeningError,
    SSHPlan,
    SystemdUnitState,
    TCPListener,
    apply_ssh_plan,
    apply_ssh_plan_data,
    backup_paths_from_metadata,
    build_ssh_plan,
    choose_random_port,
    confirm,
    current_auth_values,
    detect_activation_mode,
    detect_complex_ssh_config,
    ensure_ssh_hardening_from_state,
    list_sshd_config_files,
    manual_rollback_commands,
    ordinary_second_session_command,
    parse_ss_listeners,
    parse_ss_tcp_listeners,
    parse_sshd_t,
    parse_socket_listen_streams,
    parse_systemctl_show_listen_ports,
    parse_ufw_allowed_ports,
    parse_confirmation,
    format_codepoints,
    publickey_only_second_session_command,
    recover_interrupted_migration,
    rollback_ssh,
    second_session_command,
    second_session_validation_command,
    validate_candidate_effective,
    verify_discovered_ssh_state,
)


def discovery(
    *,
    service_active: str = "active",
    socket_active: str = "inactive",
    socket_enabled: str = "disabled",
    socket_ports: list[int] | None = None,
    mode: str = "service",
    ports: set[int] | None = None,
    listeners: set[int] | None = None,
    tcp_listeners: list[TCPListener] | None = None,
    ssh_listeners: set[int] | None = None,
    overrides: list[str] | None = None,
    reliable_key: bool = True,
    sudo_user: bool = True,
    ufw_active: bool = False,
    ufw_allowed: set[int] | None = None,
    current_user: str = "example-user",
    admin_user: str = "example-user",
    complex_reasons: list[str] | None = None,
) -> SSHDiscovery:
    effective = {
        "port": [str(port) for port in sorted(ports or {22})],
        "pubkeyauthentication": ["yes"],
        "passwordauthentication": ["no" if reliable_key else "yes"],
        "kbdinteractiveauthentication": ["no" if reliable_key else "yes"],
        "permitrootlogin": ["no" if sudo_user and reliable_key else "prohibit-password"],
    }
    actual_ports = listeners or ports or {22}
    tcp = tcp_listeners or [TCPListener(f"0.0.0.0:{port}", port, 'users:(("sshd",pid=1,fd=3))') for port in actual_ports]
    return SSHDiscovery(
        openssh_server_installed=True,
        sshd_path="/usr/sbin/sshd",
        service=SystemdUnitState(service_active, "enabled"),
        socket=SystemdUnitState(socket_active, socket_enabled, listen_streams=socket_ports or []),
        activation_mode=mode,
        effective_config=effective,
        tcp_listeners=tcp,
        actual_listeners=listeners or ports or {22},
        actual_ssh_listeners=ssh_listeners if ssh_listeners is not None else actual_ports,
        configured_ports=ports or {22},
        include_files=["/etc/ssh/sshd_config.d/*.conf"],
        sshd_config_files=["/etc/ssh/sshd_config"],
        complex_config_reasons=complex_reasons or [],
        managed_dropin_exists=True,
        systemd_overrides=overrides or [],
        current_user=current_user,
        in_ssh_session=True,
        ssh_connection="192.0.2.1 55555 192.0.2.10 22",
        admin_user=admin_user,
        admin_authorized_keys_exists=True,
        admin_authorized_keys_count=1,
        admin_ssh_permissions_ok=True,
        sudo_non_root_user_exists=sudo_user,
        ufw_installed=True,
        ufw_active=ufw_active,
        ufw_allowed_ports=ufw_allowed or set(),
    )


class SSHHardeningTests(unittest.TestCase):
    def test_detect_ssh_socket_mode(self) -> None:
        mode = detect_activation_mode(SystemdUnitState("inactive", "disabled"), SystemdUnitState("active", "enabled", listen_streams=[22]), [])

        self.assertEqual(mode, "socket")

    def test_detect_ssh_service_mode(self) -> None:
        mode = detect_activation_mode(SystemdUnitState("active", "enabled"), SystemdUnitState("inactive", "disabled"), [])

        self.assertEqual(mode, "service")

    def test_detect_custom_systemd_override(self) -> None:
        mode = detect_activation_mode(SystemdUnitState("active", "enabled"), SystemdUnitState("inactive", "disabled"), ["/etc/systemd/system/ssh.service.d/custom.conf"])

        self.assertEqual(mode, "custom")

    def test_parse_sshd_t(self) -> None:
        parsed = parse_sshd_t("port 22\nport 2222\npasswordauthentication no\n")

        self.assertEqual(parsed["port"], ["22", "2222"])
        self.assertEqual(parsed["passwordauthentication"], ["no"])

    def test_distinguish_configured_vs_actual_listener(self) -> None:
        disc = discovery(ports={2222}, listeners={22}, ssh_listeners={22})
        data = {"ports": [2222], "activation_mode": "socket", "auth_values": {}}

        with patch("app.ssh_hardening.run_command", return_value=CommandResult(["sshd", "-t"], 0, "", "")):
            self.assertFalse(verify_discovered_ssh_state(disc, data))

    def test_sshd_t_new_port_but_ss_old_port_is_drift(self) -> None:
        disc = discovery(mode="socket", socket_active="active", socket_ports=[22], ports={2222}, listeners={22}, ssh_listeners={22})
        data = {"ports": [2222], "activation_mode": "socket", "auth_values": {"PasswordAuthentication": "no"}}

        with patch("app.ssh_hardening.run_command", return_value=CommandResult(["sshd", "-t"], 0, "", "")):
            self.assertFalse(verify_discovered_ssh_state(disc, data))

    def test_port_collision_detection(self) -> None:
        with self.assertRaisesRegex(SSHHardeningError, "already used"):
            build_ssh_plan(discovery(listeners={22, 25000}), 25000)

    def test_random_port_selection_avoids_occupied_ports(self) -> None:
        for _ in range(20):
            port = choose_random_port(set(range(20000, 20050)))
            self.assertNotIn(port, set(range(20000, 20050)))

    def test_two_port_transition_plan(self) -> None:
        plan = build_ssh_plan(discovery(ports={22}, listeners={22}), 25000)

        self.assertEqual(plan.target_ports, {22, 25000})
        self.assertEqual(plan.final_ports, {25000})
        self.assertTrue(plan.requires_two_port_confirmation)

    def test_failed_new_listener_rolls_back(self) -> None:
        plan = SSHPlan({22}, {22, 25000}, {25000}, "service", {"PubkeyAuthentication": "yes"}, {"PubkeyAuthentication": "yes"})
        with patch("app.ssh_hardening.backup_ssh_files", return_value={}), patch("app.ssh_hardening.write_atomic"), patch(
            "app.ssh_hardening.apply_systemd_ssh"
        ), patch("app.ssh_hardening.validate_candidate_effective"), patch("app.ssh_hardening.verify_transition_listeners", return_value=False), patch(
            "app.ssh_hardening.rollback_ssh"
        ) as rollback:
            with self.assertRaisesRegex(SSHHardeningError, "listener"):
                apply_ssh_plan(plan)

        rollback.assert_called_once()

    def test_user_does_not_confirm_new_ssh_login_restores_old_port(self) -> None:
        plan = SSHPlan({22}, {22, 25000}, {25000}, "service", {"PubkeyAuthentication": "yes"}, {"PubkeyAuthentication": "yes"}, requires_two_port_confirmation=True)
        with patch("app.ssh_hardening.backup_ssh_files", return_value={}), patch("app.ssh_hardening.write_atomic"), patch(
            "app.ssh_hardening.apply_systemd_ssh"
        ), patch("app.ssh_hardening.validate_candidate_effective"), patch("app.ssh_hardening.verify_transition_listeners", return_value=True), patch(
            "app.ssh_hardening.rollback_ssh"
        ) as rollback, patch("builtins.input", return_value="n"):
            with self.assertRaisesRegex(SSHHardeningError, "not confirmed"):
                apply_ssh_plan(plan)

        rollback.assert_called_once()

    def test_second_session_no_saves_completed_rollback_state(self) -> None:
        plan = SSHPlan({22}, {22, 25000}, {25000}, "service", {"PubkeyAuthentication": "yes"}, {"PubkeyAuthentication": "yes"}, requires_two_port_confirmation=True)
        snapshots: list[dict] = []
        with patch("app.ssh_hardening.backup_ssh_files", return_value={}), patch("app.ssh_hardening.write_atomic"), patch(
            "app.ssh_hardening.apply_systemd_ssh"
        ), patch("app.ssh_hardening.validate_candidate_effective"), patch("app.ssh_hardening.verify_transition_listeners", return_value=True), patch(
            "app.ssh_hardening.rollback_ssh"
        ), patch("builtins.input", return_value="n"):
            with self.assertRaisesRegex(SSHHardeningError, "not confirmed"):
                apply_ssh_plan(plan, save_state=snapshots.append)

        self.assertEqual(snapshots[-1]["migration_stage"], "rolled_back")
        self.assertFalse(snapshots[-1]["interrupted_migration"])
        self.assertTrue(snapshots[-1]["rolled_back"])
        self.assertEqual(snapshots[-1]["ports"], [22])

    def test_user_confirms_new_ssh_login_allows_final_port(self) -> None:
        plan = SSHPlan({22}, {22, 25000}, {25000}, "service", {"PubkeyAuthentication": "yes"}, {"PubkeyAuthentication": "yes"}, requires_two_port_confirmation=True)
        with patch("app.ssh_hardening.backup_ssh_files", return_value={}), patch("app.ssh_hardening.write_atomic") as write, patch(
            "app.ssh_hardening.apply_systemd_ssh"
        ), patch("app.ssh_hardening.validate_candidate_effective"), patch("app.ssh_hardening.verify_transition_listeners", return_value=True), patch(
            "app.ssh_hardening.verify_expected_ssh_state", return_value=True
        ), patch("builtins.input", return_value="y"):
            data = apply_ssh_plan(plan)

        self.assertEqual(data["ports"], [25000])
        self.assertGreaterEqual(write.call_count, 2)

    def test_keep_current_port_no_auth_change_verifies_without_writes(self) -> None:
        disc = discovery(reliable_key=False, ports={22}, listeners={22}, ssh_listeners={22})
        plan = build_ssh_plan(disc, None, keep_current_port=True, publickey_confirmed=False)
        saved: list[dict] = []

        with patch("app.ssh_hardening.run_command", return_value=CommandResult(["sshd", "-t"], 0, "", "")), patch(
            "app.ssh_hardening.backup_ssh_files"
        ) as backup, patch("app.ssh_hardening.write_atomic") as write, patch("app.ssh_hardening.apply_systemd_ssh") as systemd:
            data = apply_ssh_plan(plan, save_state=saved.append, discovery=disc)

        self.assertEqual(data["ports"], [22])
        self.assertFalse(data["interrupted_migration"])
        self.assertEqual(saved[-1]["ports"], [22])
        backup.assert_not_called()
        write.assert_not_called()
        systemd.assert_not_called()

    def test_transition_config_keeps_auth_until_second_session_confirmation(self) -> None:
        plan = SSHPlan(
            {22},
            {22, 25000},
            {25000},
            "service",
            {"PubkeyAuthentication": "yes", "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no"},
            {"PubkeyAuthentication": "yes", "PasswordAuthentication": "yes", "KbdInteractiveAuthentication": "yes"},
            requires_two_port_confirmation=True,
            requires_publickey_confirmation=True,
        )
        written: list[str] = []

        def capture_write(_path, content, _mode):
            written.append(content)

        with patch("app.ssh_hardening.backup_ssh_files", return_value={}), patch("app.ssh_hardening.write_atomic", side_effect=capture_write), patch(
            "app.ssh_hardening.apply_systemd_ssh"
        ), patch("app.ssh_hardening.validate_candidate_effective"), patch("app.ssh_hardening.verify_transition_listeners", return_value=True), patch(
            "app.ssh_hardening.verify_expected_ssh_state", return_value=True
        ), patch("builtins.input", return_value="y"):
            apply_ssh_plan(plan)

        self.assertIn("PasswordAuthentication yes", written[0])
        self.assertIn("KbdInteractiveAuthentication yes", written[0])
        self.assertTrue(any("PasswordAuthentication no" in item for item in written[1:]))

    def test_pubkey_disabled_auth_hardening_uses_validation_transition(self) -> None:
        disc = discovery(reliable_key=False)
        disc = SSHDiscovery(**{**disc.__dict__, "effective_config": {**disc.effective_config, "pubkeyauthentication": ["no"]}})

        plan = build_ssh_plan(disc, None, keep_current_port=True, publickey_confirmed=True)

        self.assertEqual(plan.transition_auth_values["PubkeyAuthentication"], "yes")
        self.assertEqual(plan.transition_auth_values["PasswordAuthentication"], "yes")
        self.assertEqual(plan.transition_auth_values["KbdInteractiveAuthentication"], "yes")
        self.assertEqual(plan.auth_values["PubkeyAuthentication"], "yes")
        self.assertEqual(plan.auth_values["PasswordAuthentication"], "no")

    def test_pubkey_enabled_auth_hardening_keeps_transition_pubkey_unchanged(self) -> None:
        plan = build_ssh_plan(discovery(reliable_key=False), None, keep_current_port=True, publickey_confirmed=True)

        self.assertEqual(plan.transition_auth_values["PubkeyAuthentication"], "yes")
        self.assertEqual(plan.transition_auth_values["PasswordAuthentication"], "yes")

    def test_port_only_migration_does_not_change_pubkey_disabled_auth_policy(self) -> None:
        disc = discovery(reliable_key=False)
        disc = SSHDiscovery(**{**disc.__dict__, "effective_config": {**disc.effective_config, "pubkeyauthentication": ["no"]}})

        plan = build_ssh_plan(disc, 25000, publickey_confirmed=False)

        self.assertEqual(plan.transition_auth_values["PubkeyAuthentication"], "no")
        self.assertEqual(plan.auth_values["PubkeyAuthentication"], "no")
        self.assertEqual(plan.transition_auth_values["PasswordAuthentication"], "yes")
        self.assertEqual(plan.auth_values["PasswordAuthentication"], "yes")

    def test_apply_this_ssh_port_y_continues_workflow(self) -> None:
        with patch("app.ssh_hardening.discover_ssh", return_value=discovery()), patch(
            "app.ssh_hardening.choose_random_port", return_value=25000
        ), patch(
            "app.ssh_hardening.apply_ssh_plan",
            return_value={"mode": "managed", "ports": [25000], "activation_mode": "service", "auth_values": {}},
        ) as apply, patch(
            "builtins.input", side_effect=["1", "y", "n", "y"]
        ):
            data = ensure_ssh_hardening_from_state({})

        self.assertEqual(data["ports"], [25000])
        apply.assert_called_once()

    def test_port_only_with_pubkey_disabled_uses_ordinary_new_port_validation(self) -> None:
        disc = discovery(reliable_key=False)
        disc = SSHDiscovery(**{**disc.__dict__, "effective_config": {**disc.effective_config, "pubkeyauthentication": ["no"]}})
        plan = build_ssh_plan(disc, 25000, publickey_confirmed=False)

        command = second_session_validation_command(plan, disc)

        self.assertTrue(plan.requires_two_port_confirmation)
        self.assertFalse(plan.requires_publickey_confirmation)
        self.assertEqual(command, ordinary_second_session_command(disc, 25000))
        self.assertEqual(command, "ssh -p 25000 example-user@192.0.2.10")
        self.assertNotIn("PreferredAuthentications=publickey", command)
        self.assertNotIn("PasswordAuthentication=no", command)

    def test_port_only_with_pubkey_enabled_uses_ordinary_new_port_validation(self) -> None:
        disc = discovery(reliable_key=True)
        plan = build_ssh_plan(disc, 25000, publickey_confirmed=False)

        command = second_session_validation_command(plan, disc)

        self.assertTrue(plan.requires_two_port_confirmation)
        self.assertFalse(plan.requires_publickey_confirmation)
        self.assertEqual(command, "ssh -p 25000 example-user@192.0.2.10")
        self.assertNotIn("PreferredAuthentications=publickey", command)

    def test_port_migration_with_auth_hardening_uses_publickey_validation_on_new_port(self) -> None:
        disc = discovery(reliable_key=False)
        plan = build_ssh_plan(disc, 25000, publickey_confirmed=True)

        command = second_session_validation_command(plan, disc)

        self.assertTrue(plan.requires_two_port_confirmation)
        self.assertTrue(plan.requires_publickey_confirmation)
        self.assertEqual(command, publickey_only_second_session_command(disc, 25000))
        self.assertIn("-o PreferredAuthentications=publickey", command)
        self.assertIn("-o PasswordAuthentication=no", command)
        self.assertIn("-p 25000 example-user@192.0.2.10", command)

    def test_auth_hardening_without_port_change_uses_publickey_validation_on_current_port(self) -> None:
        disc = discovery(reliable_key=False, ports={22}, listeners={22}, ssh_listeners={22})
        plan = build_ssh_plan(disc, None, keep_current_port=True, publickey_confirmed=True)

        command = second_session_validation_command(plan, disc)

        self.assertFalse(plan.requires_two_port_confirmation)
        self.assertTrue(plan.requires_publickey_confirmation)
        self.assertIn("-o PreferredAuthentications=publickey", command)
        self.assertIn("-o PasswordAuthentication=no", command)
        self.assertIn("-p 22 example-user@192.0.2.10", command)

    def test_active_ufw_without_new_allow_rule_blocks_unsafe_finalization(self) -> None:
        plan = build_ssh_plan(discovery(ufw_active=True, ufw_allowed={22}), 25000)

        self.assertTrue(any("UFW is active" in reason for reason in plan.blocked_reasons))

    def test_root_session_without_verified_sudo_user_blocks_permit_root_no(self) -> None:
        plan = build_ssh_plan(discovery(sudo_user=False, reliable_key=True, current_user="root", admin_user="root"), None, keep_current_port=True)

        self.assertNotEqual(plan.auth_values.get("PermitRootLogin"), "no")

    def test_without_publickey_confirmation_password_disable_is_not_planned(self) -> None:
        plan = build_ssh_plan(discovery(reliable_key=False), None, keep_current_port=True, publickey_confirmed=False)

        self.assertNotEqual(plan.auth_values.get("PasswordAuthentication"), "no")

    def test_parse_confirmation_accepts_strict_yes_with_nfkc(self) -> None:
        for value in ["y", "Y", "yes", "YES", "Yes", " y ", "ｙ", "Ｙ", "ｙｅｓ"]:
            with self.subTest(value=value):
                self.assertTrue(parse_confirmation(value))

    def test_parse_confirmation_rejects_no_empty_and_unknown(self) -> None:
        for value in ["", "n", "N", "no", "NO"]:
            with self.subTest(value=value):
                self.assertFalse(parse_confirmation(value))
        for value in ["maybe", "yep", "да"]:
            with self.subTest(value=value):
                self.assertIsNone(parse_confirmation(value))

    def test_parse_confirmation_empty_uses_default(self) -> None:
        self.assertTrue(parse_confirmation("", default=True))
        self.assertFalse(parse_confirmation("", default=False))

    def test_confirm_reprompts_unknown_then_accepts_yes(self) -> None:
        with patch("builtins.input", side_effect=["maybe", "y"]), patch("builtins.print") as printed:
            self.assertTrue(confirm("Apply? [y/N]: "))

        text = "\n".join(str(call.args[0]) for call in printed.call_args_list)
        self.assertIn("Unrecognized confirmation input", text)
        self.assertIn("U+006D", text)
        self.assertNotIn("maybe", text)

    def test_confirm_reprompts_unknown_then_accepts_no(self) -> None:
        with patch("builtins.input", side_effect=["maybe", "n"]):
            self.assertFalse(confirm("Apply? [y/N]: "))

    def test_confirm_eof_returns_default_safely(self) -> None:
        with patch("builtins.input", side_effect=EOFError):
            self.assertFalse(confirm("Apply? [y/N]: "))
        with patch("builtins.input", side_effect=EOFError):
            self.assertTrue(confirm("Apply? [Y/n]: ", default=True))

    def test_format_codepoints_does_not_need_raw_input(self) -> None:
        self.assertEqual(format_codepoints("\x1b[y"), "U+001B U+005B U+0079")

    def test_sshd_t_failure_is_verifier_failure(self) -> None:
        disc = discovery(ports={22}, listeners={22})
        data = {"ports": [22], "activation_mode": "service", "auth_values": {}}
        with patch("app.ssh_hardening.run_command", return_value=CommandResult(["sshd", "-t"], 1, "", "bad")):
            self.assertFalse(verify_discovered_ssh_state(disc, data))

    def test_managed_dropin_conflict_effective_mismatch_fails(self) -> None:
        disc = discovery(ports={22}, listeners={22})
        data = {"ports": [22], "activation_mode": "service", "auth_values": {"PasswordAuthentication": "yes"}}
        with patch("app.ssh_hardening.run_command", return_value=CommandResult(["sshd", "-t"], 0, "", "")):
            self.assertFalse(verify_discovered_ssh_state(disc, data))

    def test_resume_interrupted_migration_never_blindly_disables_old_port(self) -> None:
        data = {"mode": "managed", "ports": [25000], "activation_mode": "service", "interrupted_migration": True}

        with self.assertRaisesRegex(SSHHardeningError, "Interrupted SSH migration"):
            apply_ssh_plan_data(data)

    def test_managed_repair_validates_candidate_before_systemd_apply(self) -> None:
        data = {"mode": "managed", "ports": [25000], "activation_mode": "service", "auth_values": {"PubkeyAuthentication": "yes"}}
        events: list[str] = []

        with patch("app.ssh_hardening.discover_ssh", return_value=discovery(ports={22}, listeners={22}, ssh_listeners={22})), patch(
            "app.ssh_hardening.backup_ssh_files", return_value={}
        ), patch("app.ssh_hardening.write_atomic"), patch("app.ssh_hardening.validate_candidate_effective", side_effect=lambda *args: events.append("candidate")), patch(
            "app.ssh_hardening.apply_systemd_ssh", side_effect=lambda *args: events.append("systemd")
        ), patch("app.ssh_hardening.verify_transition_listeners", return_value=True):
            apply_ssh_plan_data(data)

        self.assertEqual(events, ["candidate", "systemd"])

    def test_managed_repair_rollback_verifies_original_pre_repair_listener(self) -> None:
        data = {"mode": "managed", "ports": [25000], "activation_mode": "service", "auth_values": {"PubkeyAuthentication": "yes"}}

        with patch("app.ssh_hardening.discover_ssh", return_value=discovery(ports={22}, listeners={22}, ssh_listeners={22})), patch(
            "app.ssh_hardening.backup_ssh_files", return_value={}
        ), patch("app.ssh_hardening.write_atomic"), patch(
            "app.ssh_hardening.validate_candidate_effective", side_effect=SSHHardeningError("candidate mismatch")
        ), patch("app.ssh_hardening.rollback_ssh") as rollback:
            with self.assertRaisesRegex(SSHHardeningError, "candidate mismatch"):
                apply_ssh_plan_data(data)

        rollback.assert_called_once_with({}, "service", {22})

    def test_verifier_success_path(self) -> None:
        disc = discovery(ports={25000}, listeners={25000}, ssh_listeners={25000})
        data = {
            "ports": [25000],
            "activation_mode": "service",
            "auth_values": {"PasswordAuthentication": "no", "PubkeyAuthentication": "yes"},
        }

        with patch("app.ssh_hardening.run_command", return_value=CommandResult(["sshd", "-t"], 0, "", "")):
            self.assertTrue(verify_discovered_ssh_state(disc, data))

    def test_parse_actual_listeners(self) -> None:
        output = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"

        self.assertEqual(parse_ss_listeners(output), {22})

    def test_parse_socket_listen_streams(self) -> None:
        self.assertEqual(parse_socket_listen_streams("ListenStream=22\nListenStream=\nListenStream=25000\n"), [25000])

    def test_parse_systemctl_show_listen_ports(self) -> None:
        output = "Listen=0.0.0.0:25000 (Stream) [::]:25000 (Stream)\nTriggeredBy=\n"

        self.assertEqual(parse_systemctl_show_listen_ports(output), [25000, 25000])

    def test_parse_ufw_allowed_ports(self) -> None:
        self.assertEqual(parse_ufw_allowed_ports("22/tcp ALLOW Anywhere\n25000/tcp ALLOW Anywhere\n"), {22, 25000})

    def test_authenticationmethods_blocks_auth_hardening(self) -> None:
        plan = build_ssh_plan(
            discovery(reliable_key=False, complex_reasons=["AuthenticationMethods in /etc/ssh/sshd_config.d/01-custom.conf"]),
            None,
            keep_current_port=True,
            publickey_confirmed=True,
        )

        self.assertTrue(any("complex SSH config" in reason for reason in plan.blocked_reasons))

    def test_match_block_blocks_auth_hardening_but_port_plan_can_exist(self) -> None:
        plan = build_ssh_plan(
            discovery(complex_reasons=["Match block in /etc/ssh/sshd_config"]),
            25000,
            publickey_confirmed=False,
        )

        self.assertEqual(plan.target_ports, {22, 25000})
        self.assertFalse(any("complex SSH config" in reason for reason in plan.blocked_reasons))

    def test_parse_realistic_ss_h_ipv4_ipv6_with_process(self) -> None:
        output = "\n".join(
            [
                'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=111,fd=3))',
                'LISTEN 0 4096 [::]:25000 [::]:* users:(("systemd",pid=1,fd=42))',
            ]
        )

        listeners = parse_ss_tcp_listeners(output)

        self.assertEqual([listener.port for listener in listeners], [22, 25000])
        self.assertTrue(listeners[0].looks_like_sshd)
        self.assertTrue(listeners[1].looks_like_systemd)

    def test_publickey_second_session_command_uses_discovered_ipv4(self) -> None:
        command = publickey_only_second_session_command(discovery(), 25000)

        self.assertIn("-o PreferredAuthentications=publickey", command)
        self.assertIn("-o PasswordAuthentication=no", command)
        self.assertIn("-p 25000 example-user@192.0.2.10", command)

    def test_publickey_second_session_command_formats_ipv6(self) -> None:
        disc = discovery()
        disc = SSHDiscovery(**{**disc.__dict__, "ssh_connection": "2001:db8::1 555 2001:db8::10 22"})

        command = publickey_only_second_session_command(disc, 25000)

        self.assertIn("example-user@[2001:db8::10]", command)

    def test_legacy_second_session_command_remains_publickey_only(self) -> None:
        command = second_session_command(discovery(), 25000)

        self.assertEqual(command, publickey_only_second_session_command(discovery(), 25000))

    def test_service_verifier_rejects_non_ssh_process_on_expected_port(self) -> None:
        disc = discovery(
            ports={25000},
            listeners={25000},
            ssh_listeners=set(),
            tcp_listeners=[TCPListener("0.0.0.0:25000", 25000, 'users:(("nc",pid=7,fd=3))')],
        )
        data = {"ports": [25000], "activation_mode": "service", "auth_values": {}}
        with patch("app.ssh_hardening.run_command", return_value=CommandResult(["sshd", "-t"], 0, "", "")):
            self.assertFalse(verify_discovered_ssh_state(disc, data))

    def test_final_verifier_rejects_extra_effective_ssh_port(self) -> None:
        disc = discovery(ports={25000, 26000}, listeners={25000, 26000}, ssh_listeners={25000, 26000})
        data = {"ports": [25000], "activation_mode": "service", "auth_values": {}}

        with patch("app.ssh_hardening.run_command", return_value=CommandResult(["sshd", "-t"], 0, "", "")):
            self.assertFalse(verify_discovered_ssh_state(disc, data))

    def test_final_verifier_rejects_stale_old_ssh_port(self) -> None:
        disc = discovery(ports={25000}, listeners={22, 25000}, ssh_listeners={22, 25000})
        data = {"ports": [25000], "old_ports": [22], "activation_mode": "service", "auth_values": {}}
        with patch("app.ssh_hardening.run_command", return_value=CommandResult(["sshd", "-t"], 0, "", "")):
            self.assertFalse(verify_discovered_ssh_state(disc, data))

    def test_socket_verifier_rejects_stale_old_ssh_listener(self) -> None:
        disc = discovery(
            mode="socket",
            socket_active="active",
            socket_enabled="enabled",
            socket_ports=[25000],
            ports={25000},
            listeners={22, 25000},
            ssh_listeners={22, 25000},
        )
        data = {"ports": [25000], "old_ports": [22], "activation_mode": "socket", "auth_values": {}}

        with patch("app.ssh_hardening.run_command", return_value=CommandResult(["sshd", "-t"], 0, "", "")):
            self.assertFalse(verify_discovered_ssh_state(disc, data))

    def test_candidate_effective_mismatch_rolls_back_before_systemd_apply(self) -> None:
        plan = SSHPlan({22}, {22, 25000}, {25000}, "service", {"PubkeyAuthentication": "yes"}, {"PubkeyAuthentication": "yes"})
        with patch("app.ssh_hardening.backup_ssh_files", return_value={}), patch("app.ssh_hardening.write_atomic"), patch(
            "app.ssh_hardening.validate_candidate_effective", side_effect=SSHHardeningError("candidate mismatch")
        ), patch("app.ssh_hardening.apply_systemd_ssh") as apply_systemd, patch("app.ssh_hardening.rollback_ssh") as rollback:
            with self.assertRaisesRegex(SSHHardeningError, "candidate mismatch"):
                apply_ssh_plan(plan)

        apply_systemd.assert_not_called()
        rollback.assert_called_once()

    def test_validate_candidate_effective_checks_sshd_t_before_systemd_apply_inputs(self) -> None:
        results = [
            CommandResult(["sshd", "-t"], 0, "", ""),
            CommandResult(["sshd", "-T"], 0, "port 25000\npubkeyauthentication yes\npasswordauthentication no\n", ""),
        ]

        with patch("app.ssh_hardening.run_command", side_effect=results) as command:
            validate_candidate_effective({25000}, {"PubkeyAuthentication": "yes", "PasswordAuthentication": "no"})

        self.assertEqual(command.call_args_list[0].args[0], ["sshd", "-t"])
        self.assertEqual(command.call_args_list[1].args[0], ["sshd", "-T"])

    def test_custom_include_file_blocks_auth_hardening(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            main = root / "sshd_config"
            include = root / "custom.conf"
            dropin = root / "sshd_config.d"
            dropin.mkdir()
            main.write_text("Include custom.conf\n", encoding="utf-8")
            include.write_text("AuthenticationMethods publickey,password\n", encoding="utf-8")

            with patch("app.ssh_hardening.SSHD_CONFIG", main), patch("app.ssh_hardening.SSHD_CONFIG_D", dropin):
                files, include_reasons = list_sshd_config_files()
                complex_reasons = detect_complex_ssh_config(files)

            self.assertEqual(include_reasons, [])
            self.assertIn(str(include), {str(path) for path in files})
            self.assertTrue(any("AuthenticationMethods" in reason for reason in complex_reasons))

    def test_unmatched_include_blocks_auth_hardening(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            main = root / "sshd_config"
            dropin = root / "sshd_config.d"
            dropin.mkdir()
            main.write_text("Include missing/*.conf\n", encoding="utf-8")

            with patch("app.ssh_hardening.SSHD_CONFIG", main), patch("app.ssh_hardening.SSHD_CONFIG_D", dropin):
                _files, include_reasons = list_sshd_config_files()

        self.assertTrue(any("did not match" in reason for reason in include_reasons))

    def test_permit_root_login_no_requires_sudo_confirmation(self) -> None:
        plan = build_ssh_plan(
            discovery(reliable_key=False, sudo_user=True, admin_user="example-user"),
            None,
            keep_current_port=True,
            publickey_confirmed=True,
            request_root_disable=True,
        )

        self.assertEqual(plan.auth_values["PermitRootLogin"], "no")
        self.assertTrue(plan.requires_sudo_confirmation)

    def test_permit_root_login_no_after_sudo_confirmation_does_not_require_second_sudo_prompt(self) -> None:
        plan = build_ssh_plan(
            discovery(reliable_key=False, sudo_user=True, admin_user="example-user"),
            None,
            keep_current_port=True,
            publickey_confirmed=True,
            request_root_disable=True,
            sudo_confirmed=True,
        )

        self.assertEqual(plan.auth_values["PermitRootLogin"], "no")
        self.assertFalse(plan.requires_sudo_confirmation)

    def test_sudo_confirmation_default_no_rolls_back_before_root_disable_finalization(self) -> None:
        plan = SSHPlan(
            {22},
            {22, 25000},
            {25000},
            "service",
            {"PubkeyAuthentication": "yes", "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no", "PermitRootLogin": "no"},
            {"PubkeyAuthentication": "yes", "PasswordAuthentication": "yes", "KbdInteractiveAuthentication": "yes", "PermitRootLogin": "prohibit-password"},
            requires_two_port_confirmation=True,
            requires_publickey_confirmation=True,
            requires_sudo_confirmation=True,
        )

        with patch("app.ssh_hardening.backup_ssh_files", return_value={}), patch("app.ssh_hardening.write_atomic"), patch(
            "app.ssh_hardening.apply_systemd_ssh"
        ), patch("app.ssh_hardening.validate_candidate_effective"), patch("app.ssh_hardening.verify_transition_listeners", return_value=True), patch(
            "app.ssh_hardening.rollback_ssh"
        ) as rollback, patch("builtins.input", side_effect=["y", "n"]):
            with self.assertRaisesRegex(SSHHardeningError, "Sudo validation"):
                apply_ssh_plan(plan)

        rollback.assert_called_once()

    def test_sudo_confirmation_no_saves_completed_rollback_state(self) -> None:
        plan = SSHPlan(
            {22},
            {22, 25000},
            {25000},
            "service",
            {"PubkeyAuthentication": "yes", "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no", "PermitRootLogin": "no"},
            {"PubkeyAuthentication": "yes", "PasswordAuthentication": "yes", "KbdInteractiveAuthentication": "yes", "PermitRootLogin": "prohibit-password"},
            requires_two_port_confirmation=True,
            requires_publickey_confirmation=True,
            requires_sudo_confirmation=True,
        )
        snapshots: list[dict] = []

        with patch("app.ssh_hardening.backup_ssh_files", return_value={}), patch("app.ssh_hardening.write_atomic"), patch(
            "app.ssh_hardening.apply_systemd_ssh"
        ), patch("app.ssh_hardening.validate_candidate_effective"), patch("app.ssh_hardening.verify_transition_listeners", return_value=True), patch(
            "app.ssh_hardening.rollback_ssh"
        ), patch("builtins.input", side_effect=["y", "n"]):
            with self.assertRaisesRegex(SSHHardeningError, "Sudo validation"):
                apply_ssh_plan(plan, save_state=snapshots.append)

        self.assertEqual(snapshots[-1]["migration_stage"], "rolled_back")
        self.assertFalse(snapshots[-1]["interrupted_migration"])

    def test_publickey_confirmation_no_saves_completed_rollback_state(self) -> None:
        plan = SSHPlan(
            {22},
            {22},
            {22},
            "service",
            {"PubkeyAuthentication": "yes", "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no"},
            {"PubkeyAuthentication": "yes", "PasswordAuthentication": "yes", "KbdInteractiveAuthentication": "yes"},
            requires_publickey_confirmation=True,
        )
        snapshots: list[dict] = []

        with patch("app.ssh_hardening.backup_ssh_files", return_value={}), patch("app.ssh_hardening.write_atomic"), patch(
            "app.ssh_hardening.apply_systemd_ssh"
        ), patch("app.ssh_hardening.validate_candidate_effective"), patch("app.ssh_hardening.verify_transition_listeners", return_value=True), patch(
            "app.ssh_hardening.rollback_ssh"
        ), patch("builtins.input", return_value="n"):
            with self.assertRaisesRegex(SSHHardeningError, "Publickey-only SSH login"):
                apply_ssh_plan(plan, save_state=snapshots.append)

        self.assertEqual(snapshots[-1]["migration_stage"], "rolled_back")
        self.assertFalse(snapshots[-1]["interrupted_migration"])

    def test_current_auth_values_reflects_effective_pubkeyauthentication(self) -> None:
        disc = discovery()
        disc = SSHDiscovery(**{**disc.__dict__, "effective_config": {**disc.effective_config, "pubkeyauthentication": ["no"]}})

        self.assertEqual(current_auth_values(disc)["PubkeyAuthentication"], "no")

    def test_migration_state_is_saved_before_first_write(self) -> None:
        plan = SSHPlan({22}, {22, 25000}, {25000}, "service", {"PubkeyAuthentication": "yes"}, {"PubkeyAuthentication": "yes"})
        events: list[str] = []

        def save_state(data):
            events.append(f"save:{data['migration_stage']}")

        def write(*args, **kwargs):
            events.append("write")

        with patch("app.ssh_hardening.backup_ssh_files", return_value={}), patch("app.ssh_hardening.write_atomic", side_effect=write), patch(
            "app.ssh_hardening.validate_candidate_effective"
        ), patch("app.ssh_hardening.apply_systemd_ssh"), patch("app.ssh_hardening.verify_transition_listeners", return_value=False), patch(
            "app.ssh_hardening.rollback_ssh"
        ):
            with self.assertRaises(SSHHardeningError):
                apply_ssh_plan(plan, save_state=save_state)

        self.assertLess(events.index("save:planned"), events.index("write"))
        self.assertIn("save:transition_applying", events)

    def test_migration_state_records_backup_metadata_before_first_write(self) -> None:
        plan = SSHPlan({22}, {22, 25000}, {25000}, "service", {"PubkeyAuthentication": "yes"}, {"PubkeyAuthentication": "yes"})
        snapshots: list[dict] = []

        def save_state(data):
            snapshots.append(dict(data))

        def write(*args, **kwargs):
            self.assertTrue(any("backup_metadata" in item for item in snapshots))
            raise SSHHardeningError("stop before live write")

        with patch("app.ssh_hardening.backup_ssh_files", return_value={"dropin": None, "socket": None}), patch(
            "app.ssh_hardening.write_atomic", side_effect=write
        ), patch("app.ssh_hardening.rollback_ssh"):
            with self.assertRaisesRegex(SSHHardeningError, "stop before live write"):
                apply_ssh_plan(plan, save_state=save_state)

        self.assertIn("backup_metadata", snapshots[-1])

    def test_exception_after_transition_saves_completed_rollback_state(self) -> None:
        plan = SSHPlan({22}, {22, 25000}, {25000}, "service", {"PubkeyAuthentication": "yes"}, {"PubkeyAuthentication": "yes"})
        snapshots: list[dict] = []

        with patch("app.ssh_hardening.backup_ssh_files", return_value={}), patch("app.ssh_hardening.write_atomic"), patch(
            "app.ssh_hardening.validate_candidate_effective"
        ), patch("app.ssh_hardening.apply_systemd_ssh"), patch("app.ssh_hardening.verify_transition_listeners", return_value=False), patch(
            "app.ssh_hardening.rollback_ssh"
        ):
            with self.assertRaisesRegex(SSHHardeningError, "listener"):
                apply_ssh_plan(plan, save_state=snapshots.append)

        self.assertEqual(snapshots[-1]["migration_stage"], "rolled_back")
        self.assertFalse(snapshots[-1]["interrupted_migration"])

    def test_failed_automatic_rollback_does_not_mark_state_rolled_back(self) -> None:
        plan = SSHPlan({22}, {22, 25000}, {25000}, "service", {"PubkeyAuthentication": "yes"}, {"PubkeyAuthentication": "yes"})
        snapshots: list[dict] = []

        with patch("app.ssh_hardening.backup_ssh_files", return_value={}), patch("app.ssh_hardening.write_atomic"), patch(
            "app.ssh_hardening.validate_candidate_effective"
        ), patch("app.ssh_hardening.apply_systemd_ssh"), patch("app.ssh_hardening.verify_transition_listeners", return_value=False), patch(
            "app.ssh_hardening.rollback_ssh", side_effect=SSHHardeningError("rollback failed")
        ):
            with self.assertRaisesRegex(SSHHardeningError, "rollback failed"):
                apply_ssh_plan(plan, save_state=snapshots.append)

        self.assertNotEqual(snapshots[-1]["migration_stage"], "rolled_back")
        self.assertTrue(snapshots[-1]["interrupted_migration"])

    def test_generated_final_state_keeps_old_ports_for_stale_listener_detection(self) -> None:
        plan = SSHPlan({22}, {22, 25000}, {25000}, "service", {"PubkeyAuthentication": "yes"}, {"PubkeyAuthentication": "yes"}, requires_two_port_confirmation=True)

        with patch("app.ssh_hardening.backup_ssh_files", return_value={}), patch("app.ssh_hardening.write_atomic"), patch(
            "app.ssh_hardening.apply_systemd_ssh"
        ), patch("app.ssh_hardening.validate_candidate_effective"), patch("app.ssh_hardening.verify_transition_listeners", return_value=True), patch(
            "app.ssh_hardening.verify_expected_ssh_state", return_value=True
        ), patch("builtins.input", return_value="y"):
            data = apply_ssh_plan(plan)

        self.assertEqual(data["old_ports"], [22])

    def test_interrupted_recovery_default_leaves_current_state_unchanged(self) -> None:
        data = {"mode": "migration", "interrupted_migration": True, "old_ports": [22], "activation_mode": "service", "backup_metadata": {}}

        with patch("builtins.input", return_value=""), patch("app.ssh_hardening.rollback_ssh") as rollback:
            with self.assertRaisesRegex(SSHHardeningError, "left unchanged"):
                recover_interrupted_migration(data)

        rollback.assert_not_called()

    def test_interrupted_recovery_with_valid_backup_metadata_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "10-vps-bootstrap.conf"
            backup = root / "10-vps-bootstrap.conf.bak-20260821T000000Z"
            backup.write_text("old", encoding="utf-8")
            data = {
                "mode": "migration",
                "interrupted_migration": True,
                "old_ports": [22],
                "activation_mode": "service",
                "backup_metadata": {"dropin": str(backup), "socket": None},
            }

            with patch("app.ssh_hardening.MANAGED_SSHD_DROPIN", target), patch("builtins.input", return_value="2"), patch(
                "app.ssh_hardening.rollback_ssh"
            ) as rollback:
                result = recover_interrupted_migration(data)

        self.assertFalse(result["interrupted_migration"])
        self.assertTrue(result["rollback_completed"])
        self.assertIn("vps-bootstrap ssh", result["reason"])
        self.assertNotIn("vps-bootstrap full", result["reason"])
        rollback.assert_called_once()

    def test_interrupted_recovery_missing_backup_blocks_without_restore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "10-vps-bootstrap.conf"
            missing = Path(directory) / "10-vps-bootstrap.conf.bak-20260821T000000Z"
            data = {"mode": "migration", "interrupted_migration": True, "old_ports": [22], "activation_mode": "service", "backup_metadata": {"dropin": str(missing)}}

            with patch("app.ssh_hardening.MANAGED_SSHD_DROPIN", target), patch("builtins.input", return_value="2"), patch(
                "app.ssh_hardening.rollback_ssh"
            ) as rollback:
                with self.assertRaisesRegex(SSHHardeningError, "backup file does not exist"):
                    recover_interrupted_migration(data)

        rollback.assert_not_called()

    def test_interrupted_recovery_missing_dropin_key_blocks_without_restore(self) -> None:
        data = {"mode": "migration", "interrupted_migration": True, "old_ports": [22], "activation_mode": "service", "backup_metadata": {}}

        with patch("builtins.input", return_value="2"), patch("app.ssh_hardening.rollback_ssh") as rollback:
            with self.assertRaisesRegex(SSHHardeningError, "backup metadata key is missing: dropin"):
                recover_interrupted_migration(data)

        rollback.assert_not_called()

    def test_service_explicit_null_dropin_metadata_is_valid_original_absent(self) -> None:
        paths = backup_paths_from_metadata({"dropin": None}, "service")

        self.assertEqual(paths, {"dropin": None, "socket": None})

    def test_socket_missing_socket_key_blocks(self) -> None:
        with self.assertRaisesRegex(SSHHardeningError, "backup metadata key is missing: socket"):
            backup_paths_from_metadata({"dropin": None}, "socket")

    def test_socket_explicit_null_metadata_is_valid_original_absent(self) -> None:
        paths = backup_paths_from_metadata({"dropin": None, "socket": None}, "socket")

        self.assertEqual(paths, {"dropin": None, "socket": None})

    def test_interrupted_recovery_untrusted_backup_path_blocks(self) -> None:
        data = {
            "mode": "migration",
            "interrupted_migration": True,
            "old_ports": [22],
            "activation_mode": "service",
            "backup_metadata": {"dropin": "/tmp/untrusted.conf"},
        }

        with patch("builtins.input", return_value="2"), patch("app.ssh_hardening.rollback_ssh") as rollback:
            with self.assertRaisesRegex(SSHHardeningError, "untrusted backup path"):
                recover_interrupted_migration(data)

        rollback.assert_not_called()

    def test_rollback_listener_verification_failure_is_critical(self) -> None:
        with patch("app.ssh_hardening.restore_file"), patch("app.ssh_hardening.apply_systemd_ssh"), patch(
            "app.ssh_hardening.verify_transition_listeners", return_value=False
        ):
            with self.assertRaisesRegex(SSHHardeningError, "CRITICAL"):
                rollback_ssh({"dropin": None, "socket": None}, "service", {22})

    def test_backup_metadata_validation_accepts_expected_backup_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "10-vps-bootstrap.conf"
            backup = root / "10-vps-bootstrap.conf.bak-20260821T000000Z"
            backup.write_text("old", encoding="utf-8")

            with patch("app.ssh_hardening.MANAGED_SSHD_DROPIN", target):
                paths = backup_paths_from_metadata({"dropin": str(backup)}, "service")

        self.assertEqual(paths["dropin"], backup)

    def test_manual_commands_restore_existing_dropin_backup_without_rm_target(self) -> None:
        backup = Path("/etc/ssh/sshd_config.d/10-vps-bootstrap.conf.bak-20260821T000000Z")

        commands = manual_rollback_commands({22}, "service", {"dropin": backup, "socket": None})

        self.assertIn(f"sudo install -m 600 {backup} /etc/ssh/sshd_config.d/10-vps-bootstrap.conf", commands)
        self.assertFalse(any(command == "sudo rm -f /etc/ssh/sshd_config.d/10-vps-bootstrap.conf" for command in commands))

    def test_manual_commands_may_rm_original_absent_dropin(self) -> None:
        commands = manual_rollback_commands({22}, "service", {"dropin": None, "socket": None})

        self.assertIn("sudo rm -f /etc/ssh/sshd_config.d/10-vps-bootstrap.conf", commands)

    def test_manual_commands_socket_mode_handles_files_independently(self) -> None:
        dropin_backup = Path("/etc/ssh/sshd_config.d/10-vps-bootstrap.conf.bak-20260821T000000Z")
        commands = manual_rollback_commands({22}, "socket", {"dropin": dropin_backup, "socket": None})

        self.assertIn(f"sudo install -m 600 {dropin_backup} /etc/ssh/sshd_config.d/10-vps-bootstrap.conf", commands)
        self.assertIn("sudo rm -f /etc/systemd/system/ssh.socket.d/10-vps-bootstrap.conf", commands)

    def test_recovery_invalid_activation_mode_blocks_before_restore(self) -> None:
        data = {"mode": "migration", "interrupted_migration": True, "old_ports": [22], "activation_mode": "garbage", "backup_metadata": {"dropin": None}}

        with patch("builtins.input", return_value="2"), patch("app.ssh_hardening.rollback_ssh") as rollback:
            with self.assertRaisesRegex(SSHHardeningError, "Unsupported SSH activation mode"):
                recover_interrupted_migration(data)

        rollback.assert_not_called()

    def test_apply_managed_state_invalid_activation_mode_blocks_before_write(self) -> None:
        data = {"mode": "managed", "ports": [22], "activation_mode": "garbage", "auth_values": {}}

        with patch("app.ssh_hardening.write_atomic") as write, patch("app.ssh_hardening.apply_systemd_ssh") as systemd:
            with self.assertRaisesRegex(SSHHardeningError, "Unsupported SSH activation mode"):
                apply_ssh_plan_data(data)

        write.assert_not_called()
        systemd.assert_not_called()

    def test_rollback_invalid_activation_mode_blocks_before_restore(self) -> None:
        with patch("app.ssh_hardening.restore_file") as restore, patch("app.ssh_hardening.apply_systemd_ssh") as systemd:
            with self.assertRaisesRegex(SSHHardeningError, "Unsupported SSH activation mode"):
                rollback_ssh({"dropin": None, "socket": None}, "garbage", {22})

        restore.assert_not_called()
        systemd.assert_not_called()

    def test_interrupted_after_transition_keeps_state_and_rolls_back_on_ctrl_c(self) -> None:
        plan = SSHPlan({22}, {22, 25000}, {25000}, "service", {"PubkeyAuthentication": "yes"}, {"PubkeyAuthentication": "yes"}, requires_two_port_confirmation=True)
        stages: list[str] = []

        def save_state(data):
            stages.append(data["migration_stage"])

        with patch("app.ssh_hardening.backup_ssh_files", return_value={}), patch("app.ssh_hardening.write_atomic"), patch(
            "app.ssh_hardening.validate_candidate_effective"
        ), patch("app.ssh_hardening.apply_systemd_ssh"), patch("app.ssh_hardening.verify_transition_listeners", return_value=True), patch(
            "app.ssh_hardening.rollback_ssh"
        ) as rollback, patch("builtins.input", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                apply_ssh_plan(plan, save_state=save_state)

        self.assertIn("transition_active", stages)
        self.assertIn("awaiting_second_session", stages)
        rollback.assert_called_once()


if __name__ == "__main__":
    unittest.main()
