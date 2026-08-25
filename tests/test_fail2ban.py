import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.command import CommandResult
from app.fail2ban import (
    Fail2banError,
    Fail2banSettings,
    apply_settings,
    backup_jail,
    conflicting_sshd_port_overrides,
    finalize_ssh_migration,
    parse_managed_jail,
    prepare_ssh_migration,
    recommended_settings,
    render_jail,
    rollback_ssh_migration,
    sshd_ports_from_config,
    validate_duration,
    validate_ignoreip_entry,
    verify_fail2ban_state,
    wait_for_fail2ban_ready,
)


class Fail2banTests(unittest.TestCase):
    class FakeClock:
        def __init__(self) -> None:
            self.now = 0.0

        def monotonic(self) -> float:
            return self.now

        def sleep(self, seconds: float) -> None:
            self.now += seconds

    def test_recommended_preset(self) -> None:
        settings = recommended_settings([22])
        self.assertEqual(settings.maxretry, 5)
        self.assertEqual(settings.findtime, "10m")
        self.assertEqual(settings.bantime, "1h")
        self.assertIn("backend = systemd", render_jail(settings))

    def test_custom_validation_rejects_invalid_duration(self) -> None:
        with self.assertRaises(Fail2banError):
            validate_duration("forever")

    def test_optional_ignoreip_is_rendered(self) -> None:
        text = render_jail(Fail2banSettings([22], ignoreip=["192.0.2.0/24"]))
        self.assertIn("ignoreip = 192.0.2.0/24", text)

    def test_parse_managed_jail_round_trip(self) -> None:
        settings = parse_managed_jail(render_jail(Fail2banSettings([22, 25000], maxretry=4, findtime="20m", bantime="2h")))
        self.assertEqual(settings.ports, [22, 25000])
        self.assertEqual(settings.maxretry, 4)
        self.assertEqual(settings.findtime, "20m")

    def test_verify_service_jail_and_port(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            jail = Path(directory) / "jail.local"
            jail.write_text(render_jail(Fail2banSettings([25000])), encoding="utf-8")

            def fake_run(args, timeout=10):
                if args == ["fail2ban-client", "-t"]:
                    return CommandResult(args, 0, "OK", "")
                if args[:3] == ["systemctl", "is-active", "fail2ban"]:
                    return CommandResult(args, 0, "active", "")
                if args[:3] == ["fail2ban-client", "status", "sshd"]:
                    return CommandResult(args, 0, "Status for the jail: sshd", "")
                return CommandResult(args, 1, "", "unexpected")

            with patch("app.fail2ban.MANAGED_JAIL", jail), patch("app.fail2ban.FAIL2BAN_CONFIG_ROOT", Path(directory) / "config"), patch(
                "app.fail2ban.run_command", side_effect=fake_run
            ), patch("app.fail2ban.current_ssh_ports", return_value=[25000]):
                self.assertTrue(verify_fail2ban_state({"mode": "managed", "ports": [25000]}))

    def test_verify_fails_when_actual_ssh_port_differs_from_managed_jail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            jail = Path(directory) / "jail.local"
            jail.write_text(render_jail(Fail2banSettings([25000])), encoding="utf-8")
            with patch("app.fail2ban.MANAGED_JAIL", jail), patch("app.fail2ban.FAIL2BAN_CONFIG_ROOT", Path(directory) / "config"), patch(
                "app.fail2ban.run_command", return_value=CommandResult([], 0, "active", "")
            ), patch(
                "app.fail2ban.current_ssh_ports", return_value=[22]
            ):
                self.assertFalse(verify_fail2ban_state({"mode": "managed", "ports": [25000]}))

    def test_prepare_and_finalize_ssh_transaction_updates_ports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            jail = Path(directory) / "jail.local"
            jail.write_text(render_jail(Fail2banSettings([22])), encoding="utf-8")
            def fake_run(args, timeout=10):
                stdout = "active" if args == ["systemctl", "is-active", "fail2ban"] else ""
                return CommandResult(args, 0, stdout, "")

            with patch("app.fail2ban.MANAGED_JAIL", jail), patch("app.fail2ban.run_command", side_effect=fake_run):
                metadata = prepare_ssh_migration({22}, {22, 25000})
                self.assertTrue(metadata["managed"])
                self.assertEqual(parse_managed_jail(jail.read_text(encoding="utf-8")).ports, [22, 25000])
                finalize_ssh_migration({25000}, metadata)
                self.assertEqual(parse_managed_jail(jail.read_text(encoding="utf-8")).ports, [25000])

    def test_rollback_restores_previous_jail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            jail = Path(directory) / "jail.local"
            backup = Path(directory) / "backup.local"
            jail.write_text(render_jail(Fail2banSettings([25000])), encoding="utf-8")
            backup = Path(directory) / "jail.local.bak-transaction-1"
            backup.write_text(render_jail(Fail2banSettings([22])), encoding="utf-8")

            def fake_run(args, timeout=10):
                if args == ["systemctl", "is-active", "fail2ban"]:
                    return CommandResult(args, 0, "active", "")
                return CommandResult(args, 0, "", "")

            original_state = {"mode": "managed", "ports": [22], "maxretry": 5, "findtime": "10m", "bantime": "1h", "ignoreip": []}
            with patch("app.fail2ban.MANAGED_JAIL", jail), patch("app.fail2ban.FAIL2BAN_CONFIG_ROOT", Path(directory) / "config"), patch(
                "app.fail2ban.run_command", side_effect=fake_run
            ), patch("app.fail2ban.current_ssh_ports", return_value=[22]):
                metadata = {"managed": True, "backup": str(backup), "original_state": original_state}
                rollback_ssh_migration(metadata)
            self.assertEqual(parse_managed_jail(jail.read_text(encoding="utf-8")).ports, [22])
            self.assertEqual(metadata["rollback_state"], original_state)

    def test_invalid_ignoreip_is_rejected(self) -> None:
        with self.assertRaises(Fail2banError):
            validate_ignoreip_entry("not-an-ip")

    def test_config_test_failure_restores_previous_jail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            jail = Path(directory) / "jail.local"
            jail.write_text(render_jail(Fail2banSettings([22])), encoding="utf-8")

            def fake_run(args, timeout=10):
                if args == ["fail2ban-client", "-t"]:
                    return CommandResult(args, 1, "", "bad config")
                return CommandResult(args, 0, "", "")

            with patch("app.fail2ban.MANAGED_JAIL", jail), patch("app.fail2ban.run_command", side_effect=fake_run):
                with self.assertRaisesRegex(Fail2banError, "configuration test failed"):
                    apply_settings(Fail2banSettings([25000]))
            self.assertEqual(parse_managed_jail(jail.read_text(encoding="utf-8")).ports, [22])

    def test_restart_failure_restores_previous_jail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            jail = Path(directory) / "jail.local"
            jail.write_text(render_jail(Fail2banSettings([22])), encoding="utf-8")

            def fake_run(args, timeout=10):
                if args == ["systemctl", "restart", "fail2ban"]:
                    return CommandResult(args, 1, "", "restart failed")
                return CommandResult(args, 0, "", "")

            with patch("app.fail2ban.MANAGED_JAIL", jail), patch("app.fail2ban.run_command", side_effect=fake_run):
                with self.assertRaisesRegex(Fail2banError, "restart"):
                    apply_settings(Fail2banSettings([25000]))
            self.assertEqual(parse_managed_jail(jail.read_text(encoding="utf-8")).ports, [22])

    def test_transaction_backup_remains_original_after_finalize(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            jail = Path(directory) / "10-vps-bootstrap-sshd.local"
            old_content = render_jail(Fail2banSettings([22]))
            jail.write_text(old_content, encoding="utf-8")
            def fake_run(args, timeout=10):
                stdout = "active" if args == ["systemctl", "is-active", "fail2ban"] else ""
                return CommandResult(args, 0, stdout, "")

            with patch("app.fail2ban.MANAGED_JAIL", jail), patch("app.fail2ban.run_command", side_effect=fake_run):
                metadata = prepare_ssh_migration({22}, {22, 25000})
                transaction_backup = Path(metadata["backup"])
                self.assertEqual(transaction_backup.read_text(encoding="utf-8"), old_content)
                finalize_ssh_migration({25000}, metadata)

            self.assertEqual(transaction_backup.read_text(encoding="utf-8"), old_content)
            self.assertEqual(parse_managed_jail(jail.read_text(encoding="utf-8")).ports, [25000])

    def test_effective_override_conflict_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jail_d = root / "jail.d"
            jail_d.mkdir()
            managed = jail_d / "10-vps-bootstrap-sshd.local"
            managed.write_text(render_jail(Fail2banSettings([25000])), encoding="utf-8")
            (jail_d / "99-user.local").write_text("[sshd]\nport = 26000\n", encoding="utf-8")
            with patch("app.fail2ban.MANAGED_JAIL", managed), patch("app.fail2ban.FAIL2BAN_CONFIG_ROOT", root):
                self.assertEqual(conflicting_sshd_port_overrides({25000}), [str(jail_d / "99-user.local")])

    def test_effective_override_with_same_port_is_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jail_d = root / "jail.d"
            jail_d.mkdir()
            managed = jail_d / "10-vps-bootstrap-sshd.local"
            managed.write_text(render_jail(Fail2banSettings([25000])), encoding="utf-8")
            (jail_d / "99-user.local").write_text("[sshd]\nport = 25000\n", encoding="utf-8")
            with patch("app.fail2ban.MANAGED_JAIL", managed), patch("app.fail2ban.FAIL2BAN_CONFIG_ROOT", root):
                self.assertEqual(conflicting_sshd_port_overrides({25000}), [])

    def test_port_parser_supports_ssh_service_name(self) -> None:
        self.assertEqual(sshd_ports_from_config("[sshd]\nport = ssh,25000\n"), {22, 25000})

    def test_runtime_apply_failure_restarts_restored_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            jail = Path(directory) / "jail.local"
            jail.write_text(render_jail(Fail2banSettings([22])), encoding="utf-8")
            restart_calls = 0
            status_attempts = 0
            clock = self.FakeClock()

            def fake_run(args, timeout=10):
                nonlocal restart_calls, status_attempts
                if args == ["systemctl", "restart", "fail2ban"]:
                    restart_calls += 1
                    if restart_calls == 1:
                        return CommandResult(args, 1, "", "new config restart failed")
                if args == ["systemctl", "is-active", "fail2ban"]:
                    return CommandResult(args, 0, "active", "")
                if args == ["fail2ban-client", "status", "sshd"]:
                    status_attempts += 1
                    return CommandResult(args, 0 if status_attempts == 3 else 1, "", "not ready")
                return CommandResult(args, 0, "", "")

            with patch("app.fail2ban.MANAGED_JAIL", jail), patch("app.fail2ban.run_command", side_effect=fake_run), patch(
                "app.fail2ban.monotonic", side_effect=clock.monotonic
            ), patch("app.fail2ban.sleep", side_effect=clock.sleep):
                with self.assertRaisesRegex(Fail2banError, "new config restart failed"):
                    apply_settings(Fail2banSettings([25000]))

            self.assertEqual(restart_calls, 2)
            self.assertEqual(status_attempts, 3)
            self.assertEqual(parse_managed_jail(jail.read_text(encoding="utf-8")).ports, [22])

    def test_readiness_retries_until_sshd_jail_is_available(self) -> None:
        clock = self.FakeClock()
        status_attempts = 0

        def fake_run(args, timeout=10):
            nonlocal status_attempts
            if args == ["systemctl", "is-active", "fail2ban"]:
                return CommandResult(args, 0, "active", "")
            if args == ["fail2ban-client", "status", "sshd"]:
                status_attempts += 1
                return CommandResult(args, 0 if status_attempts == 3 else 1, "", "not ready")
            return CommandResult(args, 1, "", "unexpected")

        with patch("app.fail2ban.run_command", side_effect=fake_run), patch(
            "app.fail2ban.monotonic", side_effect=clock.monotonic
        ), patch("app.fail2ban.sleep", side_effect=clock.sleep):
            self.assertTrue(wait_for_fail2ban_ready(timeout_seconds=1, interval_seconds=0.2))
        self.assertEqual(status_attempts, 3)

    def test_readiness_timeout_is_bounded(self) -> None:
        clock = self.FakeClock()

        def fake_run(args, timeout=10):
            if args == ["systemctl", "is-active", "fail2ban"]:
                return CommandResult(args, 0, "active", "")
            return CommandResult(args, 1, "", "not ready")

        with patch("app.fail2ban.run_command", side_effect=fake_run), patch(
            "app.fail2ban.monotonic", side_effect=clock.monotonic
        ), patch("app.fail2ban.sleep", side_effect=clock.sleep):
            with self.assertRaisesRegex(Fail2banError, "did not become ready within 0.5 seconds"):
                wait_for_fail2ban_ready(timeout_seconds=0.5, interval_seconds=0.2)
        self.assertEqual(clock.now, 0.5)

    def test_config_test_failure_is_not_masked_by_readiness_polling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            jail = Path(directory) / "jail.local"
            jail.write_text(render_jail(Fail2banSettings([22])), encoding="utf-8")

            def fake_run(args, timeout=10):
                if args == ["fail2ban-client", "-t"]:
                    return CommandResult(args, 1, "", "bad config")
                return CommandResult(args, 0, "", "")

            with patch("app.fail2ban.MANAGED_JAIL", jail), patch("app.fail2ban.run_command", side_effect=fake_run), patch(
                "app.fail2ban.wait_for_fail2ban_ready"
            ) as readiness:
                with self.assertRaisesRegex(Fail2banError, "configuration test failed"):
                    apply_settings(Fail2banSettings([25000]))
            readiness.assert_not_called()

    def test_apply_waits_for_delayed_sshd_jail_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            jail = Path(directory) / "jail.local"
            jail.write_text(render_jail(Fail2banSettings([22])), encoding="utf-8")
            clock = self.FakeClock()
            status_attempts = 0

            def fake_run(args, timeout=10):
                nonlocal status_attempts
                if args == ["systemctl", "is-active", "fail2ban"]:
                    return CommandResult(args, 0, "active", "")
                if args == ["fail2ban-client", "status", "sshd"]:
                    status_attempts += 1
                    return CommandResult(args, 0 if status_attempts == 3 else 1, "", "not ready")
                return CommandResult(args, 0, "", "")

            with patch("app.fail2ban.MANAGED_JAIL", jail), patch("app.fail2ban.run_command", side_effect=fake_run), patch(
                "app.fail2ban.monotonic", side_effect=clock.monotonic
            ), patch("app.fail2ban.sleep", side_effect=clock.sleep):
                apply_settings(Fail2banSettings([25000]))

            self.assertEqual(status_attempts, 3)
            self.assertEqual(parse_managed_jail(jail.read_text(encoding="utf-8")).ports, [25000])

    def test_migration_rollback_waits_for_delayed_jail_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            jail = Path(directory) / "10-vps-bootstrap-sshd.local"
            backup = Path(directory) / "10-vps-bootstrap-sshd.local.bak-transaction-1"
            jail.write_text(render_jail(Fail2banSettings([25000])), encoding="utf-8")
            backup.write_text(render_jail(Fail2banSettings([22])), encoding="utf-8")
            original_state = {"mode": "managed", "ports": [22], "maxretry": 5, "findtime": "10m", "bantime": "1h", "ignoreip": []}
            metadata = {"managed": True, "backup": str(backup), "original_state": original_state}
            clock = self.FakeClock()
            status_attempts = 0

            def fake_run(args, timeout=10):
                nonlocal status_attempts
                if args == ["systemctl", "is-active", "fail2ban"]:
                    return CommandResult(args, 0, "active", "")
                if args == ["fail2ban-client", "status", "sshd"]:
                    status_attempts += 1
                    return CommandResult(args, 0 if status_attempts == 3 else 1, "", "not ready")
                return CommandResult(args, 0, "", "")

            with patch("app.fail2ban.MANAGED_JAIL", jail), patch("app.fail2ban.FAIL2BAN_CONFIG_ROOT", Path(directory) / "config"), patch(
                "app.fail2ban.current_ssh_ports", return_value=[22]
            ), patch("app.fail2ban.run_command", side_effect=fake_run), patch(
                "app.fail2ban.monotonic", side_effect=clock.monotonic
            ), patch("app.fail2ban.sleep", side_effect=clock.sleep):
                rollback_ssh_migration(metadata)

            self.assertEqual(status_attempts, 3)
            self.assertEqual(metadata["rollback_state"], original_state)

    def test_migration_rollback_readiness_timeout_remains_critical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            jail = Path(directory) / "10-vps-bootstrap-sshd.local"
            backup = Path(directory) / "10-vps-bootstrap-sshd.local.bak-transaction-1"
            jail.write_text(render_jail(Fail2banSettings([25000])), encoding="utf-8")
            backup.write_text(render_jail(Fail2banSettings([22])), encoding="utf-8")
            original_state = {"mode": "managed", "ports": [22], "maxretry": 5, "findtime": "10m", "bantime": "1h", "ignoreip": []}
            metadata = {"managed": True, "backup": str(backup), "original_state": original_state}
            clock = self.FakeClock()

            def fake_run(args, timeout=10):
                if args == ["systemctl", "is-active", "fail2ban"]:
                    return CommandResult(args, 0, "active", "")
                if args == ["fail2ban-client", "status", "sshd"]:
                    return CommandResult(args, 1, "", "not ready")
                return CommandResult(args, 0, "", "")

            with patch("app.fail2ban.MANAGED_JAIL", jail), patch("app.fail2ban.FAIL2BAN_CONFIG_ROOT", Path(directory) / "config"), patch(
                "app.fail2ban.current_ssh_ports", return_value=[22]
            ), patch("app.fail2ban.FAIL2BAN_READY_TIMEOUT_SECONDS", 0.5), patch(
                "app.fail2ban.FAIL2BAN_READY_INTERVAL_SECONDS", 0.2
            ), patch("app.fail2ban.run_command", side_effect=fake_run), patch(
                "app.fail2ban.monotonic", side_effect=clock.monotonic
            ), patch("app.fail2ban.sleep", side_effect=clock.sleep):
                with self.assertRaisesRegex(Fail2banError, "CRITICAL: restored Fail2ban SSH jail"):
                    rollback_ssh_migration(metadata)

            self.assertNotIn("rollback_state", metadata)


if __name__ == "__main__":
    unittest.main()
