import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.command import CommandResult
from app.security_updates import (
    SecurityUpdatesError,
    ensure_security_updates_from_state,
    parse_apt_config_status,
    parse_security_status,
    render_auto_upgrades,
    verify_security_updates_state,
)


APT_EFFECTIVE = (
    'APT::Periodic::Update-Package-Lists "1";\n'
    'APT::Periodic::Unattended-Upgrade "1";\n'
    'Unattended-Upgrade::Automatic-Reboot "false";\n'
    'Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";\n'
)


class SecurityUpdatesTests(unittest.TestCase):
    def test_fresh_setup_enables_security_updates_without_auto_reboot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            managed = Path(directory) / "90-vps-bootstrap-security-updates"
            unattended = Path(directory) / "50unattended-upgrades"
            unattended.write_text("// Ubuntu stock config\n", encoding="utf-8")

            def fake_run(args, timeout=10):
                if args == ["apt-config", "dump"]:
                    return CommandResult(args, 0, APT_EFFECTIVE, "")
                return CommandResult(args, 0, "", "")

            with patch("app.security_updates.UNATTENDED_UPGRADES", unattended), patch(
                "app.security_updates.MANAGED_SECURITY_UPDATES", managed
            ), patch("app.security_updates.run_command", side_effect=fake_run):
                state = ensure_security_updates_from_state({})
            self.assertTrue(state["enabled"])
            self.assertTrue(state["security_origin"])
            self.assertFalse(state["automatic_reboot"])
            self.assertIn('APT::Periodic::Unattended-Upgrade "1"', managed.read_text(encoding="utf-8"))
            self.assertEqual(unattended.read_text(encoding="utf-8"), "// Ubuntu stock config\n")

    def test_effective_apt_config_parser(self) -> None:
        status = parse_apt_config_status(
            'APT::Periodic::Update-Package-Lists "1";\n'
            'APT::Periodic::Unattended-Upgrade "1";\n'
            'Unattended-Upgrade::Automatic-Reboot "false";\n'
            'Unattended-Upgrade::Allowed-Origins:: "Ubuntu:noble-security";\n'
        )
        self.assertTrue(status.enabled)
        self.assertTrue(status.security_origin)
        self.assertFalse(status.automatic_reboot)

    def test_existing_distro_config_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            managed = Path(directory) / "90-vps-bootstrap-security-updates"
            unattended = Path(directory) / "50unattended-upgrades"
            original = 'Unattended-Upgrade::Package-Blacklist { "example"; };\n'
            unattended.write_text(original, encoding="utf-8")
            with patch("app.security_updates.UNATTENDED_UPGRADES", unattended), patch("app.security_updates.MANAGED_SECURITY_UPDATES", managed), patch(
                "app.security_updates.run_command",
                return_value=CommandResult([], 0, APT_EFFECTIVE, ""),
            ):
                state = ensure_security_updates_from_state({})
            self.assertTrue(state["enabled"])
            self.assertEqual(unattended.read_text(encoding="utf-8"), original)

    def test_existing_compatible_configuration_verifies(self) -> None:
        stock_origins = 'Unattended-Upgrade::Allowed-Origins { "${distro_id}:${distro_codename}-security"; };\n'
        status = parse_security_status(render_auto_upgrades(), render_auto_upgrades() + stock_origins)
        self.assertTrue(status.enabled)
        self.assertTrue(status.security_origin)
        self.assertFalse(status.automatic_reboot)

    def test_ambiguous_auto_reboot_true_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            managed = Path(directory) / "90-vps-bootstrap-security-updates"
            unattended = Path(directory) / "50unattended-upgrades"
            unattended.write_text("user config\n", encoding="utf-8")
            with patch("app.security_updates.UNATTENDED_UPGRADES", unattended), patch("app.security_updates.MANAGED_SECURITY_UPDATES", managed), patch(
                "app.security_updates.run_command",
                return_value=CommandResult([], 0, APT_EFFECTIVE.replace('"false"', '"true"'), ""),
            ):
                with self.assertRaises(SecurityUpdatesError):
                    ensure_security_updates_from_state({})

    def test_idempotency(self) -> None:
        status = parse_apt_config_status(APT_EFFECTIVE)
        with patch("app.security_updates.discover_security_updates", return_value=status):
            self.assertTrue(verify_security_updates_state({"mode": "managed"}))

    def test_missing_effective_ubuntu_security_origin_fails_verification(self) -> None:
        no_origin = APT_EFFECTIVE.replace('Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";\n', "")
        with patch("app.security_updates.discover_security_updates", return_value=parse_apt_config_status(no_origin)):
            self.assertFalse(verify_security_updates_state({"mode": "managed"}))

    def test_apply_blocks_when_effective_origin_policy_has_no_security_origin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            managed = Path(directory) / "90-vps-bootstrap-security-updates"
            unattended = Path(directory) / "50unattended-upgrades"
            unattended.write_text("// Ubuntu stock config remains untouched\n", encoding="utf-8")
            no_origin = APT_EFFECTIVE.replace('Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";\n', "")
            with patch("app.security_updates.UNATTENDED_UPGRADES", unattended), patch(
                "app.security_updates.MANAGED_SECURITY_UPDATES", managed
            ), patch("app.security_updates.run_command", return_value=CommandResult([], 0, no_origin, "")):
                with self.assertRaisesRegex(SecurityUpdatesError, "no Ubuntu security origin"):
                    ensure_security_updates_from_state({})

            self.assertEqual(unattended.read_text(encoding="utf-8"), "// Ubuntu stock config remains untouched\n")


if __name__ == "__main__":
    unittest.main()
