import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app.admin_user import (
    AdminUserDiscovery,
    AdminUserError,
    AdminUserPlan,
    apply_admin_user_plan,
    admin_second_session_command,
    admin_second_session_instructions,
    configure_sudo_policy,
    confirm_existing_admin_user,
    merge_authorized_keys,
    read_uid_min,
    install_state_from_discovery,
    render_authorized_keys,
    render_managed_sudoers,
    SUDO_MODE_NOPASSWD,
    SUDO_MODE_PASSWORD_REQUIRED,
    sudo_validation_commands,
    validate_public_key,
    validate_username,
    verify_sudo_policy,
    setup_password_interactively,
    verify_admin_user_state,
)
from app.command import CommandResult


PUBLIC_KEY = "ssh-ed25519 QUJDREVGR0g= example"


class AdminUserTests(unittest.TestCase):
    def test_invalid_and_root_usernames_are_rejected(self) -> None:
        for username in ["root", "BadName", "bad name", "1admin"]:
            with self.subTest(username=username):
                with self.assertRaises(AdminUserError):
                    validate_username(username)

    def test_public_key_validation_accepts_public_key_only(self) -> None:
        self.assertEqual(validate_public_key(PUBLIC_KEY), PUBLIC_KEY)
        with self.assertRaises(AdminUserError):
            validate_public_key("not-a-public-key")

    def test_new_user_happy_path_never_stores_private_key_material(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "admin"
            home.mkdir()
            commands: list[list[str]] = []

            def fake_run(args, timeout=10):
                commands.append(args)
                return CommandResult(args, 0, "", "")

            with patch("app.admin_user.fingerprint_public_key", return_value="SHA256:testfp"), patch(
                "app.admin_user.pwd.getpwnam",
                return_value=SimpleNamespace(pw_dir=str(home), pw_uid=1001, pw_gid=1002),
            ), patch("app.admin_user.run_command", side_effect=fake_run), patch("app.admin_user.setup_password_interactively") as passwd, patch("app.admin_user.confirm", return_value=True):
                state = apply_admin_user_plan(AdminUserPlan("adminuser", True, PUBLIC_KEY))

            self.assertEqual(state["username"], "adminuser")
            self.assertEqual(state["fingerprint"], "SHA256:testfp")
            self.assertTrue(state["validated"])
            passwd.assert_called_once_with("adminuser")
            self.assertIn(["useradd", "--create-home", "--shell", "/bin/bash", "adminuser"], commands)
            self.assertIn(["usermod", "-aG", "sudo", "adminuser"], commands)
            self.assertEqual(state["sudo_mode"], SUDO_MODE_PASSWORD_REQUIRED)
            self.assertTrue(state["sudo_validated"])
            self.assertTrue(state["local_password_usable"])
            self.assertIn(["chown", "1001:1002", str(home)], commands)
            self.assertIn(["chown", "1001:1002", str(home / ".ssh"), str(home / ".ssh" / "authorized_keys")], commands)
            self.assertEqual(home.stat().st_mode & 0o777, 0o700)
            self.assertEqual((home / ".ssh").stat().st_mode & 0o777, 0o700)
            self.assertEqual((home / ".ssh" / "authorized_keys").stat().st_mode & 0o777, 0o600)
            self.assertEqual((home / ".ssh" / "authorized_keys").read_text(encoding="utf-8"), PUBLIC_KEY + "\n")
            self.assertNotIn("PRIVATE", str(state))

    def test_new_user_password_setup_failure_blocks_phase(self) -> None:
        with patch("app.admin_user.fingerprint_public_key", return_value="SHA256:testfp"), patch(
            "app.admin_user.run_command", return_value=CommandResult([], 0, "", "")
        ), patch("app.admin_user.setup_password_interactively", side_effect=AdminUserError("passwd failed")):
            with self.assertRaisesRegex(AdminUserError, "passwd failed"):
                apply_admin_user_plan(AdminUserPlan("adminuser", True, PUBLIC_KEY))

    def test_existing_user_password_is_not_modified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "existing"
            home.mkdir()
            discovery = AdminUserDiscovery(
                "existing", True, 1001, home, "/bin/bash", True, True, True, True, True,
                ["SHA256:testfp"], local_password_status="P"
            )
            with patch("app.admin_user.fingerprint_public_key", return_value="SHA256:testfp"), patch(
                "app.admin_user.pwd.getpwnam",
                return_value=SimpleNamespace(pw_dir=str(home), pw_uid=1001, pw_gid=1001, pw_shell="/bin/bash"),
            ), patch("app.admin_user.discover_admin_user", return_value=discovery), patch(
                "app.admin_user.run_command", return_value=CommandResult([], 0, "", "")
            ), patch("app.admin_user.setup_password_interactively") as passwd, patch(
                "app.admin_user.confirm", return_value=True
            ):
                apply_admin_user_plan(AdminUserPlan("existing", False, PUBLIC_KEY))
        passwd.assert_not_called()

    def test_existing_user_nopasswd_does_not_change_or_lock_local_password(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "existing"
            home.mkdir()
            with patch("app.admin_user.fingerprint_public_key", return_value="SHA256:testfp"), patch(
                "app.admin_user.pwd.getpwnam",
                return_value=SimpleNamespace(pw_dir=str(home), pw_uid=1001, pw_gid=1001, pw_shell="/bin/bash"),
            ), patch("app.admin_user.discover_admin_user") as discover, patch(
                "app.admin_user.run_command", return_value=CommandResult([], 0, "", "")
            ), patch("app.admin_user.setup_password_interactively") as passwd, patch(
                "app.admin_user.lock_local_password"
            ) as lock, patch("app.admin_user.configure_sudo_policy"), patch("app.admin_user.confirm", return_value=True):
                discover.return_value = AdminUserDiscovery(
                    "existing", True, 1001, home, "/bin/bash", True, True, True, True, True, ["SHA256:testfp"], local_password_status="P"
                )
                state = apply_admin_user_plan(
                    AdminUserPlan("existing", False, PUBLIC_KEY, "SHA256:testfp", SUDO_MODE_NOPASSWD, "unchanged")
                )

        passwd.assert_not_called()
        lock.assert_not_called()
        self.assertTrue(state["local_password_usable"])

    def test_existing_user_sudo_validation_failure_blocks_safe_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "existing"
            home.mkdir()
            discovery = AdminUserDiscovery(
                "existing", True, 1001, home, "/bin/bash", True, True, True, True, True,
                ["SHA256:testfp"], local_password_status="P"
            )
            with patch("app.admin_user.fingerprint_public_key", return_value="SHA256:testfp"), patch(
                "app.admin_user.pwd.getpwnam",
                return_value=SimpleNamespace(pw_dir=str(home), pw_uid=1001, pw_gid=1001, pw_shell="/bin/bash"),
            ), patch("app.admin_user.discover_admin_user", return_value=discovery), patch(
                "app.admin_user.run_command", return_value=CommandResult([], 0, "", "")
            ), patch("app.admin_user.confirm", return_value=False):
                with self.assertRaisesRegex(AdminUserError, "validation was not confirmed"):
                    apply_admin_user_plan(AdminUserPlan("existing", False, PUBLIC_KEY))

    def test_existing_locked_user_blocks_password_required_before_sudoers_change(self) -> None:
        discovery = AdminUserDiscovery(
            "existing", True, 1001, Path("/home/existing"), "/bin/bash", True, True, True, True, True,
            ["SHA256:existing"], password_locked=True, local_password_status="L"
        )
        with patch("app.admin_user.confirm", return_value=False), patch(
            "app.admin_user.setup_password_interactively"
        ) as passwd, patch("app.admin_user.configure_sudo_policy") as sudoers, patch(
            "app.admin_user.ensure_admin_home_permissions"
        ):
            with self.assertRaisesRegex(AdminUserError, "verified local password"):
                confirm_existing_admin_user(discovery, sudo_mode=SUDO_MODE_PASSWORD_REQUIRED)

        passwd.assert_not_called()
        sudoers.assert_not_called()

    def test_existing_locked_user_can_explicitly_set_password_before_switch(self) -> None:
        discovery = AdminUserDiscovery(
            "existing", True, 1001, Path("/home/existing"), "/bin/bash", True, True, True, True, True,
            ["SHA256:existing"], password_locked=True, local_password_status="L"
        )
        with patch("app.admin_user.confirm", side_effect=[True, True]), patch(
            "app.admin_user.setup_password_interactively"
        ) as passwd, patch("app.admin_user.configure_sudo_policy") as sudoers, patch(
            "app.admin_user.ensure_admin_home_permissions"
        ):
            state = confirm_existing_admin_user(discovery, sudo_mode=SUDO_MODE_PASSWORD_REQUIRED)

        self.assertTrue(state["local_password_usable"])
        passwd.assert_called_once_with("existing")
        sudoers.assert_called_once_with("existing", SUDO_MODE_PASSWORD_REQUIRED)

    def test_existing_user_happy_path_uses_existing_authorized_keys_fingerprint(self) -> None:
        discovery = AdminUserDiscovery(
            "existing", True, 1001, Path("/home/existing"), "/bin/bash", True, True, True, True, True,
            ["SHA256:existing"], local_password_status="P"
        )
        with patch("app.admin_user.confirm", return_value=True), patch("app.admin_user.ensure_admin_home_permissions"), patch(
            "app.admin_user.configure_sudo_policy"
        ):
            state = confirm_existing_admin_user(discovery)
        self.assertEqual(state["username"], "existing")
        self.assertEqual(state["fingerprint"], "SHA256:existing")
        self.assertEqual(state["sudo_mode"], SUDO_MODE_PASSWORD_REQUIRED)
        self.assertTrue(state["sudo_validated"])

    def test_verify_admin_user_state_uses_fingerprint_not_key_body(self) -> None:
        discovery = AdminUserDiscovery("adminuser", True, 1001, Path("/home/adminuser"), "/bin/bash", True, True, True, True, True, ["SHA256:testfp"])
        with patch("app.admin_user.discover_admin_user", return_value=discovery), patch("app.admin_user.verify_sudo_policy", return_value=True):
            self.assertTrue(verify_admin_user_state({"mode": "managed", "username": "adminuser", "fingerprint": "SHA256:testfp", "validated": True}))

    def test_verify_admin_user_state_rejects_wrong_authorized_keys_owner(self) -> None:
        discovery = AdminUserDiscovery(
            "adminuser",
            True,
            1001,
            Path("/home/adminuser"),
            "/bin/bash",
            True,
            True,
            True,
            True,
            True,
            ["SHA256:testfp"],
            authorized_keys_owner_ok=False,
        )
        with patch("app.admin_user.discover_admin_user", return_value=discovery):
            self.assertFalse(verify_admin_user_state({"mode": "managed", "username": "adminuser", "fingerprint": "SHA256:testfp", "validated": True}))

    def test_install_state_from_discovery_is_non_secret(self) -> None:
        discovery = AdminUserDiscovery("adminuser", True, 1001, Path("/home/adminuser"), "/bin/bash", True, True, True, True, True, ["SHA256:testfp"])
        state = install_state_from_discovery(discovery, "SHA256:testfp")
        self.assertEqual(state["username"], "adminuser")
        self.assertEqual(state["fingerprint"], "SHA256:testfp")
        self.assertEqual(state["sudo_mode"], SUDO_MODE_PASSWORD_REQUIRED)
        self.assertNotIn("public_key", state)

    def test_render_authorized_keys_rejects_private_key_like_input(self) -> None:
        with self.assertRaises(AdminUserError):
            render_authorized_keys("-----BEGIN OPENSSH PRIVATE KEY-----")

    def test_existing_authorized_keys_are_preserved_and_key_is_deduplicated(self) -> None:
        existing = "ssh-ed25519 QUJDREVGR0g= old-comment\nssh-ed25519 SElKS0w= another\n"
        self.assertEqual(merge_authorized_keys(existing, PUBLIC_KEY), existing)
        merged = merge_authorized_keys(existing, "ssh-ed25519 TU5PUA== new")
        self.assertIn(existing, merged)
        self.assertIn("ssh-ed25519 TU5PUA== new\n", merged)

    def test_option_prefixed_authorized_key_is_preserved_without_unrestricted_duplicate(self) -> None:
        restricted = 'restrict,from="192.0.2.0/24" ssh-ed25519 QUJDREVGR0g= restricted\n'

        self.assertEqual(merge_authorized_keys(restricted, PUBLIC_KEY), restricted)

    def test_system_uid_is_not_a_usable_admin(self) -> None:
        discovery = AdminUserDiscovery(
            "serviceaccount",
            True,
            500,
            Path("/home/serviceaccount"),
            "/bin/bash",
            True,
            True,
            True,
            True,
            True,
            ["SHA256:testfp"],
            uid_min=1000,
        )

        self.assertFalse(discovery.normal_login_user)
        self.assertFalse(discovery.usable)

    def test_uid_min_is_read_from_login_defs_with_safe_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            login_defs = Path(directory) / "login.defs"
            login_defs.write_text("# policy\nUID_MIN 1500\n", encoding="utf-8")
            self.assertEqual(read_uid_min(login_defs), 1500)
            self.assertEqual(read_uid_min(Path(directory) / "missing"), 1000)

    def test_admin_second_session_command_includes_current_nonstandard_port(self) -> None:
        self.assertEqual(
            admin_second_session_command("adminuser", "192.0.2.10", port=25000),
            "ssh -i <path-to-private-key> -o IdentitiesOnly=yes -o PreferredAuthentications=publickey "
            "-o PasswordAuthentication=no -p 25000 adminuser@192.0.2.10",
        )

    def test_admin_second_session_instructions_explain_nondefault_private_key_selection(self) -> None:
        rendered = "\n".join(admin_second_session_instructions("adminuser", "203.0.113.10", port=25000))

        self.assertIn("PRIVATE key corresponding to the configured public key", rendered)
        self.assertIn("ssh-agent or OpenSSH config", rendered)
        self.assertIn("-i <path-to-private-key>", rendered)
        self.assertIn("-o IdentitiesOnly=yes", rendered)
        self.assertIn("may be omitted", rendered)
        self.assertNotIn("C:\\", rendered)
        self.assertNotIn("/home/", rendered)

    def test_nopasswd_new_user_can_set_local_recovery_password(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "admin"
            home.mkdir()
            with patch("app.admin_user.fingerprint_public_key", return_value="SHA256:testfp"), patch(
                "app.admin_user.pwd.getpwnam", return_value=SimpleNamespace(pw_dir=str(home), pw_uid=1001, pw_gid=1001)
            ), patch("app.admin_user.run_command", return_value=CommandResult([], 0, "", "")), patch(
                "app.admin_user.setup_password_interactively"
            ) as passwd, patch("app.admin_user.configure_sudo_policy") as sudoers, patch("app.admin_user.confirm", return_value=True):
                state = apply_admin_user_plan(
                    AdminUserPlan("adminuser", True, PUBLIC_KEY, "SHA256:testfp", SUDO_MODE_NOPASSWD, "set")
                )

        passwd.assert_called_once_with("adminuser")
        sudoers.assert_called_once_with("adminuser", SUDO_MODE_NOPASSWD)
        self.assertEqual(state["sudo_mode"], SUDO_MODE_NOPASSWD)
        self.assertTrue(state["local_password_usable"])

    def test_nopasswd_new_user_can_keep_local_password_locked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "admin"
            home.mkdir()
            with patch("app.admin_user.fingerprint_public_key", return_value="SHA256:testfp"), patch(
                "app.admin_user.pwd.getpwnam", return_value=SimpleNamespace(pw_dir=str(home), pw_uid=1001, pw_gid=1001)
            ), patch("app.admin_user.run_command", return_value=CommandResult([], 0, "", "")), patch(
                "app.admin_user.setup_password_interactively"
            ) as passwd, patch("app.admin_user.lock_local_password") as lock, patch(
                "app.admin_user.configure_sudo_policy"
            ), patch("app.admin_user.confirm", return_value=True):
                state = apply_admin_user_plan(
                    AdminUserPlan("adminuser", True, PUBLIC_KEY, "SHA256:testfp", SUDO_MODE_NOPASSWD, "locked")
                )

        passwd.assert_not_called()
        lock.assert_called_once_with("adminuser")
        self.assertEqual(state["local_password_status"], "locked")
        self.assertFalse(state["local_password_usable"])

    def test_nopasswd_sudoers_is_exact_user_only_and_mode_0440(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "sudoers.d" / "10-vps-bootstrap-admin"
            sudoers = root / "sudoers"
            sudoers.write_text("@includedir /etc/sudoers.d\n", encoding="utf-8")
            with patch("app.admin_user.MANAGED_SUDOERS", target), patch("app.admin_user.SUDOERS_FILE", sudoers), patch(
                "app.admin_user.run_command", return_value=CommandResult([], 0, "parsed OK", "")
            ), patch("app.admin_user.chown_root_if_possible") as chown_root:
                configure_sudo_policy("adminuser", SUDO_MODE_NOPASSWD)

            content = target.read_text(encoding="utf-8")
            self.assertEqual(content, render_managed_sudoers("adminuser"))
            self.assertIn("adminuser ALL=(ALL:ALL) NOPASSWD: ALL", content)
            self.assertNotIn("%sudo", content)
            self.assertEqual(target.stat().st_mode & 0o777, 0o440)
            chown_root.assert_any_call(target)

    def test_nopasswd_verifier_requires_root_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "10-vps-bootstrap-admin"
            target.write_text(render_managed_sudoers("adminuser"), encoding="utf-8")
            target.chmod(0o440)
            with patch("app.admin_user.MANAGED_SUDOERS", target), patch(
                "app.admin_user.run_command", return_value=CommandResult([], 0, "parsed OK", "")
            ), patch("app.admin_user.root_owned", return_value=False):
                self.assertFalse(verify_sudo_policy("adminuser", SUDO_MODE_NOPASSWD))
            with patch("app.admin_user.MANAGED_SUDOERS", target), patch(
                "app.admin_user.run_command", return_value=CommandResult([], 0, "parsed OK", "")
            ), patch("app.admin_user.root_owned", return_value=True):
                self.assertTrue(verify_sudo_policy("adminuser", SUDO_MODE_NOPASSWD))

    def test_bad_sudoers_validation_restores_previous_managed_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "10-vps-bootstrap-admin"
            sudoers = root / "sudoers"
            original = render_managed_sudoers("existing")
            target.write_text(original, encoding="utf-8")
            calls = 0

            def fake_run(args, timeout=10):
                nonlocal calls
                if args[:2] == ["visudo", "-cf"]:
                    calls += 1
                    return CommandResult(args, 1 if calls == 1 else 0, "", "bad sudoers")
                return CommandResult(args, 0, "", "")

            with patch("app.admin_user.MANAGED_SUDOERS", target), patch("app.admin_user.SUDOERS_FILE", sudoers), patch(
                "app.admin_user.run_command", side_effect=fake_run
            ):
                with self.assertRaisesRegex(AdminUserError, "sudoers validation failed"):
                    configure_sudo_policy("adminuser", SUDO_MODE_NOPASSWD)

            self.assertEqual(target.read_text(encoding="utf-8"), original)
            self.assertEqual(calls, 2)

    def test_switch_to_password_required_removes_only_managed_dropin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "10-vps-bootstrap-admin"
            unrelated = root / "90-user-policy"
            target.write_text(render_managed_sudoers("adminuser"), encoding="utf-8")
            unrelated.write_text("unrelated ALL=(ALL) ALL\n", encoding="utf-8")
            with patch("app.admin_user.MANAGED_SUDOERS", target), patch(
                "app.admin_user.run_command", return_value=CommandResult([], 0, "parsed OK", "")
            ):
                configure_sudo_policy("adminuser", SUDO_MODE_PASSWORD_REQUIRED)

            self.assertFalse(target.exists())
            self.assertTrue(unrelated.exists())

    def test_nopasswd_second_session_requires_noninteractive_sudo_confirmation(self) -> None:
        discovery = AdminUserDiscovery(
            "existing", True, 1001, Path("/home/existing"), "/bin/bash", True, True, True, True, True, ["SHA256:existing"]
        )
        output = StringIO()
        with patch("app.admin_user.ensure_admin_home_permissions"), patch("app.admin_user.configure_sudo_policy"), patch(
            "app.admin_user.confirm", return_value=False
        ), redirect_stdout(output):
            with self.assertRaisesRegex(AdminUserError, "validation was not confirmed"):
                confirm_existing_admin_user(discovery, sudo_mode=SUDO_MODE_NOPASSWD)

        rendered = output.getvalue()
        self.assertIn("sudo -k", rendered)
        self.assertIn("sudo -n true", rendered)
        self.assertIn("sudo -n whoami", rendered)
        self.assertNotIn("sudo -v", rendered)

    def test_password_required_validation_invalidates_timestamp_and_proves_both_states(self) -> None:
        commands = sudo_validation_commands(SUDO_MODE_PASSWORD_REQUIRED)

        self.assertEqual(commands[0], "sudo -k")
        self.assertIn("EXPECTED TO FAIL", commands[1])
        self.assertTrue(commands[1].startswith("sudo -n true"))
        self.assertTrue(commands[2].startswith("sudo -v"))
        self.assertEqual(commands[3], "sudo -n true")
        self.assertIn("must print: 0", commands[4])

    def test_password_required_second_session_explains_expected_failure(self) -> None:
        discovery = AdminUserDiscovery(
            "existing", True, 1001, Path("/home/existing"), "/bin/bash", True, True, True, True, True,
            ["SHA256:existing"], local_password_status="P"
        )
        output = StringIO()
        with patch("app.admin_user.ensure_admin_home_permissions"), patch("app.admin_user.configure_sudo_policy"), patch(
            "app.admin_user.confirm", return_value=False
        ), redirect_stdout(output):
            with self.assertRaisesRegex(AdminUserError, "validation was not confirmed"):
                confirm_existing_admin_user(discovery, sudo_mode=SUDO_MODE_PASSWORD_REQUIRED)

        rendered = output.getvalue()
        self.assertIn("EXPECTED TO FAIL", rendered)
        self.assertIn("not a bootstrap failure", rendered)
        self.assertIn("After 'sudo -v'", rendered)
        self.assertIn("echo $?  # must print: 0", rendered)

    def test_sudo_validation_sequences_distinguish_selected_policy(self) -> None:
        password_required = sudo_validation_commands(SUDO_MODE_PASSWORD_REQUIRED)
        nopasswd = sudo_validation_commands(SUDO_MODE_NOPASSWD)

        self.assertIn("sudo -v  # enter the normal sudo password", password_required)
        self.assertNotIn("sudo -n whoami  # must print: root", password_required)
        self.assertNotIn("sudo -v  # enter the normal sudo password", nopasswd)
        self.assertEqual(
            nopasswd,
            ["sudo -k", "sudo -n true", "sudo -n whoami  # must print: root"],
        )

    def test_system_passwd_inherits_terminal_and_verifies_status(self) -> None:
        with patch("app.admin_user.subprocess.run", return_value=SimpleNamespace(returncode=0)) as passwd, patch(
            "app.admin_user.run_command", return_value=CommandResult([], 0, "adminuser P 2026-08-23 0 99999 7 -1", "")
        ):
            setup_password_interactively("adminuser")

        passwd.assert_called_once_with(["passwd", "adminuser"], check=False)


if __name__ == "__main__":
    unittest.main()
