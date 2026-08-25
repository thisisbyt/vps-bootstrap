import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from app.command import CommandResult
from app.config import Paths
from app.root_hardening import (
    AdminGroupAudit,
    RootHardeningError,
    apply_root_key_action,
    apply_root_password_policy,
    audit_admin_group,
    choose_root_password_policy,
    ensure_root_hardening_from_state,
    parse_admin_group,
    parse_root_authorized_keys,
    verify_root_key_state,
    verify_root_password_state,
)


KEY_ONE = "ssh-ed25519 QUJDREVGR0g= first"
KEY_TWO = "ssh-ed25519 SElKS0w= second"
RESTRICTED_KEY = 'restrict,from="203.0.113.0/24" ssh-ed25519 QUJDREVGR0g= restricted'


def make_paths(root: Path) -> Paths:
    return Paths(
        etc_dir=root / "etc",
        config_dir=root / "etc" / "config",
        secrets_dir=root / "etc" / "secrets",
        state_dir=root / "state",
        log_dir=root / "log",
    )


def fake_fingerprint(line: str) -> str:
    return "SHA256:" + ("one" if "QUJD" in line else "two")


class RootHardeningTests(unittest.TestCase):
    def test_no_root_authorized_keys_is_safe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ssh_dir = root / ".ssh"
            keys_path = ssh_dir / "authorized_keys"
            paths = make_paths(root)
            with patch("app.root_hardening.ROOT_SSH_DIR", ssh_dir), patch(
                "app.root_hardening.ROOT_AUTHORIZED_KEYS", keys_path
            ), patch("app.root_hardening.root_owned", return_value=True):
                state = apply_root_key_action("no_keys", set(), [], paths)

            self.assertEqual(state["remaining_count"], 0)
            self.assertEqual(state["fingerprints"], [])
            self.assertIsNone(state["backup"])
            self.assertTrue(ssh_dir.is_dir())
            self.assertEqual(ssh_dir.stat().st_mode & 0o777, 0o700)

    def test_unparsed_root_authorized_key_material_blocks_without_modification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ssh_dir = root / ".ssh"
            ssh_dir.mkdir()
            keys_path = ssh_dir / "authorized_keys"
            original = "environment=broken-key-entry\n"
            keys_path.write_text(original, encoding="utf-8")
            paths = make_paths(root)
            admin = {"mode": "managed", "username": "admin", "validated": True}
            with patch("app.root_hardening.ROOT_SSH_DIR", ssh_dir), patch(
                "app.root_hardening.ROOT_AUTHORIZED_KEYS", keys_path
            ), patch("app.root_hardening.verify_admin_user_state", return_value=True), patch(
                "app.root_hardening.audit_admin_group", return_value=AdminGroupAudit(False, None, [], False)
            ), patch("app.root_hardening.apply_root_key_action") as apply_keys:
                with self.assertRaisesRegex(RootHardeningError, "could not be safely parsed"):
                    ensure_root_hardening_from_state({}, admin, paths)

            self.assertEqual(keys_path.read_text(encoding="utf-8"), original)
            apply_keys.assert_not_called()

    def test_symlinked_root_authorized_keys_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ssh_dir = root / ".ssh"
            ssh_dir.mkdir()
            outside = root / "outside"
            outside.write_text(KEY_ONE + "\n", encoding="utf-8")
            keys_path = ssh_dir / "authorized_keys"
            try:
                keys_path.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable in this environment")
            with patch("app.root_hardening.ROOT_SSH_DIR", ssh_dir), patch(
                "app.root_hardening.ROOT_AUTHORIZED_KEYS", keys_path
            ):
                with self.assertRaisesRegex(RootHardeningError, "symlinked"):
                    apply_root_key_action("remove_all", set(), [], make_paths(root))

            self.assertEqual(outside.read_text(encoding="utf-8"), KEY_ONE + "\n")

    def test_option_prefixed_root_key_is_parsed_without_losing_restrictions(self) -> None:
        with patch("app.root_hardening.fingerprint_public_key", side_effect=fake_fingerprint):
            keys = parse_root_authorized_keys(RESTRICTED_KEY + "\n")

        self.assertEqual(len(keys), 1)
        self.assertTrue(keys[0].has_options)
        self.assertEqual(keys[0].key_type, "ssh-ed25519")
        self.assertEqual(keys[0].comment, "restricted")
        self.assertEqual(keys[0].original_line, RESTRICTED_KEY)

    def test_remove_all_creates_immutable_secure_backup_and_stores_fingerprints_only(self) -> None:
        original = KEY_ONE + "\n" + KEY_TWO + "\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ssh_dir = root / ".ssh"
            ssh_dir.mkdir(mode=0o755)
            keys_path = ssh_dir / "authorized_keys"
            keys_path.write_text(original, encoding="utf-8")
            paths = make_paths(root)
            with patch("app.root_hardening.ROOT_SSH_DIR", ssh_dir), patch(
                "app.root_hardening.ROOT_AUTHORIZED_KEYS", keys_path
            ), patch("app.root_hardening.fingerprint_public_key", side_effect=fake_fingerprint), patch(
                "app.root_hardening.root_owned", return_value=True
            ), patch("app.root_hardening.chown_root_if_possible") as root_chown, patch(
                "app.filesystem.chown_root_if_possible"
            ) as directory_chown:
                keys = parse_root_authorized_keys(original)
                state = apply_root_key_action("remove_all", set(), keys, paths)
                backup = Path(state["backup"])
                self.assertTrue(verify_root_key_state(state, paths))
                self.assertEqual(backup.read_text(encoding="utf-8"), original)
                self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
                self.assertEqual(backup.parent.stat().st_mode & 0o777, 0o700)
                self.assertEqual((paths.state_dir / "backups" / "root-hardening").stat().st_mode & 0o777, 0o700)
                root_chown.assert_any_call(backup)
                root_chown.assert_any_call(ssh_dir)
                directory_chown.assert_any_call(backup.parent)

            self.assertFalse(keys_path.exists())
            self.assertEqual(ssh_dir.stat().st_mode & 0o777, 0o700)
            self.assertNotIn("QUJDREVGR0g", str(state))
            self.assertNotIn("SElKS0w", str(state))

    def test_select_key_to_keep_preserves_exact_option_prefixed_line(self) -> None:
        original = RESTRICTED_KEY + "\n" + KEY_TWO + "\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ssh_dir = root / ".ssh"
            ssh_dir.mkdir()
            keys_path = ssh_dir / "authorized_keys"
            keys_path.write_text(original, encoding="utf-8")
            paths = make_paths(root)
            with patch("app.root_hardening.ROOT_SSH_DIR", ssh_dir), patch(
                "app.root_hardening.ROOT_AUTHORIZED_KEYS", keys_path
            ), patch("app.root_hardening.fingerprint_public_key", side_effect=fake_fingerprint), patch(
                "app.root_hardening.root_owned", return_value=True
            ):
                keys = parse_root_authorized_keys(original)
                state = apply_root_key_action("keep_selected", {1}, keys, paths)

            self.assertEqual(keys_path.read_text(encoding="utf-8"), RESTRICTED_KEY + "\n")
            self.assertEqual(state["fingerprints"], ["SHA256:one"])
            self.assertEqual(keys_path.stat().st_mode & 0o777, 0o600)

    def test_keep_unchanged_preserves_multiple_keys(self) -> None:
        original = KEY_ONE + "\n" + KEY_TWO + "\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ssh_dir = root / ".ssh"
            ssh_dir.mkdir()
            keys_path = ssh_dir / "authorized_keys"
            keys_path.write_text(original, encoding="utf-8")
            paths = make_paths(root)
            with patch("app.root_hardening.ROOT_SSH_DIR", ssh_dir), patch(
                "app.root_hardening.ROOT_AUTHORIZED_KEYS", keys_path
            ), patch("app.root_hardening.fingerprint_public_key", side_effect=fake_fingerprint), patch(
                "app.root_hardening.root_owned", return_value=True
            ):
                keys = parse_root_authorized_keys(original)
                state = apply_root_key_action("keep_unchanged", {1, 2}, keys, paths)

            self.assertEqual(keys_path.read_text(encoding="utf-8"), original)
            self.assertEqual(state["remaining_count"], 2)

    def test_root_key_write_failure_restores_original(self) -> None:
        original = KEY_ONE + "\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ssh_dir = root / ".ssh"
            ssh_dir.mkdir()
            keys_path = ssh_dir / "authorized_keys"
            keys_path.write_text(original, encoding="utf-8")
            paths = make_paths(root)
            with patch("app.root_hardening.ROOT_SSH_DIR", ssh_dir), patch(
                "app.root_hardening.ROOT_AUTHORIZED_KEYS", keys_path
            ), patch("app.root_hardening.fingerprint_public_key", side_effect=fake_fingerprint), patch(
                "app.root_hardening.root_owned", return_value=True
            ), patch("app.root_hardening.write_atomic", side_effect=OSError("write failed")):
                keys = parse_root_authorized_keys(original)
                with self.assertRaisesRegex(OSError, "write failed"):
                    apply_root_key_action("keep_selected", {1}, keys, paths)

            self.assertEqual(keys_path.read_text(encoding="utf-8"), original)

    def test_admin_local_password_controls_root_password_default(self) -> None:
        with patch("builtins.input", return_value=""):
            self.assertEqual(choose_root_password_policy(True), "lock")
        output = StringIO()
        with patch("builtins.input", return_value=""), redirect_stdout(output):
            self.assertEqual(choose_root_password_policy(False), "keep")
        self.assertIn("console recovery path", output.getvalue())

    def test_explicit_root_password_lock_uses_passwd_and_verifies_status(self) -> None:
        commands: list[list[str]] = []
        statuses = iter(["root P", "", "root L"])

        def fake_run(args, timeout=10):
            commands.append(args)
            output = next(statuses)
            return CommandResult(args, 0, output, "")

        with patch("app.root_hardening.run_command", side_effect=fake_run):
            state = apply_root_password_policy("lock")

        self.assertTrue(state["locked"])
        self.assertIn(["passwd", "-l", "root"], commands)
        self.assertFalse(any("shell" in command or "expire" in command or command[0] == "chage" for command in commands))

    def test_keep_root_password_does_not_unlock_or_expire_account(self) -> None:
        commands: list[list[str]] = []

        def fake_run(args, timeout=10):
            commands.append(args)
            return CommandResult(args, 0, "root P", "")

        with patch("app.root_hardening.run_command", side_effect=fake_run):
            state = apply_root_password_policy("keep")
            self.assertTrue(verify_root_password_state(state))

        self.assertEqual(commands, [["passwd", "-S", "root"], ["passwd", "-S", "root"]])

    def test_root_password_lock_verification_failure_blocks(self) -> None:
        results = iter([
            CommandResult([], 0, "root P", ""),
            CommandResult([], 0, "", ""),
            CommandResult([], 0, "root P", ""),
        ])
        with patch("app.root_hardening.run_command", side_effect=lambda args, timeout=10: next(results)):
            with self.assertRaisesRegex(RootHardeningError, "did not report a locked password"):
                apply_root_password_policy("lock")

    def test_admin_group_missing_and_empty_are_noop_audits(self) -> None:
        self.assertEqual(parse_admin_group("", "").members, [])
        empty = parse_admin_group("admin:x:110:\n", "root:x:0:0:root:/root:/bin/bash\n")
        self.assertTrue(empty.exists)
        self.assertEqual(empty.members, [])

    def test_admin_group_includes_supplementary_and_primary_gid_members(self) -> None:
        audit = parse_admin_group(
            "admin:x:110:alice\n",
            "root:x:0:0:root:/root:/bin/bash\nbob:x:1001:110::/home/bob:/bin/bash\n",
        )
        self.assertEqual(audit.members, ["alice", "bob"])

    def test_admin_group_warning_never_rewrites_sudoers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            group = root / "group"
            passwd = root / "passwd"
            sudoers = root / "sudoers"
            sudoers_d = root / "sudoers.d"
            sudoers_d.mkdir()
            group.write_text("admin:x:110:alice\n", encoding="utf-8")
            passwd.write_text("alice:x:1001:1001::/home/alice:/bin/bash\n", encoding="utf-8")
            sudoers.write_text("%admin ALL=(ALL) ALL\n", encoding="utf-8")
            before = sudoers.read_bytes()
            output = StringIO()
            with patch("app.root_hardening.GROUP_FILE", group), patch("app.root_hardening.PASSWD_FILE", passwd), patch(
                "app.root_hardening.SUDOERS_FILE", sudoers
            ), patch("app.root_hardening.SUDOERS_D", sudoers_d), redirect_stdout(output):
                audit = audit_admin_group()

            self.assertTrue(audit.sudo_privilege)
            self.assertEqual(audit.members, ["alice"])
            self.assertEqual(sudoers.read_bytes(), before)
            self.assertIn("alice", output.getvalue())

    def test_root_hardening_saves_key_progress_before_password_policy(self) -> None:
        admin_state = {
            "mode": "managed",
            "username": "adminuser",
            "fingerprint": "SHA256:admin",
            "validated": True,
            "sudo_validated": True,
            "local_password_usable": True,
        }
        saved: list[dict] = []
        key_state = {"action": "remove_all", "fingerprints": [], "verified": True, "backup": "/safe/backup"}
        password_state = {"action": "lock", "status": "L", "locked": True, "verified": True}
        events: list[str] = []
        with tempfile.TemporaryDirectory() as directory, patch(
            "app.root_hardening.verify_admin_user_state", return_value=True
        ), patch("app.root_hardening.audit_admin_group", return_value=AdminGroupAudit(False, None, [], False)), patch(
            "app.root_hardening.root_authorized_keys_inventory", return_value=([], 0)
        ), patch("app.root_hardening.display_root_key_audit"), patch(
            "app.root_hardening.choose_root_key_action", return_value=("remove_all", set())
        ), patch(
            "app.root_hardening.apply_root_key_action", side_effect=lambda *args: events.append("root-keys") or key_state
        ), patch(
            "app.root_hardening.choose_root_password_policy", side_effect=lambda value: events.append("password-choice") or "lock"
        ), patch(
            "app.root_hardening.apply_root_password_policy", side_effect=lambda action: events.append("root-password") or password_state
        ), patch("app.root_hardening.verify_root_hardening_state", return_value=True):
            result = ensure_root_hardening_from_state({}, admin_state, make_paths(Path(directory)), save_state=saved.append)

        self.assertEqual(events, ["root-keys", "password-choice", "root-password"])
        self.assertEqual(saved[0]["mode"], "running")
        self.assertEqual(saved[0]["root_authorized_keys"], key_state)
        self.assertEqual(result["mode"], "managed")


if __name__ == "__main__":
    unittest.main()
