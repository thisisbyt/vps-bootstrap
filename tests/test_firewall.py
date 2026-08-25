import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.command import CommandResult
from app.firewall import (
    UFWRule,
    FirewallError,
    FirewallDiscovery,
    delete_managed_port,
    ensure_firewall_from_state,
    finalize_ssh_migration,
    managed_firewall_exists,
    parse_ufw_status,
    parse_ufw_added,
    prepare_ssh_migration,
    rollback_ssh_migration,
    restore_old_ssh_access,
    verify_firewall_state,
)


class FirewallTests(unittest.TestCase):
    def test_parse_ufw_status_preserves_unrelated_and_managed_rules(self) -> None:
        discovery = parse_ufw_status(
            """Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)

22/tcp                     ALLOW IN    Anywhere                   # vps-bootstrap:ssh
443/tcp                    ALLOW IN    Anywhere
"""
        )
        self.assertTrue(discovery.active)
        self.assertEqual(discovery.allowed_tcp_ports(), {22, 443})
        self.assertEqual(discovery.managed_ports(), {22})

    def test_clean_inactive_system_can_be_verified_after_apply_state(self) -> None:
        discovery = FirewallDiscovery(True, True, "deny (incoming)", "allow (outgoing)", [UFWRule(22, managed=True)])
        with patch("app.firewall.discover_firewall", return_value=discovery):
            self.assertTrue(verify_firewall_state({"mode": "managed", "ssh_ports": [22]}))

    def test_verify_rejects_wrong_default_policy(self) -> None:
        discovery = FirewallDiscovery(True, True, "allow (incoming)", "allow (outgoing)", [UFWRule(22, managed=True)])
        with patch("app.firewall.discover_firewall", return_value=discovery):
            self.assertFalse(verify_firewall_state({"mode": "managed", "ssh_ports": [22]}))

    def test_inactive_existing_rules_are_detected(self) -> None:
        output = "ufw allow 22/tcp\nufw deny 443/tcp\nufw reject 25/tcp\nufw limit 2222/tcp\n"
        self.assertEqual(
            parse_ufw_added(output),
            ["ufw allow 22/tcp", "ufw deny 443/tcp", "ufw reject 25/tcp", "ufw limit 2222/tcp"],
        )

    def test_prepare_migration_allows_only_missing_new_managed_port(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "ufw.json"
            marker.write_text('{"mode":"managed","ssh_ports":[22],"default_incoming":"deny","default_outgoing":"allow"}', encoding="utf-8")
            discovery = FirewallDiscovery(True, True, "deny", "allow", [UFWRule(22, managed=True)])
            calls: list[list[str]] = []

            def fake_run(args, timeout=10):
                calls.append(args)
                return CommandResult(args, 0, "", "")

            with patch("app.firewall.MANAGED_UFW_STATE", marker), patch("app.firewall.discover_firewall", return_value=discovery), patch("app.firewall.run_command", side_effect=fake_run):
                metadata = prepare_ssh_migration({22}, {22, 25000})

            self.assertEqual(metadata["added_ports"], [25000])
            self.assertIn(["ufw", "allow", "proto", "tcp", "to", "any", "port", "25000", "comment", "vps-bootstrap:ssh"], calls)

    def test_force_reconfigure_still_requires_confirmation(self) -> None:
        with patch("app.firewall.verify_firewall_state", return_value=False), patch("app.firewall.current_ssh_ports", return_value={22}), patch(
            "app.firewall.confirm_firewall_apply", return_value=False
        ), patch("app.firewall.install_ufw_if_missing") as install:
            state = ensure_firewall_from_state({"mode": "managed", "ssh_ports": [22]}, force_reconfigure=True)

        self.assertEqual(state["mode"], "skipped")
        install.assert_not_called()

    def test_unmanaged_firewall_is_noop_for_ssh_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch("app.firewall.MANAGED_UFW_STATE", Path(directory) / "missing.json"):
            self.assertEqual(prepare_ssh_migration({22}, {22, 25000}), {"managed": False})

    def test_prepare_migration_avoids_duplicate_managed_rule(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "ufw.json"
            marker.write_text('{"mode":"managed","ssh_ports":[22],"default_incoming":"deny","default_outgoing":"allow"}', encoding="utf-8")
            discovery = FirewallDiscovery(True, True, "deny", "allow", [UFWRule(22, managed=True), UFWRule(25000, managed=True)])
            with patch("app.firewall.MANAGED_UFW_STATE", marker), patch("app.firewall.discover_firewall", return_value=discovery), patch("app.firewall.allow_managed_port") as allow:
                metadata = prepare_ssh_migration({22}, {22, 25000})
        self.assertEqual(metadata["added_ports"], [])
        allow.assert_not_called()

    def test_finalize_removes_only_managed_old_rule_and_preserves_unrelated(self) -> None:
        discovery = FirewallDiscovery(True, True, "deny", "allow", [UFWRule(22, managed=True), UFWRule(443, managed=False)])
        deleted: list[int] = []
        with patch("app.firewall.write_managed_state"), patch("app.firewall.discover_firewall", return_value=discovery), patch("app.firewall.delete_managed_port", side_effect=lambda port: deleted.append(port)):
            finalize_ssh_migration({25000}, {22}, {"managed": True})
        self.assertEqual(deleted, [22])

    def test_finalize_records_cleanup_pending_when_old_rule_delete_fails(self) -> None:
        metadata = {"managed": True}
        with patch("app.firewall.write_managed_state"), patch("app.firewall.delete_managed_port", side_effect=FirewallError("boom")):
            finalize_ssh_migration({25000}, {22}, metadata)
        self.assertEqual(metadata["cleanup_pending"], [22])

    def test_delete_managed_port_targets_exact_owned_rule_when_equivalent_unmanaged_rule_exists(self) -> None:
        discovery = FirewallDiscovery(True, True, "deny", "allow", [UFWRule(22, managed=True), UFWRule(22, managed=False)])
        with patch("app.firewall.discover_firewall", return_value=discovery), patch("app.firewall.run_command") as run:
            run.return_value = CommandResult([], 0, "", "")
            delete_managed_port(22)

        self.assertEqual(
            run.call_args.args[0],
            ["ufw", "--force", "delete", "allow", "proto", "tcp", "to", "any", "port", "22", "comment", "vps-bootstrap:ssh"],
        )

    def test_rollback_removes_new_managed_rule_when_safe(self) -> None:
        deleted: list[int] = []
        original = {"mode": "managed", "ssh_ports": [22], "default_incoming": "deny", "default_outgoing": "allow"}
        metadata = {"managed": True, "added_ports": [25000], "original_state": original}
        with patch("app.firewall.delete_managed_port", side_effect=lambda port: deleted.append(port)), patch("app.firewall.write_managed_state") as write:
            rollback_ssh_migration(metadata)
        self.assertEqual(deleted, [25000])
        write.assert_called_once_with(original)
        self.assertEqual(metadata["rollback_state"], original)

    def test_corrupt_or_inconsistent_marker_does_not_claim_managed_firewall(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "ufw.json"
            discovery = FirewallDiscovery(True, True, "deny", "allow", [UFWRule(22, managed=True)])
            for content in ("{}", "not-json", '{"mode":"managed","ssh_ports":[],"default_incoming":"deny","default_outgoing":"allow"}'):
                with self.subTest(content=content):
                    marker.write_text(content, encoding="utf-8")
                    with patch("app.firewall.MANAGED_UFW_STATE", marker), patch("app.firewall.discover_firewall", return_value=discovery):
                        self.assertFalse(managed_firewall_exists())

            marker.write_text('{"mode":"managed","ssh_ports":[22],"default_incoming":"deny","default_outgoing":"allow"}', encoding="utf-8")
            inconsistent = FirewallDiscovery(True, True, "deny", "allow", [])
            with patch("app.firewall.MANAGED_UFW_STATE", marker), patch("app.firewall.discover_firewall", return_value=inconsistent):
                self.assertFalse(managed_firewall_exists())

    def test_restore_old_managed_access_before_rollback(self) -> None:
        before = FirewallDiscovery(True, True, "deny", "allow", [UFWRule(25000, managed=True)])
        after = FirewallDiscovery(True, True, "deny", "allow", [UFWRule(22, managed=True), UFWRule(25000, managed=True)])
        metadata = {
            "managed": True,
            "old_managed_ports": [22],
            "original_state": {"mode": "managed", "ssh_ports": [22], "default_incoming": "deny", "default_outgoing": "allow"},
        }
        with patch("app.firewall.discover_firewall", side_effect=[before, after, after]), patch("app.firewall.allow_managed_port") as allow:
            restore_old_ssh_access(metadata, {22})

        allow.assert_called_once_with(22)
        self.assertTrue(metadata["old_access_restored"])

    def test_failed_first_apply_removes_only_attempted_managed_rule(self) -> None:
        inactive = FirewallDiscovery(True, False, "", "", [], [])
        with tempfile.TemporaryDirectory() as directory, patch("app.firewall.MANAGED_UFW_STATE", Path(directory) / "ufw.json"), patch(
            "app.firewall.current_ssh_ports", return_value={22}
        ), patch("app.firewall.confirm_firewall_apply", return_value=True), patch("app.firewall.install_ufw_if_missing"), patch(
            "app.firewall.discover_firewall", return_value=inactive
        ), patch("app.firewall.allow_managed_port"), patch(
            "app.firewall.run_or_raise", side_effect=FirewallError("default failed")
        ), patch("app.firewall.delete_exact_managed_port") as cleanup:
            with self.assertRaisesRegex(FirewallError, "default failed"):
                ensure_firewall_from_state({})

        cleanup.assert_called_once_with(22)


if __name__ == "__main__":
    unittest.main()
