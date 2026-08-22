import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.command import CommandResult
from app.state import InstallState, PhaseStatus
from app.swap import (
    DEFAULT_SWAPFILE,
    FSTAB,
    GIB,
    MANAGED_FSTAB_LINE,
    SwapArea,
    SwapDiscovery,
    SwapError,
    SwapFileInfo,
    apply_managed_swap,
    count_managed_fstab_entries,
    parse_fstab_swap_entries,
    parse_proc_swaps,
    plan_swap_creation,
    repair_managed_swap,
    recommended_swap_size_bytes,
    render_fstab_with_managed_swap,
    validate_filesystem_for_swap,
    validate_swap_size,
    verify_swap_state,
)


def discovery(
    *,
    ram: int = 1024**3,
    active: list[SwapArea] | None = None,
    fstab_entries: list[str] | None = None,
    fs: str = "ext4",
    free: int = 10 * 1024**3,
    swapfile: SwapFileInfo | None = None,
) -> SwapDiscovery:
    return SwapDiscovery(
        ram_total_bytes=ram,
        active_areas=active or [],
        fstab_swap_entries=fstab_entries or [],
        root_filesystem=fs,
        root_free_bytes=free,
        swapfile=swapfile or SwapFileInfo(False),
    )


class SwapTests(unittest.TestCase):
    def test_no_swap_uses_recommended_creation_plan(self) -> None:
        plan = plan_swap_creation(discovery(ram=1024**3))

        self.assertEqual(plan.action, "create")
        self.assertEqual(plan.size_bytes, 2 * GIB)

    def test_existing_valid_swap_does_not_create_duplicate(self) -> None:
        area = SwapArea("/dev/vda2", "partition", 2 * GIB)

        plan = plan_swap_creation(discovery(active=[area]))

        self.assertEqual(plan.action, "use_existing")
        self.assertEqual(plan.existing_areas, ["/dev/vda2"])

    def test_duplicate_fstab_prevention(self) -> None:
        current = "UUID=x / ext4 defaults 0 1\n# Managed by vps-bootstrap: swap\n/swapfile none swap sw 0 0\n"

        rendered = render_fstab_with_managed_swap(current)

        self.assertEqual(count_managed_fstab_entries(rendered), 1)
        self.assertEqual(parse_fstab_swap_entries(rendered), [MANAGED_FSTAB_LINE])

    def test_insufficient_disk_is_rejected(self) -> None:
        with self.assertRaisesRegex(SwapError, "Insufficient disk"):
            validate_swap_size(2 * GIB, 2 * GIB)

    def test_permissions_are_verified_for_managed_swapfile(self) -> None:
        area = SwapArea("/swapfile", "file", 2 * GIB)
        state = {"mode": "managed", "path": "/swapfile", "size_bytes": 2 * GIB}
        disc = discovery(
            active=[area],
            fstab_entries=[MANAGED_FSTAB_LINE],
            swapfile=SwapFileInfo(True, 2 * GIB, 0o644, "file"),
        )

        with patch("app.swap.discover_swap", return_value=disc):
            self.assertFalse(verify_swap_state(state))

    def test_active_swap_verifier_success(self) -> None:
        area = SwapArea("/swapfile", "file", 2 * GIB)
        state = {"mode": "managed", "path": "/swapfile", "size_bytes": 2 * GIB}
        with tempfile.TemporaryDirectory() as directory:
            fstab = Path(directory) / "fstab"
            fstab.write_text("# Managed by vps-bootstrap: swap\n/swapfile none swap sw 0 0\n", encoding="utf-8")
            disc = discovery(
                active=[area],
                fstab_entries=[MANAGED_FSTAB_LINE],
                swapfile=SwapFileInfo(True, 2 * GIB, 0o600, "file"),
            )
            with patch("app.swap.FSTAB", fstab), patch("app.swap.discover_swap", return_value=disc):
                self.assertTrue(verify_swap_state(state))

    def test_inactive_expected_swap_is_drift(self) -> None:
        state = {"mode": "managed", "path": "/swapfile", "size_bytes": 2 * GIB}
        with patch("app.swap.discover_swap", return_value=discovery()):
            self.assertFalse(verify_swap_state(state))

    def test_unsupported_filesystem_is_blocked(self) -> None:
        with self.assertRaisesRegex(SwapError, "btrfs"):
            validate_filesystem_for_swap("btrfs")

    def test_rollback_on_activation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            swapfile = root / "swapfile"
            fstab = root / "fstab"
            fstab.write_text("UUID=x / ext4 defaults 0 1\n", encoding="utf-8")

            def fake_create(path: Path, size: int) -> None:
                path.write_bytes(b"0" * 4096)

            def fake_run(args, timeout=10):
                if args[0] == "mkswap":
                    return CommandResult(args, 0, "ok", "")
                if args[0] == "swapon":
                    return CommandResult(args, 1, "", "activation failed")
                if args[0] == "swapoff":
                    return CommandResult(args, 0, "", "")
                return CommandResult(args, 0, "", "")

            with patch("app.swap.DEFAULT_SWAPFILE", swapfile), patch("app.swap.FSTAB", fstab), patch(
                "app.swap.create_non_sparse_swapfile", side_effect=fake_create
            ), patch("app.swap.run_command", side_effect=fake_run), patch("app.swap.shutil.disk_usage") as usage:
                usage.return_value.free = 10 * GIB
                with self.assertRaisesRegex(SwapError, "swapon failed"):
                    apply_managed_swap(plan_swap_creation(discovery(free=10 * GIB), 2 * GIB))

            self.assertEqual(fstab.read_text(encoding="utf-8"), "UUID=x / ext4 defaults 0 1\n")
            self.assertFalse(swapfile.exists())

    def test_partial_swapfile_from_failed_create_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            swapfile = root / "swapfile"
            fstab = root / "fstab"
            fstab.write_text("UUID=x / ext4 defaults 0 1\n", encoding="utf-8")

            def fake_create(path: Path, size: int) -> None:
                path.write_bytes(b"partial")
                raise SwapError("dd failed")

            with patch("app.swap.DEFAULT_SWAPFILE", swapfile), patch("app.swap.FSTAB", fstab), patch(
                "app.swap.create_non_sparse_swapfile", side_effect=fake_create
            ), patch("app.swap.shutil.disk_usage") as usage:
                usage.return_value.free = 10 * GIB
                with self.assertRaisesRegex(SwapError, "dd failed"):
                    apply_managed_swap(plan_swap_creation(discovery(free=10 * GIB), 2 * GIB))

            self.assertFalse(swapfile.exists())
            self.assertEqual(fstab.read_text(encoding="utf-8"), "UUID=x / ext4 defaults 0 1\n")

    def test_unknown_preexisting_regular_swapfile_blocks_without_mkswap(self) -> None:
        disc = discovery(swapfile=SwapFileInfo(True, 2 * GIB, 0o600, "file"))

        with patch("app.swap.run_command") as command:
            with self.assertRaisesRegex(SwapError, "not known to be managed"):
                plan_swap_creation(disc, 2 * GIB)

        command.assert_not_called()

    def test_active_managed_swap_fstab_drift_repairs_fstab_without_mkswap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fstab = Path(directory) / "fstab"
            fstab.write_text("UUID=x / ext4 defaults 0 1\n", encoding="utf-8")
            disc = discovery(
                active=[SwapArea("/swapfile", "file", 2 * GIB)],
                fstab_entries=[],
                swapfile=SwapFileInfo(True, 2 * GIB, 0o600, "file"),
            )

            with patch("app.swap.FSTAB", fstab), patch("app.swap.run_command") as command:
                repair_managed_swap({"mode": "managed", "path": "/swapfile", "size_bytes": 2 * GIB}, disc)

            self.assertIn(MANAGED_FSTAB_LINE, fstab.read_text(encoding="utf-8"))
            command.assert_not_called()

    def test_active_managed_swap_mode_drift_repairs_without_mkswap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fstab = Path(directory) / "fstab"
            fstab.write_text("# Managed by vps-bootstrap: swap\n/swapfile none swap sw 0 0\n", encoding="utf-8")
            disc = discovery(
                active=[SwapArea("/swapfile", "file", 2 * GIB)],
                fstab_entries=[MANAGED_FSTAB_LINE],
                swapfile=SwapFileInfo(True, 2 * GIB, 0o644, "file"),
            )

            with patch("app.swap.FSTAB", fstab), patch("app.swap.os.chmod") as chmod, patch("app.swap.run_command") as command:
                repair_managed_swap({"mode": "managed", "path": "/swapfile", "size_bytes": 2 * GIB}, disc)

            chmod.assert_called_once_with(DEFAULT_SWAPFILE, 0o600)
            command.assert_not_called()

    def test_inactive_managed_file_can_be_activated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fstab = Path(directory) / "fstab"
            fstab.write_text("# Managed by vps-bootstrap: swap\n/swapfile none swap sw 0 0\n", encoding="utf-8")
            disc = discovery(swapfile=SwapFileInfo(True, 2 * GIB, 0o600, "file"))

            def fake_run(args, timeout=10):
                return CommandResult(args, 0, "ok", "")

            with patch("app.swap.FSTAB", fstab), patch("app.swap.os.chmod"), patch("app.swap.run_command", side_effect=fake_run) as command:
                repair_managed_swap({"mode": "managed", "path": "/swapfile", "size_bytes": 2 * GIB}, disc)

            self.assertEqual([call.args[0][0] for call in command.call_args_list], ["mkswap", "swapon"])

    def test_managed_size_drift_blocks_destructive_repair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fstab = Path(directory) / "fstab"
            fstab.write_text(
                "# Managed by vps-bootstrap: swap\n"
                "/swapfile none swap sw 0 0\n",
                encoding="utf-8",
            )
            disc = discovery(
                active=[SwapArea("/swapfile", "file", 1 * GIB)],
                fstab_entries=[MANAGED_FSTAB_LINE],
                swapfile=SwapFileInfo(True, 1 * GIB, 0o600, "file"),
            )

            with patch("app.swap.FSTAB", fstab):
                with self.assertRaisesRegex(SwapError, "size drift"):
                    repair_managed_swap(
                        {"mode": "managed", "path": "/swapfile", "size_bytes": 2 * GIB},
                        disc,
                    )

    def test_unmanaged_duplicate_swapfile_fstab_entry_blocks_repair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fstab = Path(directory) / "fstab"
            fstab.write_text("/swapfile none swap sw 0 0\n", encoding="utf-8")
            disc = discovery(active=[SwapArea("/swapfile", "file", 2 * GIB)], swapfile=SwapFileInfo(True, 2 * GIB, 0o600, "file"))

            with patch("app.swap.FSTAB", fstab):
                with self.assertRaisesRegex(SwapError, "Conflicting unmanaged"):
                    repair_managed_swap({"mode": "managed", "path": "/swapfile", "size_bytes": 2 * GIB}, disc)

    def test_resume_skips_verified_swap_state(self) -> None:
        state = InstallState.fresh(["swap"])
        state.update_phase_data("swap", {"mode": "existing", "areas": ["/dev/vda2"]})
        state.set_phase("swap", PhaseStatus.DONE)
        disc = discovery(active=[SwapArea("/dev/vda2", "partition", 2 * GIB)])

        with patch("app.swap.discover_swap", return_value=disc):
            self.assertTrue(verify_swap_state(state.phases["swap"].data))

    def test_proc_swaps_parser(self) -> None:
        output = "Filename Type Size Used Priority\n/swapfile file 2097148 0 -2\n"

        areas = parse_proc_swaps(output)

        self.assertEqual(areas[0].path, "/swapfile")
        self.assertGreater(areas[0].size_bytes, 2_000_000_000)


if __name__ == "__main__":
    unittest.main()
