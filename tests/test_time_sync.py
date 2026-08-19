import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.command import CommandResult
from app.time_sync import (
    NtpProbeResult,
    TimeSyncError,
    TimeSyncStatus,
    chrony_has_selected_source,
    chrony_tracking_healthy,
    ensure_time_synchronization,
    reachable_providers,
    verify_chrony_commands,
    verify_time_sync_health,
)


def status(synchronized: bool) -> TimeSyncStatus:
    return TimeSyncStatus(
        time_sane=True,
        service_active=True,
        active_services=["systemd-timesyncd.service"],
        synchronized=synchronized,
        raw_ntp_synchronized="yes" if synchronized else "no",
    )


class TimeSyncTests(unittest.TestCase):
    def test_verify_time_sync_requires_active_service(self) -> None:
        state = TimeSyncStatus(
            time_sane=True,
            service_active=False,
            active_services=[],
            synchronized=True,
            raw_ntp_synchronized="yes",
        )
        with patch("app.time_sync.collect_time_sync_status", return_value=state):
            self.assertFalse(verify_time_sync_health())

    def test_verify_time_sync_accepts_synchronized_timesyncd(self) -> None:
        with patch("app.time_sync.collect_time_sync_status", return_value=status(True)):
            self.assertTrue(verify_time_sync_health())

    def test_verify_time_sync_requires_healthy_chrony_if_chrony_active(self) -> None:
        state = TimeSyncStatus(
            time_sane=True,
            service_active=True,
            active_services=["chrony.service"],
            synchronized=True,
            raw_ntp_synchronized="yes",
        )
        with patch("app.time_sync.collect_time_sync_status", return_value=state), patch("app.time_sync.verify_chrony_commands", return_value=False):
            self.assertFalse(verify_time_sync_health())

    def test_verify_time_sync_accepts_healthy_chrony(self) -> None:
        state = TimeSyncStatus(
            time_sane=True,
            service_active=True,
            active_services=["chrony.service"],
            synchronized=True,
            raw_ntp_synchronized="yes",
        )
        with patch("app.time_sync.collect_time_sync_status", return_value=state), patch("app.time_sync.verify_chrony_commands", return_value=True):
            self.assertTrue(verify_time_sync_health())

    def test_synchronized_systemd_timesyncd_does_not_install_chrony(self) -> None:
        with patch("app.time_sync.collect_time_sync_status", return_value=status(True)), patch("app.time_sync.install_chrony") as install:
            ensure_time_synchronization()

        install.assert_not_called()

    def test_unsynchronized_systemd_timesyncd_uses_chrony_fallback_with_candidate_redundancy(self) -> None:
        candidates = ["time.cloudflare.com", "time.google.com", "ntp.ubuntu.com", "pool.ntp.org"]
        probes = [
            NtpProbeResult("ntp.ubuntu.com", False, error="timeout"),
            NtpProbeResult("time.cloudflare.com", True, address="162.159.200.1"),
        ]
        with patch("app.time_sync.compatibility") as compat, patch("app.time_sync.collect_time_sync_status", return_value=status(False)), patch(
            "app.time_sync.probe_ntp_providers", return_value=probes
        ), patch("app.time_sync.install_chrony") as install, patch("app.time_sync.configure_chrony") as configure, patch(
            "app.time_sync.detect_chrony_unit", return_value="chrony.service"
        ), patch("app.time_sync.restart_chrony") as restart, patch("app.time_sync.wait_for_synchronization", return_value=True):
            compat.return_value = SimpleNamespace(ntp_providers=candidates, ntp_probe_timeout_seconds=2)
            ensure_time_synchronization()

        install.assert_called_once()
        configure.assert_called_once_with(candidates)
        restart.assert_called_once_with("chrony.service")

    def test_one_ntp_provider_timeout_another_works(self) -> None:
        probes = [
            NtpProbeResult("ntp.ubuntu.com", False, error="timeout"),
            NtpProbeResult("time.cloudflare.com", True, address="162.159.200.1"),
        ]

        self.assertEqual(reachable_providers(probes), ["time.cloudflare.com"])

    def test_all_providers_unavailable_fails(self) -> None:
        with patch("app.time_sync.collect_time_sync_status", return_value=status(False)), patch(
            "app.time_sync.probe_ntp_providers", return_value=[NtpProbeResult("ntp.ubuntu.com", False, error="timeout")]
        ), patch("app.time_sync.install_chrony") as install:
            with self.assertRaises(TimeSyncError):
                ensure_time_synchronization()

        install.assert_not_called()

    def test_chrony_verification_selected_source_success(self) -> None:
        def fake_run(args, timeout=10):
            if args[:2] == ["chronyc", "tracking"]:
                return CommandResult(args, 0, "Reference ID    : A29FC801\nStratum         : 3\nLeap status     : Normal", "")
            return CommandResult(args, 0, "^* time.cloudflare.com", "")

        with patch("app.time_sync.run_command", side_effect=fake_run):
            self.assertTrue(verify_chrony_commands())

    def test_chrony_verification_all_unknown_sources_fail(self) -> None:
        def fake_run(args, timeout=10):
            if args[:2] == ["chronyc", "tracking"]:
                return CommandResult(args, 0, "Stratum         : 3\nLeap status     : Normal", "")
            return CommandResult(args, 0, "^? ntp.ubuntu.com\n^? time.cloudflare.com", "")

        with patch("app.time_sync.run_command", side_effect=fake_run):
            self.assertFalse(verify_chrony_commands())

    def test_chrony_verification_stale_tracking_and_no_selected_source_fail(self) -> None:
        self.assertFalse(chrony_tracking_healthy("Stratum         : 0\nLeap status     : Not synchronised"))
        self.assertFalse(chrony_has_selected_source("^? ntp.ubuntu.com\n^- time.cloudflare.com"))

    def test_chrony_verification_stratum_zero_fails(self) -> None:
        self.assertFalse(chrony_tracking_healthy("Stratum      :    0\nLeap status  : Normal"))

    def test_chrony_verification_not_synchronised_fails(self) -> None:
        self.assertFalse(chrony_tracking_healthy("Stratum      : 3\nLeap status  : Not synchronised"))
