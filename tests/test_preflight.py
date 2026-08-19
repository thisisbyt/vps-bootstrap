import unittest
from unittest.mock import patch

from app.command import CommandResult
from app.preflight import check_clock_synchronized, check_ntp_service, check_ufw, format_service_status, summarize_listening_sockets
from app.results import Severity
from app.time_sync import TimeSyncStatus


class PreflightTests(unittest.TestCase):
    def test_ufw_status_failure_is_warning(self) -> None:
        with patch("app.preflight.shutil.which", return_value="/usr/sbin/ufw"), patch(
            "app.preflight.run_command",
            return_value=CommandResult(["ufw", "status"], 1, "", "ERROR: problem running ufw"),
        ):
            result = check_ufw()

        self.assertEqual(result.severity, Severity.WARN)
        self.assertIn("status command failed", result.message)
        self.assertIn("problem running ufw", result.details)

    def test_compact_ports_summary(self) -> None:
        output = """Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      4096       0.0.0.0:22        0.0.0.0:*     users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0      4096          [::]:22           [::]:*
udp   UNCONN 0      0          127.0.0.1:323       0.0.0.0:*
"""

        self.assertEqual(summarize_listening_sockets(output), (2, 1))

    def test_service_status_format_has_labels(self) -> None:
        line = format_service_status(
            "ssh.socket",
            CommandResult(["systemctl"], 0, "active", ""),
            CommandResult(["systemctl"], 0, "enabled", ""),
        )

        self.assertEqual(line, "ssh.socket: active=active, enabled=enabled")

    def test_service_status_preserves_nonzero_stdout_values(self) -> None:
        line = format_service_status(
            "ssh.service",
            CommandResult(["systemctl"], 3, "inactive", ""),
            CommandResult(["systemctl"], 1, "disabled", ""),
        )

        self.assertEqual(line, "ssh.service: active=inactive, enabled=disabled")

    def test_service_status_preserves_failed_and_masked_values(self) -> None:
        line = format_service_status(
            "example.service",
            CommandResult(["systemctl"], 3, "failed", ""),
            CommandResult(["systemctl"], 1, "masked", ""),
        )

        self.assertEqual(line, "example.service: active=failed, enabled=masked")

    def test_time_preflight_splits_service_and_synchronization(self) -> None:
        status = TimeSyncStatus(
            time_sane=True,
            service_active=True,
            active_services=["systemd-timesyncd.service"],
            synchronized=False,
            raw_ntp_synchronized="no",
        )
        with patch("app.preflight.collect_time_sync_status", return_value=status):
            service = check_ntp_service()
            clock = check_clock_synchronized()

        self.assertEqual(service.severity, Severity.OK)
        self.assertEqual(clock.severity, Severity.WARN)
        self.assertIn("Clock not synchronized", clock.message)
