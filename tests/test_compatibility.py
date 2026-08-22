import unittest

from app.compatibility import parse_versions_yml


class CompatibilityTests(unittest.TestCase):
    def test_ubuntu_2404_baseline_from_versions_yml(self) -> None:
        compat = parse_versions_yml(
            """
project:
  version: "0.1.3"
os:
  ubuntu:
    primary: "24.04"
    supported:
      - "24.04"
python:
  minimum: "3.12"
time_sync:
  ntp_probe_timeout_seconds: 2
  synchronization_wait_seconds: 60
  providers:
    - "time.cloudflare.com"
    - "ntp.ubuntu.com"
"""
        )

        self.assertEqual(compat.project_version, "0.1.3")
        self.assertEqual(compat.primary_ubuntu, "24.04")
        self.assertEqual(compat.supported_ubuntu, {"24.04"})
        self.assertEqual(compat.python_minimum, "3.12")
        self.assertEqual(compat.ntp_providers, ["time.cloudflare.com", "ntp.ubuntu.com"])
