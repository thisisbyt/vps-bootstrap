import unittest

from app.results import CheckResult, Severity, split_results


class ResultsTests(unittest.TestCase):
    def test_result_format_and_split(self) -> None:
        results = [
            CheckResult("dns", Severity.OK, "DNS resolution"),
            CheckResult("swap", Severity.WARN, "Swap is not configured"),
            CheckResult("route", Severity.ERROR, "Default route missing"),
        ]

        fatal, warnings = split_results(results)

        self.assertEqual(results[0].format(), "[OK] DNS resolution")
        self.assertEqual(len(fatal), 1)
        self.assertEqual(len(warnings), 1)
