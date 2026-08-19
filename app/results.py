from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    OK = "OK"
    WARN = "WARN"
    ERROR = "ERROR"
    INFO = "INFO"


@dataclass(frozen=True)
class CheckResult:
    name: str
    severity: Severity
    message: str
    details: str = ""

    @property
    def fatal(self) -> bool:
        return self.severity == Severity.ERROR

    def format(self) -> str:
        suffix = f" - {self.details}" if self.details else ""
        return f"[{self.severity.value}] {self.message}{suffix}"


def split_results(results: list[CheckResult]) -> tuple[list[CheckResult], list[CheckResult]]:
    fatal = [result for result in results if result.severity == Severity.ERROR]
    warnings = [result for result in results if result.severity == Severity.WARN]
    return fatal, warnings
