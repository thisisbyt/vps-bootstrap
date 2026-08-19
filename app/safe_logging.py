from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Any


SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r'(?i)("(?:password|passwd|token|secret|private[_-]?key|authorization|auth[_-]?header)"\s*:\s*")([^"]+)(")'),
        r"\1[REDACTED]\3",
    ),
    (
        re.compile(r"(?i)(Authorization\s*:\s*Bearer\s+)([^\s,;]+)"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(Authorization\s*:\s*)(?!Bearer\s+)([^\s,;]+)"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(password|passwd|token|secret|private[_-]?key|auth[_-]?header)(\s*[:=]\s*)([^\s,;]+)"),
        r"\1\2[REDACTED]",
    ),
    (
        re.compile(r"(?i)(postgres(?:ql)?://[^:\s]+:)([^@\s]+)(@)"),
        r"\1[REDACTED]\3",
    ),
    (
        re.compile(r"(?i)(https://api\.telegram\.org/bot)([^/\s]+)"),
        r"\1[REDACTED]",
    ),
]


def redact(value: Any) -> str:
    text = str(value)
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class SafeJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "stage": getattr(record, "stage", "general"),
            "action": redact(record.getMessage()),
        }
        result = getattr(record, "result", None)
        duration = getattr(record, "duration", None)
        if result is not None:
            payload["result"] = redact(result)
        if duration is not None:
            payload["duration_seconds"] = round(float(duration), 3)
        if record.exc_info:
            payload["error"] = redact(super().formatException(record.exc_info))
        return json.dumps(payload, ensure_ascii=False)


def setup_logger(log_file: Path | None) -> logging.Logger:
    logger = logging.getLogger("vps_bootstrap")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = SafeJsonFormatter()
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    if log_file is not None:
        add_file_handler(logger, log_file, create_parent=False)

    return logger


def add_file_handler(logger: logging.Logger, log_file: Path, create_parent: bool = True) -> None:
    if any(getattr(handler, "baseFilename", None) == str(log_file) for handler in logger.handlers):
        return
    try:
        if create_parent:
            log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(SafeJsonFormatter())
        logger.addHandler(file_handler)
    except OSError:
        logger.info("file logging unavailable", extra={"stage": "logging", "result": "stdout-only"})


class timed_stage:
    def __init__(self, logger: logging.Logger, stage: str, action: str) -> None:
        self.logger = logger
        self.stage = stage
        self.action = action
        self.started = 0.0

    def __enter__(self) -> "timed_stage":
        self.started = monotonic()
        self.logger.info(self.action, extra={"stage": self.stage, "result": "started"})
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        duration = monotonic() - self.started
        result = "failed" if exc else "done"
        self.logger.info(self.action, extra={"stage": self.stage, "result": result, "duration": duration})
        return False
