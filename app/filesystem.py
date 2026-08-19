from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ManagedPath:
    path: Path
    mode: int
    kind: str = "dir"


def chmod_secure(path: Path, mode: int) -> None:
    os.chmod(path, mode)


def chown_root_if_possible(path: Path) -> None:
    if hasattr(os, "geteuid") and hasattr(os, "chown") and os.geteuid() == 0:
        os.chown(path, 0, 0)


def ensure_directory(path: Path, mode: int) -> None:
    path.mkdir(parents=True, exist_ok=True)
    chown_root_if_possible(path)
    chmod_secure(path, mode)


def ensure_file(path: Path, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    chown_root_if_possible(path)
    chmod_secure(path, mode)


def write_atomic(path: Path, content: str, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with tmp.open("w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    chown_root_if_possible(tmp)
    chmod_secure(tmp, mode)
    os.replace(tmp, path)
    chown_root_if_possible(path)
    chmod_secure(path, mode)
    if hasattr(os, "O_DIRECTORY"):
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def has_mode(path: Path, mode: int) -> bool:
    try:
        return mode_of(path) == mode
    except OSError:
        return False


def verify_managed_path(item: ManagedPath) -> bool:
    if item.kind == "dir" and not item.path.is_dir():
        return False
    if item.kind == "file" and not item.path.is_file():
        return False
    return has_mode(item.path, item.mode)
