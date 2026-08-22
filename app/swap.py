from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from app.command import CommandResult, run_command
from app.filesystem import mode_of, write_atomic


GIB = 1024**3
MIB = 1024**2
DEFAULT_SWAPFILE = Path("/swapfile")
FSTAB = Path("/etc/fstab")
MANAGED_FSTAB_LINE = "/swapfile none swap sw 0 0"
MANAGED_FSTAB_COMMENT = "# Managed by vps-bootstrap: swap"
SUPPORTED_SWAPFILE_FILESYSTEMS = {"ext2", "ext3", "ext4", "xfs"}
UNSUPPORTED_SWAPFILE_FILESYSTEMS = {"btrfs", "zfs"}
MIN_FREE_AFTER_SWAP_BYTES = GIB
MAX_MANAGED_SWAP_BYTES = 8 * GIB
SIZE_TOLERANCE_BYTES = 64 * MIB


class SwapError(RuntimeError):
    def __init__(self, message: str, diagnostics: list[str] | None = None) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics or swap_diagnostics()


@dataclass(frozen=True)
class SwapArea:
    path: str
    kind: str
    size_bytes: int
    used_bytes: int = 0
    priority: int = -2


@dataclass(frozen=True)
class SwapFileInfo:
    exists: bool
    size_bytes: int = 0
    mode: int | None = None
    kind: str = "missing"


@dataclass(frozen=True)
class SwapDiscovery:
    ram_total_bytes: int
    active_areas: list[SwapArea]
    fstab_swap_entries: list[str]
    root_filesystem: str
    root_free_bytes: int
    swapfile: SwapFileInfo


@dataclass(frozen=True)
class SwapPlan:
    action: str
    path: str = str(DEFAULT_SWAPFILE)
    size_bytes: int = 0
    reason: str = ""
    existing_areas: list[str] = field(default_factory=list)


def parse_proc_meminfo(content: str) -> tuple[int, int]:
    values: dict[str, int] = {}
    for line in content.splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        parts = raw.strip().split()
        if parts and parts[0].isdigit():
            values[key] = int(parts[0]) * 1024
    return values.get("MemTotal", 0), values.get("SwapTotal", 0)


def parse_proc_swaps(content: str) -> list[SwapArea]:
    areas: list[SwapArea] = []
    for line in content.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        size_kib = parse_int(parts[2])
        used_kib = parse_int(parts[3])
        priority = parse_int(parts[4], default=-2)
        areas.append(SwapArea(parts[0], parts[1], size_kib * 1024, used_kib * 1024, priority))
    return areas


def parse_swapon_show(output: str) -> list[SwapArea]:
    areas: list[SwapArea] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[0].upper() == "NAME":
            continue
        size_bytes = parse_size_to_bytes(parts[2])
        used_bytes = parse_size_to_bytes(parts[3]) if len(parts) > 3 else 0
        priority = parse_int(parts[4], default=-2) if len(parts) > 4 else -2
        areas.append(SwapArea(parts[0], parts[1], size_bytes, used_bytes, priority))
    return areas


def parse_fstab_swap_entries(content: str) -> list[str]:
    entries: list[str] = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 3 and parts[2] == "swap":
            entries.append(line)
    return entries


def parse_size_to_bytes(value: str) -> int:
    text = value.strip().lower().replace(",", ".")
    units = {"b": 1, "k": 1024, "kb": 1024, "m": MIB, "mb": MIB, "g": GIB, "gb": GIB}
    number = ""
    suffix = ""
    for char in text:
        if char.isdigit() or char == ".":
            number += char
        else:
            suffix += char
    if not number:
        return 0
    multiplier = units.get(suffix or "b", 1)
    return int(float(number) * multiplier)


def parse_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except ValueError:
        return default


def discover_swap() -> SwapDiscovery:
    ram_total, _ = read_meminfo()
    active = read_active_swap_areas()
    fstab_entries = parse_fstab_swap_entries(FSTAB.read_text(encoding="utf-8") if FSTAB.exists() else "")
    fs_type = command_stdout(["findmnt", "-n", "-o", "FSTYPE", "/"]) or "unknown"
    usage = shutil.disk_usage("/")
    return SwapDiscovery(
        ram_total_bytes=ram_total,
        active_areas=active,
        fstab_swap_entries=fstab_entries,
        root_filesystem=fs_type.strip().lower(),
        root_free_bytes=usage.free,
        swapfile=inspect_swapfile(DEFAULT_SWAPFILE),
    )


def read_meminfo() -> tuple[int, int]:
    path = Path("/proc/meminfo")
    if not path.exists():
        return 0, 0
    return parse_proc_meminfo(path.read_text(encoding="utf-8"))


def read_active_swap_areas() -> list[SwapArea]:
    proc = Path("/proc/swaps")
    if proc.exists():
        areas = parse_proc_swaps(proc.read_text(encoding="utf-8"))
        if areas:
            return areas
    result = run_command(["swapon", "--show", "--bytes", "--noheadings"], timeout=5)
    return parse_swapon_show(result.stdout) if result.ok else []


def command_stdout(args: list[str]) -> str:
    result = run_command(args, timeout=5)
    return result.stdout if result.ok else ""


def inspect_swapfile(path: Path) -> SwapFileInfo:
    if not path.exists():
        return SwapFileInfo(False)
    kind = "file" if path.is_file() else "other"
    mode = mode_of(path) if path.is_file() else None
    return SwapFileInfo(True, path.stat().st_size if path.is_file() else 0, mode, kind)


def recommended_swap_size_bytes(ram_total_bytes: int) -> int:
    if ram_total_bytes <= 2 * GIB:
        return 2 * GIB
    if ram_total_bytes <= 8 * GIB:
        return 1 * GIB
    return 2 * GIB


def validate_swap_size(size_bytes: int, free_bytes: int) -> None:
    if size_bytes <= 0:
        raise SwapError("Swap size must be greater than zero.")
    if size_bytes > MAX_MANAGED_SWAP_BYTES:
        raise SwapError("Requested swap size is too large for v0.1.3 safety limits.")
    if free_bytes - size_bytes < MIN_FREE_AFTER_SWAP_BYTES:
        raise SwapError("Insufficient disk space for swap while keeping a safe free-space reserve.")


def validate_filesystem_for_swap(fs_type: str) -> None:
    normalized = fs_type.lower().strip()
    if normalized in SUPPORTED_SWAPFILE_FILESYSTEMS:
        return
    if normalized in UNSUPPORTED_SWAPFILE_FILESYSTEMS:
        raise SwapError(f"Filesystem {fs_type} requires special swapfile handling and is blocked in v0.1.3.")
    raise SwapError(f"Unsupported or unknown filesystem for managed swapfile: {fs_type}.")


def plan_swap_creation(discovery: SwapDiscovery, requested_size_bytes: int | None = None) -> SwapPlan:
    if discovery.active_areas:
        return SwapPlan("use_existing", reason="active swap already exists", existing_areas=[area.path for area in discovery.active_areas])
    validate_filesystem_for_swap(discovery.root_filesystem)
    size = requested_size_bytes or recommended_swap_size_bytes(discovery.ram_total_bytes)
    validate_swap_size(size, discovery.root_free_bytes)
    if discovery.swapfile.exists:
        if discovery.swapfile.kind != "file":
            raise SwapError(f"{DEFAULT_SWAPFILE} exists but is not a regular file.")
        raise SwapError(f"{DEFAULT_SWAPFILE} already exists and is not known to be managed by vps-bootstrap; refusing to overwrite it.")
    return SwapPlan("create", size_bytes=size, reason="no active swap detected")


def render_fstab_with_managed_swap(current: str) -> str:
    unmanaged: list[str] = []
    skip_next_managed = False
    for raw in current.splitlines():
        line = raw.rstrip()
        if line == MANAGED_FSTAB_COMMENT:
            skip_next_managed = True
            continue
        if skip_next_managed and line.strip() == MANAGED_FSTAB_LINE:
            skip_next_managed = False
            continue
        skip_next_managed = False
        unmanaged.append(line)
    while unmanaged and unmanaged[-1] == "":
        unmanaged.pop()
    unmanaged.extend(["", MANAGED_FSTAB_COMMENT, MANAGED_FSTAB_LINE])
    return "\n".join(unmanaged).lstrip("\n") + "\n"


def count_managed_fstab_entries(content: str) -> int:
    lines = content.splitlines()
    count = 0
    for index, line in enumerate(lines):
        if line.strip() == MANAGED_FSTAB_COMMENT and index + 1 < len(lines) and lines[index + 1].strip() == MANAGED_FSTAB_LINE:
            count += 1
    return count


def count_fstab_entries_for_path(content: str, path: str) -> int:
    count = 0
    for entry in parse_fstab_swap_entries(content):
        parts = entry.split()
        if parts and parts[0] == path:
            count += 1
    return count


def has_conflicting_swapfile_fstab_entry(content: str, path: str = str(DEFAULT_SWAPFILE)) -> bool:
    lines = content.splitlines()
    for index, raw in enumerate(lines):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 3 and parts[0] == path and parts[2] == "swap":
            previous = lines[index - 1].strip() if index > 0 else ""
            if line != MANAGED_FSTAB_LINE or previous != MANAGED_FSTAB_COMMENT:
                return True
    return False


def ensure_swap_from_state(data: dict) -> dict:
    discovery = discover_swap()
    if data:
        mode = data.get("mode")
        if mode == "existing":
            return data
        if mode == "managed":
            repair_managed_swap(data, discovery)
            return data

    if discovery.active_areas:
        print("Detected active swap:")
        for area in discovery.active_areas:
            print(f"  {area.path} {area.size_bytes // MIB} MiB")
        print("Existing active swap will be preserved; no second swapfile will be created.")
        return {"mode": "existing", "areas": [area.path for area in discovery.active_areas]}

    print("Swap is not configured.")
    recommended = recommended_swap_size_bytes(discovery.ram_total_bytes)
    print(f"Recommended swap size: {recommended // MIB} MiB")
    print("[1] Create recommended swap")
    print("[2] Specify custom size in MiB")
    print("[3] Skip swap configuration")
    choice = input("Select option [1]: ").strip() or "1"
    if choice == "3":
        return {"mode": "skipped", "reason": "user skipped swap configuration"}
    if choice == "2":
        raw_size = input("Swap size in MiB: ").strip()
        if not raw_size.isdigit():
            raise SwapError("Swap size must be a positive integer MiB value.")
        size = int(raw_size) * MIB
    else:
        size = recommended
    plan = plan_swap_creation(discovery, size)
    apply_managed_swap(plan)
    return {"mode": "managed", "path": str(DEFAULT_SWAPFILE), "size_bytes": plan.size_bytes}


def apply_managed_swap(plan: SwapPlan) -> None:
    if plan.action != "create":
        return
    validate_swap_size(plan.size_bytes, shutil.disk_usage("/").free)
    backup = backup_fstab()
    created_file = False
    activated = False
    try:
        if DEFAULT_SWAPFILE.exists():
            raise SwapError(f"{DEFAULT_SWAPFILE} already exists and is not known to be managed by vps-bootstrap; refusing to run mkswap.")
        created_file = True
        create_non_sparse_swapfile(DEFAULT_SWAPFILE, plan.size_bytes)
        os.chmod(DEFAULT_SWAPFILE, 0o600)
        mkswap = run_command(["mkswap", str(DEFAULT_SWAPFILE)], timeout=60)
        if not mkswap.ok:
            raise SwapError(f"mkswap failed: {mkswap.stderr or mkswap.stdout}")
        write_atomic(FSTAB, render_fstab_with_managed_swap(FSTAB.read_text(encoding="utf-8") if FSTAB.exists() else ""), 0o644)
        swapon = run_command(["swapon", str(DEFAULT_SWAPFILE)], timeout=30)
        if not swapon.ok:
            raise SwapError(f"swapon failed: {swapon.stderr or swapon.stdout}")
        activated = True
    except Exception:
        rollback_swap(backup, created_file, activated)
        raise


def repair_managed_swap(data: dict, discovery: SwapDiscovery) -> None:
    expected_path = str(data.get("path", DEFAULT_SWAPFILE))
    expected_size = int(data.get("size_bytes", 0) or 0)
    if expected_path != str(DEFAULT_SWAPFILE):
        raise SwapError(f"Unsupported managed swap path in state: {expected_path}")
    fstab_content = FSTAB.read_text(encoding="utf-8") if FSTAB.exists() else ""
    if has_conflicting_swapfile_fstab_entry(fstab_content, expected_path):
        raise SwapError(f"Conflicting unmanaged {expected_path} swap entry exists in /etc/fstab; refusing automatic repair.")
    active = next((area for area in discovery.active_areas if area.path == expected_path), None)
    if active:
        if expected_size and abs(active.size_bytes - expected_size) > SIZE_TOLERANCE_BYTES:
            raise SwapError("Managed swap size drift detected; automatic destructive resize is blocked in v0.1.3.")
        if discovery.swapfile.exists and discovery.swapfile.mode != 0o600:
            os.chmod(DEFAULT_SWAPFILE, 0o600)
        ensure_managed_fstab_entry(fstab_content)
        return
    if discovery.swapfile.exists:
        if discovery.swapfile.kind != "file":
            raise SwapError(f"{DEFAULT_SWAPFILE} exists but is not a regular file.")
        if expected_size and abs(discovery.swapfile.size_bytes - expected_size) > SIZE_TOLERANCE_BYTES:
            raise SwapError("Managed swapfile size drift detected; automatic destructive resize is blocked in v0.1.3.")
        if not managed_swap_ownership_confirmed(data, discovery, fstab_content):
            raise SwapError(f"{DEFAULT_SWAPFILE} exists but ownership by vps-bootstrap cannot be proven; refusing to run mkswap.")
        os.chmod(DEFAULT_SWAPFILE, 0o600)
        ensure_managed_fstab_entry(fstab_content)
        mkswap = run_command(["mkswap", str(DEFAULT_SWAPFILE)], timeout=60)
        if not mkswap.ok:
            raise SwapError(f"mkswap failed: {mkswap.stderr or mkswap.stdout}")
        swapon = run_command(["swapon", str(DEFAULT_SWAPFILE)], timeout=30)
        if not swapon.ok:
            raise SwapError(f"swapon failed: {swapon.stderr or swapon.stdout}")
        return
    plan = SwapPlan("create", size_bytes=expected_size)
    apply_managed_swap(plan)


def managed_swap_ownership_confirmed(data: dict, discovery: SwapDiscovery, fstab_content: str) -> bool:
    if data.get("mode") != "managed":
        return False
    if count_managed_fstab_entries(fstab_content) == 1:
        return True
    expected_size = int(data.get("size_bytes", 0) or 0)
    return bool(expected_size and abs(discovery.swapfile.size_bytes - expected_size) <= SIZE_TOLERANCE_BYTES and discovery.swapfile.mode == 0o600)


def ensure_managed_fstab_entry(current: str) -> None:
    if count_managed_fstab_entries(current) == 1 and count_fstab_entries_for_path(current, str(DEFAULT_SWAPFILE)) == 1:
        return
    backup = backup_fstab()
    try:
        write_atomic(FSTAB, render_fstab_with_managed_swap(current), 0o644)
    except Exception:
        rollback_swap(backup, created_file=False, activated=False)
        raise


def create_non_sparse_swapfile(path: Path, size_bytes: int) -> None:
    count_mib = size_bytes // MIB
    result = run_command(["dd", "if=/dev/zero", f"of={path}", "bs=1M", f"count={count_mib}", "status=none", "conv=fsync"], timeout=600)
    if not result.ok:
        raise SwapError(f"Failed to create non-sparse swapfile: {result.stderr or result.stdout}")
    os.chmod(path, 0o600)


def backup_fstab() -> Path | None:
    if not FSTAB.exists():
        return None
    backup = FSTAB.with_name(f"fstab.vps-bootstrap.bak-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}")
    shutil.copy2(FSTAB, backup)
    os.chmod(backup, 0o600)
    return backup


def rollback_swap(backup: Path | None, created_file: bool, activated: bool) -> None:
    if activated:
        run_command(["swapoff", str(DEFAULT_SWAPFILE)], timeout=30)
    if backup is not None and backup.exists():
        shutil.copy2(backup, FSTAB)
        os.chmod(FSTAB, 0o644)
    elif FSTAB.exists() and MANAGED_FSTAB_COMMENT in FSTAB.read_text(encoding="utf-8"):
        FSTAB.unlink()
    if created_file:
        try:
            DEFAULT_SWAPFILE.unlink()
        except FileNotFoundError:
            pass


def verify_swap_state(data: dict) -> bool:
    if not data:
        return False
    mode = data.get("mode")
    discovery = discover_swap()
    if mode == "existing":
        expected = set(data.get("areas", []))
        active = {area.path for area in discovery.active_areas}
        return bool(expected) and expected.issubset(active)
    if mode == "managed":
        expected_path = str(data.get("path", DEFAULT_SWAPFILE))
        expected_size = int(data.get("size_bytes", 0) or 0)
        return verify_managed_swap(discovery, expected_path, expected_size)
    if mode == "skipped":
        return True
    return False


def verify_managed_swap(discovery: SwapDiscovery, expected_path: str, expected_size: int) -> bool:
    active = next((area for area in discovery.active_areas if area.path == expected_path), None)
    if active is None:
        return False
    if expected_size and abs(active.size_bytes - expected_size) > SIZE_TOLERANCE_BYTES:
        return False
    if discovery.swapfile.mode != 0o600:
        return False
    fstab_content = FSTAB.read_text(encoding="utf-8") if FSTAB.exists() else ""
    if count_managed_fstab_entries(fstab_content) != 1:
        return False
    if count_fstab_entries_for_path(fstab_content, expected_path) != 1:
        return False
    if has_conflicting_swapfile_fstab_entry(fstab_content, expected_path):
        return False
    return MANAGED_FSTAB_LINE in discovery.fstab_swap_entries


def swap_diagnostics() -> list[str]:
    return ["cat /proc/swaps", "swapon --show --bytes", "grep -n swap /etc/fstab", "findmnt -n -o FSTYPE /", "ls -l /swapfile"]


def command_result(args: list[str], ok: bool = True, stdout: str = "", stderr: str = "") -> CommandResult:
    return CommandResult(args=args, returncode=0 if ok else 1, stdout=stdout, stderr=stderr)
