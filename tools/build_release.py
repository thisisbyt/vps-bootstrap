#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import re
import shutil
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


PROJECT_NAME = "vps-bootstrap"
DEFAULT_MANIFEST = Path("packaging/runtime-manifest.txt")
DEFAULT_DIST = Path("dist")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
FORBIDDEN_NAMES = {
    ".git",
    ".github",
    "__pycache__",
    "AGENTS.md",
    "README.md",
    "docs",
    "tests",
    "site",
    "tools",
}
FORBIDDEN_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".log",
    ".sqlite",
    ".db",
}
FORBIDDEN_EXACT_NAMES = {
    ".env",
}
FORBIDDEN_PREFIXES = ("secrets.", ".env.")
SKIPPED_GENERATED_NAMES = {
    "__pycache__",
    ".DS_Store",
    ".gitkeep",
}
SKIPPED_GENERATED_SUFFIXES = {
    ".pyc",
    ".pyo",
}


class PackagingError(RuntimeError):
    pass


@dataclass(frozen=True)
class BuildResult:
    version: str
    archive_path: Path
    checksum_path: Path
    checksum: str
    contents: list[str]


def project_version(repo_root: Path) -> str:
    path = repo_root / "versions.yml"
    if not path.exists():
        raise PackagingError("Missing canonical version source: versions.yml")
    in_project = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() == "project:":
            in_project = True
            continue
        if in_project and line and not line.startswith(" "):
            break
        if in_project and line.strip().startswith("version:"):
            version = clean_scalar(line.split(":", 1)[1])
            validate_version(version)
            return version
    raise PackagingError("Project version not found in versions.yml project.version")


def clean_scalar(value: str) -> str:
    return value.strip().strip('"').strip("'")


def validate_version(version: str) -> None:
    if not VERSION_RE.match(version):
        raise PackagingError(f"Invalid project version format: {version}")


def normalize_tag(tag: str) -> str:
    normalized = tag[1:] if tag.startswith("v") else tag
    validate_version(normalized)
    return normalized


def check_tag_matches_version(tag: str | None, version: str) -> None:
    if tag is None or tag == "":
        return
    tag_version = normalize_tag(tag)
    if tag_version != version:
        raise PackagingError(f"Tag/version mismatch: tag {tag} != project version {version}")


def read_manifest(repo_root: Path, manifest_path: Path) -> list[PurePosixPath]:
    manifest = manifest_path if manifest_path.is_absolute() else repo_root / manifest_path
    if not manifest.exists():
        raise PackagingError(f"Runtime manifest not found: {manifest}")
    entries: list[PurePosixPath] = []
    for line_number, raw_line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        entry = validate_relative_path(line.rstrip("/"), f"{manifest}:{line_number}")
        reject_forbidden_path(entry, f"runtime manifest entry {line}")
        entries.append(entry)
    if not entries:
        raise PackagingError("Runtime manifest is empty")
    return entries


def validate_relative_path(value: str, context: str) -> PurePosixPath:
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or str(path) in {"", "."}:
        raise PackagingError(f"Unsafe path in {context}: {value}")
    return path


def reject_forbidden_path(path: PurePosixPath, context: str) -> None:
    for part in path.parts:
        if part in FORBIDDEN_NAMES:
            raise PackagingError(f"Forbidden development path in {context}: {path}")
    name = path.name
    if name in FORBIDDEN_EXACT_NAMES or name.startswith(FORBIDDEN_PREFIXES) or any(name.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES):
        raise PackagingError(f"Forbidden file type in {context}: {path}")


def copy_runtime(repo_root: Path, stage_root: Path, entries: list[PurePosixPath]) -> None:
    for entry in entries:
        source = repo_root / Path(*entry.parts)
        target = stage_root / Path(*entry.parts)
        reject_symlink(source, entry)
        if not source.exists():
            raise PackagingError(f"Mandatory runtime path is missing: {entry}")
        if source.is_dir():
            copy_runtime_directory(source, target)
        elif source.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        else:
            raise PackagingError(f"Unsupported runtime path type: {entry}")


def copy_runtime_directory(source: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    for item in sorted(source.rglob("*")):
        relative = item.relative_to(source)
        posix_relative = PurePosixPath(relative.as_posix())
        reject_symlink(item, PurePosixPath(source.name) / posix_relative)
        if is_generated_runtime_junk(posix_relative):
            continue
        reject_forbidden_path(posix_relative, f"runtime directory {source.name}")
        destination = target / relative
        if item.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
            continue
        if item.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, destination)


def is_generated_runtime_junk(path: PurePosixPath) -> bool:
    return any(part in SKIPPED_GENERATED_NAMES for part in path.parts) or any(path.name.endswith(suffix) for suffix in SKIPPED_GENERATED_SUFFIXES)


def reject_symlink(path: Path, display_path: PurePosixPath) -> None:
    if path.is_symlink():
        raise PackagingError(f"Symlinks are not supported in runtime artifact: {display_path}")


def validate_staging(stage_root: Path) -> None:
    for item in stage_root.rglob("*"):
        relative = PurePosixPath(item.relative_to(stage_root).as_posix())
        reject_symlink(item, relative)
        validate_relative_path(relative.as_posix(), "staging directory")
        reject_forbidden_path(relative, "staging directory")


def deterministic_tar_gz(source_root: Path, archive_path: Path, top_level: str) -> list[str]:
    members = [source_root, *sorted(source_root.rglob("*"), key=lambda item: item.relative_to(source_root).as_posix())]
    contents: list[str] = []
    with archive_path.open("wb") as raw_file:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_file, mtime=0) as gzip_file:
            with tarfile.open(fileobj=gzip_file, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for item in members:
                    arcname = top_level if item == source_root else f"{top_level}/{item.relative_to(source_root).as_posix()}"
                    validate_archive_name(arcname)
                    tarinfo = tar.gettarinfo(str(item), arcname)
                    normalize_tarinfo(tarinfo, item)
                    contents.append(arcname + ("/" if item.is_dir() else ""))
                    if item.is_file():
                        with item.open("rb") as handle:
                            tar.addfile(tarinfo, handle)
                    else:
                        tar.addfile(tarinfo)
    return contents


def normalize_tarinfo(tarinfo: tarfile.TarInfo, source: Path) -> None:
    tarinfo.uid = 0
    tarinfo.gid = 0
    tarinfo.uname = ""
    tarinfo.gname = ""
    tarinfo.mtime = 0
    if source.is_dir():
        tarinfo.mode = 0o755
    elif source.name == "bootstrap.sh":
        tarinfo.mode = 0o755
    else:
        tarinfo.mode = 0o644


def validate_archive_name(name: str) -> None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise PackagingError(f"Unsafe archive member path: {name}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_sha256sums_temp(archive_name: str, checksum: str, tmp_path: Path) -> None:
    tmp_path.write_text(f"{checksum}  {archive_name}\n", encoding="utf-8")


def temp_output_path(dist_path: Path, final_name: str) -> Path:
    handle = tempfile.NamedTemporaryFile(prefix=f".{final_name}.", suffix=".tmp", dir=dist_path, delete=False)
    handle.close()
    return Path(handle.name)


def commit_outputs(archive_path: Path, checksum_path: Path, tmp_archive: Path, tmp_checksum: Path) -> None:
    backup_archive: Path | None = None
    backup_checksum: Path | None = None
    archive_replaced = False
    checksum_replaced = False
    try:
        backup_archive = backup_existing_output(archive_path)
        backup_checksum = backup_existing_output(checksum_path)
        atomic_replace(tmp_archive, archive_path)
        archive_replaced = True
        atomic_replace(tmp_checksum, checksum_path)
        checksum_replaced = True
    except Exception:
        rollback_output(archive_path, backup_archive, archive_replaced)
        rollback_output(checksum_path, backup_checksum, checksum_replaced)
        raise
    finally:
        cleanup_temp_file(backup_archive)
        cleanup_temp_file(backup_checksum)


def backup_existing_output(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup = temp_output_path(path.parent, path.name)
    try:
        shutil.copy2(path, backup)
    except Exception:
        cleanup_temp_file(backup)
        raise
    return backup


def rollback_output(target: Path, backup: Path | None, was_replaced: bool) -> None:
    if backup is not None:
        atomic_replace(backup, target)
        return
    if was_replaced:
        cleanup_temp_file(target)


def atomic_replace(source: Path, target: Path) -> None:
    os.replace(source, target)


def build_release(repo_root: Path, manifest_path: Path = DEFAULT_MANIFEST, dist_dir: Path = DEFAULT_DIST, tag: str | None = None) -> BuildResult:
    repo_root = repo_root.resolve()
    version = project_version(repo_root)
    check_tag_matches_version(tag, version)
    entries = read_manifest(repo_root, manifest_path)
    dist_path = (dist_dir if dist_dir.is_absolute() else repo_root / dist_dir).resolve()
    dist_path.mkdir(parents=True, exist_ok=True)
    top_level = f"{PROJECT_NAME}-v{version}"
    archive_path = dist_path / f"{top_level}.tar.gz"
    checksum_path = dist_path / "SHA256SUMS"
    tmp_archive: Path | None = None
    tmp_checksum: Path | None = None

    try:
        with tempfile.TemporaryDirectory(prefix=f"{PROJECT_NAME}-build-") as tmp:
            stage_root = Path(tmp) / top_level
            stage_root.mkdir()
            copy_runtime(repo_root, stage_root, entries)
            validate_staging(stage_root)
            tmp_archive = temp_output_path(dist_path, archive_path.name)
            tmp_checksum = temp_output_path(dist_path, checksum_path.name)
            contents = deterministic_tar_gz(stage_root, tmp_archive, top_level)
            checksum = sha256_file(tmp_archive)
            write_sha256sums_temp(archive_path.name, checksum, tmp_checksum)
            commit_outputs(archive_path, checksum_path, tmp_archive, tmp_checksum)
            tmp_archive = None
            tmp_checksum = None
    except Exception:
        cleanup_temp_file(tmp_archive)
        cleanup_temp_file(tmp_checksum)
        raise
    return BuildResult(version, archive_path, checksum_path, checksum, contents)


def cleanup_temp_file(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build VPS Bootstrap runtime release artifact.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--dist-dir", type=Path, default=DEFAULT_DIST)
    parser.add_argument("--tag", default=None)
    args = parser.parse_args(argv)
    env_tag = os.environ.get("GITHUB_REF_NAME", "")
    tag = args.tag if args.tag is not None else (env_tag if os.environ.get("GITHUB_REF_TYPE") == "tag" else None)
    try:
        result = build_release(args.repo_root, args.manifest, args.dist_dir, tag)
    except PackagingError as exc:
        print(f"[ERROR] release build failed: {exc}")
        return 1
    print(f"Built {result.archive_path}")
    print(f"Wrote {result.checksum_path}")
    print(f"SHA256 {result.checksum}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
