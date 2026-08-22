import hashlib
import os
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.build_release import PackagingError, build_release, read_manifest


def write(path: Path, content: str = "x\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def make_repo(root: Path) -> None:
    write(root / "versions.yml", 'project:\n  version: "0.1.3"\n')
    write(root / "bootstrap.sh", "#!/usr/bin/env bash\n")
    write(root / "requirements.txt", "# pinned deps go here\n")
    write(root / "app" / "__init__.py", "__version__ = '0.1.3'\n")
    write(root / "app" / "cli.py", "def main():\n    return 0\n")
    write(root / "ansible" / "playbook.yml", "---\n")
    write(root / "ansible" / "roles" / ".gitkeep", "")
    write(root / "templates" / "journald-vps-bootstrap.conf", "[Journal]\n")
    write(root / "packaging" / "runtime-manifest.txt", "bootstrap.sh\nrequirements.txt\nversions.yml\napp/\nansible/\ntemplates/\n")
    write(root / "AGENTS.md", "agent instructions\n")
    write(root / "README.md", "developer readme\n")
    write(root / "docs" / "notes.md", "docs\n")
    write(root / "tests" / "test_example.py", "tests\n")
    write(root / ".github" / "workflows" / "release.yml", "workflow\n")
    write(root / ".git" / "HEAD", "ref: refs/heads/main\n")
    write(root / "site" / "index.html", "site\n")
    write(root / "unknown-development-note.md", "must not be included\n")
    write(root / "app" / "__pycache__" / "cli.cpython-312.pyc", "cache\n")


def symlink_supported() -> bool:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        target = root / "target"
        link = root / "link"
        target.write_text("target\n", encoding="utf-8")
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            return False
        return link.is_symlink()


SYMLINK_SUPPORTED = symlink_supported()


def assert_no_temp_outputs(testcase: unittest.TestCase, dist: Path) -> None:
    if not dist.exists():
        return
    leftovers = sorted(path.name for path in dist.iterdir() if path.name.startswith(".") and path.name.endswith(".tmp"))
    testcase.assertEqual(leftovers, [])


def fail_once_on_checksum_replace():
    state = {"failed": False}

    def fake_replace(source, target):
        if Path(target).name == "SHA256SUMS" and not state["failed"]:
            state["failed"] = True
            raise RuntimeError("checksum replace failed")
        os.replace(source, target)

    return fake_replace


def fail_on_checksum_backup_copy(dist: Path):
    real_copy2 = shutil.copy2

    def fake_copy2(source, target, *args, **kwargs):
        source_path = Path(source)
        if source_path.parent == dist and source_path.name == "SHA256SUMS":
            raise RuntimeError("backup failed")
        return real_copy2(source, target, *args, **kwargs)

    return fake_copy2


class PackagingTests(unittest.TestCase):
    def test_runtime_artifact_contains_only_allowlisted_runtime_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            make_repo(repo)

            result = build_release(repo, dist_dir=repo / "dist", tag="v0.1.3")

            with tarfile.open(result.archive_path, "r:gz") as archive:
                names = archive.getnames()

        self.assertIn("vps-bootstrap-v0.1.3/bootstrap.sh", names)
        self.assertIn("vps-bootstrap-v0.1.3/requirements.txt", names)
        self.assertIn("vps-bootstrap-v0.1.3/versions.yml", names)
        self.assertIn("vps-bootstrap-v0.1.3/app/cli.py", names)
        self.assertIn("vps-bootstrap-v0.1.3/ansible/playbook.yml", names)
        self.assertIn("vps-bootstrap-v0.1.3/templates/journald-vps-bootstrap.conf", names)
        self.assertEqual({name.split("/", 1)[0] for name in names}, {"vps-bootstrap-v0.1.3"})

        forbidden = ["AGENTS.md", "README.md", "docs/", "tests/", ".git/", ".github/", "site/", "tools/", "__pycache__", ".pyc", ".gitkeep"]
        for name in names:
            self.assertTrue(name == "vps-bootstrap-v0.1.3" or name.startswith("vps-bootstrap-v0.1.3/"))
            self.assertFalse(any(part in name for part in forbidden), name)
        self.assertFalse(any("unknown-development-note.md" in name for name in names))

    def test_checksum_matches_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            make_repo(repo)

            result = build_release(repo, dist_dir=repo / "dist")
            digest = hashlib.sha256(result.archive_path.read_bytes()).hexdigest()
            checksums = result.checksum_path.read_text(encoding="utf-8")

        self.assertEqual(result.checksum, digest)
        self.assertEqual(checksums, f"{digest}  vps-bootstrap-v0.1.3.tar.gz\n")

    def test_artifact_version_comes_from_versions_yml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            make_repo(repo)

            result = build_release(repo, dist_dir=repo / "dist")

        self.assertEqual(result.version, "0.1.3")
        self.assertEqual(result.archive_path.name, "vps-bootstrap-v0.1.3.tar.gz")

    def test_missing_mandatory_runtime_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            make_repo(repo)
            (repo / "bootstrap.sh").unlink()

            with self.assertRaisesRegex(PackagingError, "Mandatory runtime path is missing: bootstrap.sh"):
                build_release(repo, dist_dir=repo / "dist")

    def test_tag_version_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            make_repo(repo)

            with self.assertRaisesRegex(PackagingError, "Tag/version mismatch"):
                build_release(repo, dist_dir=repo / "dist", tag="v0.1.4")

    def test_manifest_rejects_development_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            make_repo(repo)
            write(repo / "packaging" / "runtime-manifest.txt", "bootstrap.sh\ndocs/\n")

            with self.assertRaisesRegex(PackagingError, "Forbidden development path"):
                read_manifest(repo, Path("packaging/runtime-manifest.txt"))

    def test_runtime_secret_like_file_fails_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            make_repo(repo)
            write(repo / "app" / ".env", "TOKEN=secret\n")

            with self.assertRaisesRegex(PackagingError, "Forbidden file type"):
                build_release(repo, dist_dir=repo / "dist")

    @unittest.skipUnless(SYMLINK_SUPPORTED, "symlink creation is unavailable in this environment")
    def test_symlink_file_inside_allowlisted_directory_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            make_repo(repo)
            (repo / "app" / "link.txt").symlink_to(repo / "app" / "cli.py")

            with self.assertRaisesRegex(PackagingError, "Symlinks are not supported.*app/link.txt"):
                build_release(repo, dist_dir=repo / "dist")

    @unittest.skipUnless(SYMLINK_SUPPORTED, "symlink creation is unavailable in this environment")
    def test_symlink_to_file_outside_repository_fails_without_copying_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            outside = root / "outside-secret.txt"
            make_repo(repo)
            outside.write_text("outside secret\n", encoding="utf-8")
            (repo / "app" / "leak.txt").symlink_to(outside)

            with self.assertRaisesRegex(PackagingError, "Symlinks are not supported.*app/leak.txt"):
                build_release(repo, dist_dir=repo / "dist")

    @unittest.skipUnless(SYMLINK_SUPPORTED, "symlink creation is unavailable in this environment")
    def test_symlink_directory_inside_allowlisted_directory_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            outside_dir = root / "outside-dir"
            make_repo(repo)
            outside_dir.mkdir()
            write(outside_dir / "secret.txt", "outside secret\n")
            (repo / "app" / "linked-dir").symlink_to(outside_dir, target_is_directory=True)

            with self.assertRaisesRegex(PackagingError, "Symlinks are not supported.*app/linked-dir"):
                build_release(repo, dist_dir=repo / "dist")

    @unittest.skipUnless(SYMLINK_SUPPORTED, "symlink creation is unavailable in this environment")
    def test_symlink_manifest_entry_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            make_repo(repo)
            (repo / "linked-bootstrap.sh").symlink_to(repo / "bootstrap.sh")
            write(repo / "packaging" / "runtime-manifest.txt", "linked-bootstrap.sh\n")

            with self.assertRaisesRegex(PackagingError, "Symlinks are not supported.*linked-bootstrap.sh"):
                build_release(repo, dist_dir=repo / "dist")

    def test_failure_during_new_build_keeps_existing_outputs_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            make_repo(repo)
            dist = repo / "dist"
            first = build_release(repo, dist_dir=dist)
            old_archive = first.archive_path.read_bytes()
            old_checksum = first.checksum_path.read_bytes()

            with patch("tools.build_release.deterministic_tar_gz", side_effect=RuntimeError("boom")):
                with self.assertRaises(RuntimeError):
                    build_release(repo, dist_dir=dist)

            self.assertEqual(first.archive_path.read_bytes(), old_archive)
            self.assertEqual(first.checksum_path.read_bytes(), old_checksum)
            assert_no_temp_outputs(self, dist)

    def test_no_previous_outputs_second_replace_failure_leaves_no_finals(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            make_repo(repo)
            dist = repo / "dist"
            archive = dist / "vps-bootstrap-v0.1.3.tar.gz"
            checksum = dist / "SHA256SUMS"

            with patch("tools.build_release.atomic_replace", side_effect=fail_once_on_checksum_replace()):
                with self.assertRaisesRegex(RuntimeError, "checksum replace failed"):
                    build_release(repo, dist_dir=dist)

            self.assertFalse(archive.exists())
            self.assertFalse(checksum.exists())
            assert_no_temp_outputs(self, dist)

    def test_existing_outputs_second_replace_failure_restores_old_pair(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            make_repo(repo)
            dist = repo / "dist"
            first = build_release(repo, dist_dir=dist)
            old_archive = first.archive_path.read_bytes()
            old_checksum = first.checksum_path.read_bytes()

            write(repo / "app" / "cli.py", "def main():\n    return 1\n")
            with patch("tools.build_release.atomic_replace", side_effect=fail_once_on_checksum_replace()):
                with self.assertRaisesRegex(RuntimeError, "checksum replace failed"):
                    build_release(repo, dist_dir=dist)

            self.assertEqual(first.archive_path.read_bytes(), old_archive)
            self.assertEqual(first.checksum_path.read_bytes(), old_checksum)
            assert_no_temp_outputs(self, dist)

    def test_successful_transaction_replaces_both_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            make_repo(repo)
            dist = repo / "dist"
            first = build_release(repo, dist_dir=dist)
            old_archive = first.archive_path.read_bytes()
            old_checksum = first.checksum_path.read_bytes()

            write(repo / "app" / "cli.py", "def main():\n    return 2\n")
            second = build_release(repo, dist_dir=dist)
            new_archive = second.archive_path.read_bytes()
            new_checksum = second.checksum_path.read_text(encoding="utf-8")

            self.assertNotEqual(new_archive, old_archive)
            self.assertNotEqual(second.checksum_path.read_bytes(), old_checksum)
            self.assertEqual(new_checksum, f"{hashlib.sha256(new_archive).hexdigest()}  vps-bootstrap-v0.1.3.tar.gz\n")
            assert_no_temp_outputs(self, dist)

    def test_backup_failure_keeps_existing_outputs_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            make_repo(repo)
            dist = repo / "dist"
            first = build_release(repo, dist_dir=dist)
            old_archive = first.archive_path.read_bytes()
            old_checksum = first.checksum_path.read_bytes()

            write(repo / "app" / "cli.py", "def main():\n    return 3\n")
            with patch("tools.build_release.shutil.copy2", side_effect=fail_on_checksum_backup_copy(dist)):
                with self.assertRaisesRegex(RuntimeError, "backup failed"):
                    build_release(repo, dist_dir=dist)

            self.assertEqual(first.archive_path.read_bytes(), old_archive)
            self.assertEqual(first.checksum_path.read_bytes(), old_checksum)
            assert_no_temp_outputs(self, dist)

    def test_tar_member_modes_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            make_repo(repo)
            os.chmod(repo / "app" / "cli.py", 0o755)

            result = build_release(repo, dist_dir=repo / "dist")
            with tarfile.open(result.archive_path, "r:gz") as archive:
                members = archive.getmembers()

        for member in members:
            if member.isdir():
                self.assertEqual(member.mode, 0o755, member.name)
            elif member.name == "vps-bootstrap-v0.1.3/bootstrap.sh":
                self.assertEqual(member.mode, 0o755, member.name)
            else:
                self.assertEqual(member.mode, 0o644, member.name)

    def test_release_workflow_does_not_clobber_assets(self) -> None:
        workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")

        self.assertNotIn("--clobber", workflow)
        self.assertIn("Release asset already exists and will not be replaced", workflow)
