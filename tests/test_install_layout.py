import unittest
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


class InstallLayoutTests(unittest.TestCase):
    def test_bootstrap_wrapper_uses_stable_install_dir(self) -> None:
        bootstrap = Path("bootstrap.sh").read_text(encoding="utf-8")

        self.assertIn('INSTALL_DIR="${VPS_BOOTSTRAP_INSTALL_DIR:-/opt/vps-bootstrap}"', bootstrap)
        self.assertIn('CURRENT_LINK="$INSTALL_DIR/current"', bootstrap)
        self.assertIn('RELEASES_DIR="$INSTALL_DIR/releases"', bootstrap)
        self.assertIn('RELEASE_DIR="$RELEASES_DIR/$RELEASE_ID"', bootstrap)
        self.assertIn('RELEASE_VENV_DIR="$RELEASE_DIR/venv"', bootstrap)
        self.assertIn('mv -Tf "$NEXT_LINK" "$CURRENT_LINK"', bootstrap)
        self.assertIn('PROJECT_ROOT="$CURRENT_LINK"', bootstrap)
        self.assertIn('export VPS_BOOTSTRAP_PROJECT_ROOT="\\$PROJECT_ROOT"', bootstrap)
        self.assertIn("unset PYTHONPATH", bootstrap)
        self.assertIn('cd "\\$PROJECT_ROOT"', bootstrap)
        self.assertIn('exec "\\$PROJECT_ROOT/venv/bin/python" -m app.cli "\\$@"', bootstrap)
        self.assertIn('cd "$CURRENT_LINK"', bootstrap)
        self.assertIn('exec "$CURRENT_LINK/venv/bin/python" -m app.cli "$@"', bootstrap)
        self.assertNotIn('export PYTHONPATH="$CHECKOUT_ROOT', bootstrap)
        self.assertNotIn('export PYTHONPATH="$CURRENT_LINK', bootstrap)
        self.assertNotIn('VENV_DIR="${VPS_BOOTSTRAP_VENV:-$INSTALL_DIR/venv}"', bootstrap)
        self.assertNotIn('exec "$VENV_DIR/bin/python"', bootstrap)
        self.assertNotIn('rm -rf "$INSTALL_DIR/app"', bootstrap)

    @unittest.skipIf(os.name == "nt" or not shutil.which("bash"), "bash subprocess wrapper check requires Linux/Unix")
    def test_wrapper_cd_prevents_cwd_app_shadowing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "current"
            cwd = root / "cwd"
            wrapper = root / "vps-bootstrap"
            (release / "app").mkdir(parents=True)
            (cwd / "app").mkdir(parents=True)
            (release / "app" / "__init__.py").write_text("", encoding="utf-8")
            (cwd / "app" / "__init__.py").write_text("", encoding="utf-8")
            (release / "app" / "cli.py").write_text("print('PRODUCTION')\nprint(__file__)\n", encoding="utf-8")
            (cwd / "app" / "cli.py").write_text("print('SHADOW')\nprint(__file__)\n", encoding="utf-8")
            wrapper.write_text(
                "\n".join(
                    [
                        "#!/usr/bin/env bash",
                        "set -Eeuo pipefail",
                        f'PROJECT_ROOT="{release}"',
                        'export VPS_BOOTSTRAP_PROJECT_ROOT="$PROJECT_ROOT"',
                        "unset PYTHONPATH",
                        'cd "$PROJECT_ROOT"',
                        f'exec "{sys.executable}" -m app.cli "$@"',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            wrapper.chmod(0o755)

            result = subprocess.run(
                [str(wrapper)],
                cwd=cwd,
                env={**os.environ, "PYTHONPATH": str(cwd)},
                text=True,
                capture_output=True,
                check=True,
            )

        self.assertIn("PRODUCTION", result.stdout)
        self.assertIn(str(release / "app" / "cli.py"), result.stdout)
        self.assertNotIn("SHADOW", result.stdout)
