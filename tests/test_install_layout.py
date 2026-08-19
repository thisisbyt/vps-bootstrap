import unittest
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
        self.assertIn('export VPS_BOOTSTRAP_PROJECT_ROOT="$CURRENT_LINK"', bootstrap)
        self.assertIn('export PYTHONPATH="$CURRENT_LINK', bootstrap)
        self.assertIn('exec "$CURRENT_LINK/venv/bin/python" -m app.cli "$@"', bootstrap)
        self.assertNotIn('export PYTHONPATH="$CHECKOUT_ROOT', bootstrap)
        self.assertNotIn('VENV_DIR="${VPS_BOOTSTRAP_VENV:-$INSTALL_DIR/venv}"', bootstrap)
        self.assertNotIn('exec "$VENV_DIR/bin/python"', bootstrap)
        self.assertNotIn('rm -rf "$INSTALL_DIR/app"', bootstrap)
