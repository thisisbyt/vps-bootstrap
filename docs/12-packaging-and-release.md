# Packaging and release

## Three layers

VPS Bootstrap has three separate layers:

```text
Development repository
    -> Release artifact
    -> Installed VPS Bootstrap
```

They must not be mixed.

## Development repository

Contains everything needed for development and review:

- `AGENTS.md`;
- `README.md`;
- `docs/`;
- `tests/`;
- `tools/`;
- `.github/workflows/`;
- runtime sources.

The development repository is not a production deployment artifact.

## Release artifact

Contains only files explicitly allowed by:

```text
packaging/runtime-manifest.txt
```

Current runtime allowlist:

```text
bootstrap.sh
requirements.txt
versions.yml
app/
ansible/
templates/
```

New repository files are excluded by default until added to the manifest.

The artifact name is:

```text
dist/vps-bootstrap-v0.1.2.tar.gz
dist/SHA256SUMS
```

The archive has one top-level directory:

```text
vps-bootstrap-v0.1.2/
```

It must not contain `AGENTS.md`, `README.md`, `docs/`, `tests/`, `.git/`, `.github/`, `site/`, `tools/`, caches, local config, state, logs, or secrets.

Runtime artifact v0.1.2 does not support symlinks. A symlink as a manifest entry or anywhere under an allowlisted directory is a packaging error, even if it points back inside the repository.

File modes in the archive are deterministic:

```text
directories: 0755
bootstrap.sh: 0755
all other regular files: 0644
```

Future executable runtime files must be added through explicit packaging metadata, not inferred from host filesystem permissions.

## Installed VPS Bootstrap

After bootstrap, the installed product lives under:

```text
/opt/vps-bootstrap/releases/<release>/
/opt/vps-bootstrap/current -> /opt/vps-bootstrap/releases/<release>
/usr/local/bin/vps-bootstrap
/etc/vps-bootstrap/
/var/lib/vps-bootstrap/
/var/log/vps-bootstrap/
```

The wrapper uses:

```text
/opt/vps-bootstrap/current/venv/bin/python
```

The extraction directory used to start bootstrap is disposable after successful installation.

## Local build

```bash
python3 -m unittest discover -s tests
python3 -m compileall app tests tools
bash -n bootstrap.sh
python3 tools/build_release.py
cd dist
sha256sum -c SHA256SUMS
tar -tzf vps-bootstrap-v0.1.2.tar.gz
```

## Git workflow

Development changes should use the following flow:

```text
feature/fix/chore branch
    -> Pull Request
    -> CI
    -> main
    -> version tag
    -> GitHub Release
```

CI runs the non-publishing release checks on pull requests to `main` and pushes to `main`: unit tests, compile/import checks, `bootstrap.sh` syntax check, packaging tests, runtime artifact build, and `SHA256SUMS` verification.

Do not introduce permanent `test` or `prod` branches for this project. Production distribution is the immutable versioned GitHub Release artifact, not a branch checkout.

## Tag consistency

Release tag `v0.1.2` must match `project.version: "0.1.2"` in `versions.yml`.

If the tag is `v0.1.3` while project version is `0.1.2`, release build must fail.

## Immutable release assets

GitHub Release assets are immutable for production tags. The release workflow must not use `--clobber`.

If `vps-bootstrap-vX.Y.Z.tar.gz` or `SHA256SUMS` already exists for a tag, the workflow must not replace it. If a previous run failed after uploading only one asset, a later run may upload the missing asset, but it still reports the existing asset as an immutable conflict.

Changing release contents requires a new project version and a new tag.

## Atomic local artifact writes

The builder writes `tar.gz` and `SHA256SUMS` to temporary files in the `dist` filesystem first. Final paths are updated with `os.replace()` only after archive creation and checksum generation succeed.

If a new build fails, previously valid final artifact files must remain byte-for-byte unchanged.

## Checksum limits

`SHA256SUMS` detects corruption or artifact mismatch. If the release source and checksum are compromised together, checksum verification alone is not publisher authentication.

Release signing is a future hardening item and is not implemented in v0.1.2.

For a public repository, downloading a published release artifact does not require GitHub credentials. For a private repository, authentication strategy must be designed separately; v0.1.2 does not store GitHub tokens on the VPS.
