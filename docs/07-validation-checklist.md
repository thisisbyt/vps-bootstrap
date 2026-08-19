# Validation checklist

## v0.1.2 local checks

- [ ] Python modules compile
- [ ] Unit tests pass
- [ ] CLI imports successfully
- [ ] State file roundtrip works
- [ ] Resume skips verified `done` phases
- [ ] Resume repairs drifted `done` phases
- [ ] State save creates `/var/lib/vps-bootstrap` with `0750` and state file with `0640`
- [ ] Runtime directory verification checks modes, not only existence
- [ ] Managed config drift creates timestamped backup and restores default
- [ ] Unmanaged config drift requires manual intervention
- [ ] UFW status command failure is WARN, not OK
- [ ] Installed wrapper uses `/opt/vps-bootstrap`, not checkout path
- [ ] Install update uses staged release and atomic `current` symlink switch
- [ ] `time_sync_check` state migrates to `time_sync`
- [ ] `SKIPPED` phase is not executed on resume
- [ ] Time sync fallback uses chrony only when actual synchronization is absent
- [ ] NTP provider probes tolerate one provider timeout if another works
- [ ] Redaction masks password/token/private key/DB URL values
- [ ] `bootstrap.sh` shell syntax checked on Linux-compatible shell
- [ ] No runtime config/secrets added to Git
- [ ] Runtime artifact builds from `packaging/runtime-manifest.txt`
- [ ] Artifact has one top-level `vps-bootstrap-v0.1.2/` directory
- [ ] Artifact contains only runtime allowlist
- [ ] Artifact excludes `AGENTS.md`, `README.md`, `docs/`, `tests/`, `.git/`, `.github/`, `site/`, `tools/`
- [ ] `SHA256SUMS` matches the runtime archive
- [ ] tag/version mismatch fails release build
- [ ] Runtime artifact rejects symlinks in manifest entries and allowlisted directories
- [ ] Failed artifact rebuild leaves previous `tar.gz` and `SHA256SUMS` unchanged
- [ ] Archive modes are deterministic: directories `0755`, `bootstrap.sh` `0755`, other files `0644`
- [ ] GitHub Release upload does not use `--clobber`

## v0.1.2 Ubuntu VPS checks

- [ ] Runtime artifact and `SHA256SUMS` are transferred without full repository checkout
- [ ] `sha256sum -c SHA256SUMS` passes before extraction
- [ ] `sudo bash bootstrap.sh` completes on Ubuntu 24.04 from extracted artifact
- [ ] `/usr/local/bin/vps-bootstrap` works
- [ ] `/usr/local/bin/vps-bootstrap` still works after moving/removing source checkout
- [ ] CLI shows server info
- [ ] `sudo vps-bootstrap preflight` prints OK/WARN/ERROR report
- [ ] warnings do not fail the run
- [ ] Time sane
- [ ] Time synchronization service healthy
- [ ] Actual synchronization achieved
- [ ] At least one usable NTP source
- [ ] `chrony` installed/configured only if required
- [ ] `sudo vps-bootstrap full` creates runtime directories
- [ ] `/var/lib/vps-bootstrap/state.json` is created
- [ ] `sudo vps-bootstrap resume` verifies and skips completed phases
- [ ] SSH port/authentication unchanged
- [ ] UFW rules unchanged
- [ ] Fail2ban configuration unchanged
- [ ] No Xray/3x-ui/PostgreSQL/Caddy/NaiveProxy/WARP/Telegram components installed

## Bootstrap

- [ ] Ubuntu detected
- [ ] architecture supported
- [ ] root/sudo available
- [ ] apt works
- [ ] DNS works
- [ ] Internet works
- [ ] time sane
- [ ] enough free disk
- [ ] base dependencies installed
- [ ] Python venv works

## System

- [ ] hostname correct
- [ ] timezone correct
- [ ] time sync active
- [ ] actual clock synchronization achieved
- [ ] at least one usable NTP source
- [ ] swap policy correct
- [ ] journald limits applied
- [ ] disk usage acceptable

## SSH

- [ ] sshd config validates
- [ ] expected port listening
- [ ] firewall allows expected port
- [ ] old port not removed too early
- [ ] second connection test recommended/performed where possible

## UFW

- [ ] default incoming policy correct
- [ ] default outgoing policy correct
- [ ] SSH allowed
- [ ] only required application ports open
- [ ] PostgreSQL not public unless explicitly requested

## Fail2ban

- [ ] service active
- [ ] SSH jail active
- [ ] status readable

## PostgreSQL

- [ ] service active
- [ ] expected bind address
- [ ] DB exists
- [ ] DB user exists
- [ ] authentication succeeds
- [ ] test query succeeds
- [ ] backup command works

## 3x-ui

- [ ] expected version
- [ ] service/container active
- [ ] panel port/path known
- [ ] database connection works
- [ ] no critical errors in recent logs
- [ ] backup created before upgrade

## Xray

- [ ] binary/core present
- [ ] expected version
- [ ] config valid
- [ ] service active
- [ ] inbound ports listening
- [ ] no critical start errors
- [ ] end-to-end test where possible

## Caddy / NaiveProxy

- [ ] correct Caddy build
- [ ] forwardproxy module present
- [ ] Caddyfile valid
- [ ] DNS matches VPS
- [ ] 80/443 situation understood
- [ ] TLS issued
- [ ] cover site works if configured
- [ ] authentication works
- [ ] proxy test succeeds

## WARP

- [ ] service active
- [ ] routing expected
- [ ] external IP expected
- [ ] SSH not affected
- [ ] Xray not affected
- [ ] Naive not affected
- [ ] DNS not broken

## Monitoring

- [ ] monitor executable installed
- [ ] manual run succeeds
- [ ] runtime low
- [ ] Telegram test delivered
- [ ] systemd service/timer valid
- [ ] timer enabled
- [ ] failure handling tested
- [ ] disk alert configured
- [ ] RAM/swap alert configured
- [ ] service alerts configured

## Backup

- [ ] config backup exists
- [ ] PostgreSQL dump exists if applicable
- [ ] backup file non-empty
- [ ] restore instructions documented
- [ ] secrets not committed

## Final

- [ ] no failed systemd units relevant to stack
- [ ] listening ports expected
- [ ] firewall expected
- [ ] disk has reserve
- [ ] logs do not show critical errors
- [ ] user receives summary
