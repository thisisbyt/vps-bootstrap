# Validation checklist

## v0.2.0 local checks

- [ ] `versions.yml` project version is `0.2.0`
- [ ] `base` scope remains conservative and excludes `swap`, `admin_user`, `root_hardening`, `firewall`, `fail2ban`, and `ssh_hardening`
- [ ] `full` scope includes `admin_user`, `root_hardening`, `firewall`, `fail2ban`, `ssh_hardening`, and `security_updates`
- [ ] `admin_user` rejects `root` and invalid usernames
- [ ] `admin_user` validates SSH public keys and stores only username/fingerprint/validation state
- [ ] `admin_user` requires publickey-only second SSH session and sudo validation
- [ ] publickey-only second-session instructions show generic `-i <path-to-private-key>` and `IdentitiesOnly=yes`, while explaining when ssh-agent/OpenSSH config/default identity makes them optional
- [ ] password-required sudo uses the system `passwd` tool without Python reading the password
- [ ] password-required sudo validation runs `sudo -k`, requires the first `sudo -n true` to fail, then requires `sudo -v` and a successful post-authentication `sudo -n true`
- [ ] NOPASSWD sudo validation runs `sudo -k`, `sudo -n true`, and `sudo -n whoami` without `sudo -v`; the final command reports `root`
- [ ] NOPASSWD sudo uses only `/etc/sudoers.d/10-vps-bootstrap-admin`, mode `0440`, exact-user policy, and `visudo -cf`
- [ ] switching back to password-required removes only the managed sudoers drop-in
- [ ] root authorized-key cleanup creates an immutable root-only backup and stores fingerprints rather than key bodies
- [ ] root password lock default depends on whether the non-root admin has a verified local recovery password
- [ ] root shell/account expiry are unchanged and legacy `%admin` access is warning-only
- [ ] sensitive path modes and ownership match the documented permission matrix
- [ ] UFW phase never uses `ufw reset`
- [ ] UFW managed SSH rules use an identifiable vps-bootstrap comment
- [ ] UFW preserves unrelated rules
- [ ] Fail2ban recommended preset is rendered for SSH only
- [ ] Fail2ban customized values are validated
- [ ] Fail2ban verifies valid configuration, active service, active `sshd` jail, actual SSH port, and no conflicting effective `[sshd] port` override
- [ ] SSH migration prepares managed UFW before SSH transition
- [ ] SSH migration updates managed Fail2ban to OLD+NEW during transition
- [ ] SSH rollback restores and verifies OLD UFW access before restoring SSH, restores managed Fail2ban, and removes temporary NEW UFW access only after the OLD path is proven usable
- [ ] Successful SSH migration/rollback synchronizes persisted firewall and Fail2ban phase state
- [ ] Interrupted SSH recovery runs before ordinary firewall/Fail2ban drift handling
- [ ] Security unattended upgrades are enabled
- [ ] Automatic reboot remains disabled
- [ ] Unit tests remain hermetic and do not depend on host `/etc`, systemd, UFW, Fail2ban, or network state

## v0.2.0 Ubuntu VPS checks

- [ ] Fresh install from runtime artifact succeeds on Ubuntu 24.04
- [ ] `sudo vps-bootstrap admin-user` validates a second publickey-only admin login and sudo
- [ ] `sudo vps-bootstrap root-hardening` runs only after validated alternate admin access
- [ ] `sudo vps-bootstrap firewall` enables UFW without breaking SSH
- [ ] `sudo vps-bootstrap fail2ban` enables SSH jail for the actual SSH port
- [ ] `sudo vps-bootstrap ssh` migrates OLD_PORT -> NEW_PORT with managed UFW and Fail2ban
- [ ] Failed second-session confirmation rolls back safely
- [ ] `sudo vps-bootstrap security-updates` enables security updates, verifies an effective Ubuntu security origin, and leaves auto reboot disabled
- [ ] Re-running `sudo vps-bootstrap full` verifies and skips completed phases

## v0.1.2 local checks

- [ ] Python modules compile
- [ ] Unit tests pass
- [ ] CLI imports successfully
- [ ] State file roundtrip works
- [ ] Resume skips verified `done` phases
- [ ] Resume repairs drifted `done` phases
- [ ] State save creates `/var/lib/vps-bootstrap` with `0700` and state file with `0600`
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
- [ ] Artifact excludes `AGENTS.md`, `README.md`, `docs/`, `tests/`, `.git/`, `.github/`, `tools/`
- [ ] `SHA256SUMS` matches the runtime archive
- [ ] tag/version mismatch fails release build
- [ ] Runtime artifact rejects symlinks in manifest entries and allowlisted directories
- [ ] Failed artifact rebuild leaves previous `tar.gz` and `SHA256SUMS` unchanged
- [ ] Archive modes are deterministic: directories `0755`, `bootstrap.sh` `0755`, other files `0644`
- [ ] GitHub Release upload does not use `--clobber`

## v0.1.3 local checks

- [ ] `versions.yml` project version is `0.1.3`
- [ ] State supports non-secret phase metadata
- [ ] Resume verifies `done` swap and SSH phases before skip
- [ ] Swap discovery handles `/proc/swaps`, `swapon --show`, `/etc/fstab`, filesystem and `/swapfile`
- [ ] Existing active swap is preserved and no duplicate swap is created
- [ ] Managed swap verifies active area, size, fstab persistence and `0600`
- [ ] Managed swap detects duplicate fstab entries
- [ ] Managed swap rolls back `/etc/fstab` and new swapfile after activation failure
- [ ] Unsupported filesystem blocks managed swapfile creation
- [ ] SSH discovery distinguishes configured, effective, systemd and actual listener state
- [ ] SSH detects `ssh.socket` vs classic `ssh.service`
- [ ] SSH blocks custom/ambiguous systemd overrides
- [ ] SSH verifier fails if `sshd -T` shows new port but `ss` still shows old port
- [ ] SSH port randomization avoids occupied ports
- [ ] SSH two-port transition preserves old port until second session is confirmed
- [ ] SSH auth-hardening validation explains how to select the client-side private key without storing or guessing its path
- [ ] root-disable sudo validation follows the selected password-required or NOPASSWD admin policy
- [ ] SSH rollback restores old listener after failed new listener
- [ ] `sudo vps-bootstrap ssh` reopens SSH configuration after `done` or `skipped`
- [ ] Repeated SSH migration uses fresh discovery of the current port
- [ ] Port-only second-session validation uses `ssh -p NEW_PORT USER@SERVER_IP`
- [ ] SSH yes/no prompts accept strict `y`/`yes` including NFKC full-width forms
- [ ] Active UFW without new allow rule blocks unsafe finalization
- [ ] Password auth disable is blocked without publickey-only second-session confirmation
- [ ] `PermitRootLogin no` is blocked without verified sudo-capable non-root user
- [ ] managed SSH config and effective `sshd -T` both require `PermitEmptyPasswords no`
- [ ] Interrupted SSH migration resume does not blindly disable old port

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

## v0.1.3 Ubuntu VPS checks

- [ ] Existing provider/user swap is discovered and preserved
- [ ] No-swap VPS can create recommended `/swapfile`
- [ ] `/etc/fstab` backup is created before managed swap persistence change
- [ ] Re-running `sudo vps-bootstrap resume` skips verified swap
- [ ] Swap drift is detected if `/swapfile` is inactive or permissions drift
- [ ] SSH discovery reports `ssh.socket` or `ssh.service` accurately
- [ ] SSH port migration first exposes old and new ports simultaneously
- [ ] User can open a second SSH session before old port removal
- [ ] If user answers `N`, old SSH port remains/restores
- [ ] External provider firewall/security group requirement is shown to user
- [ ] UFW active without new port allow does not remove old SSH port

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
