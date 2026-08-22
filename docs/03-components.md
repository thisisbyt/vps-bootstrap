# Компоненты

## v0.1.3 scope

В v0.1.3 реализованы bootstrap, Python CLI, preflight, state/resume, safe logging, base setup foundation, managed time synchronization fallback, managed swap, safe SSH hardening и Ansible skeleton.

Xray, 3x-ui, PostgreSQL, NaiveProxy, Caddy, WARP и Telegram monitoring имеют архитектурные места, но не устанавливаются.

v0.1.3 не добавляет Xray, 3x-ui, PostgreSQL, NaiveProxy, Caddy, WARP или Telegram monitoring.

## bootstrap.sh

Ответственность:

- минимальный вход на чистой Ubuntu;
- проверка ОС/root;
- установка bootstrap dependencies;
- получение/обновление проекта;
- создание venv;
- запуск Python CLI.

Не помещать в него бизнес-логику provisioning.

## Python CLI

Ответственность:

- UX;
- вопросы пользователю;
- валидация ответов;
- скрытый ввод секретов;
- генерация секретов;
- отображение плана;
- state/resume;
- запуск provisioning;
- финальный отчёт.

## Ansible

Ответственность:

- приведение системы к целевому состоянию;
- system packages;
- config files;
- services;
- users/groups;
- firewall;
- PostgreSQL;
- Xray;
- 3x-ui;
- Caddy/Naive;
- WARP;
- monitoring.

В v0.1.2 Ansible представлен `ansible/playbook.yml` как foundation. Он не применяется bootstrap-скриптом и не меняет ОС. Реальные роли будут добавляться отдельными версиями после фиксации pinned dependencies и verification-политики.

## Time synchronization

Ответственность:

- preflight read-only diagnostics;
- разделение sane system time, active NTP service и actual synchronization;
- managed fallback на chrony, если штатная синхронизация не работает;
- проверка нескольких NTP providers из `versions.yml`;
- verification по фактической synchronization, а не только active service.

## Swap

v0.1.3 safety notes:

- verifier checks active swap area, expected size, persistence, permissions and duplicate/conflicting `/swapfile` fstab entries;
- if `/swapfile` already exists but ownership by vps-bootstrap cannot be proven from safe state/fstab metadata, repair and creation are blocked;
- v0.1.3 must not run `mkswap`, `chmod`, truncate or delete an unknown existing `/swapfile`;
- drift repair is non-destructive: active managed swap with fstab or mode drift is repaired without running `mkswap`; size drift is blocked.

Ответственность:

- read-only discovery RAM, active swap, `/etc/fstab`, root filesystem, free space and `/swapfile`;
- не создавать второй swap, если уже есть активный валидный swap;
- создавать managed `/swapfile` только на поддерживаемом filesystem;
- использовать non-sparse файл, `0600`, `mkswap`, `swapon`;
- добавлять ровно одну managed запись в `/etc/fstab`;
- backup/atomic write/rollback для `/etc/fstab`;
- verifier проверяет active swap area, размер, persistence, permissions и отсутствие duplicate managed entries.

Btrfs/CoW и неизвестные filesystem блокируются до отдельной безопасной реализации.

## SSH hardening

v0.1.3 safety notes:

- discovery uses `ss -H -lntp` and keeps listener address, port and owner process;
- verifier accepts the expected port only when it is an SSH listener: `sshd` in classic service mode, or the effective `ssh.socket`/systemd listener in socket activation mode;
- stale old SSH listeners after final migration are drift, while unrelated services on other ports are allowed;
- candidate files are validated with `sshd -t` and `sshd -T` before socket/service reload or restart;
- transition keeps current auth settings; final `PasswordAuthentication no`, `KbdInteractiveAuthentication no` and stricter `PermitRootLogin` require a confirmed publickey-only second SSH login;
- interrupted migration state is written before managed SSH writes/restarts and resume never removes the old port automatically.
- `sudo vps-bootstrap ssh` is an explicit reconfiguration command; it performs fresh discovery and may reopen the SSH wizard even when the phase was previously `done` or `skipped`.

Ответственность:

- discovery `ssh.service`, `ssh.socket`, effective `sshd -T`, actual `ss -H -lntp`, drop-ins and overrides;
- выбор execution strategy: `ssh.socket`, classic `ssh.service` или blocked custom/ambiguous;
- managed drop-in `/etc/ssh/sshd_config.d/10-vps-bootstrap.conf`;
- проверка `sshd -t`, `sshd -T`, systemd listener и actual TCP LISTEN;
- двухпортовая миграция при смене port;
- блокировка опасных auth changes, если key-based access или sudo-capable non-root user не доказаны;
- повторная настройка через тот же production mechanism, без ручного редактирования `state.json`;
- UFW awareness без полноценной UFW management phase;
- rollback managed SSH config/systemd listener к старому port.

`systemctl is-active ssh` не является достаточной проверкой.

## Xray

Требования:

- версионирование;
- config validation;
- проверка systemd;
- проверка портов;
- backup перед заменой конфигурации;
- логирование без избыточного шума.
- ставится панелью 3x-ui

## 3x-ui

Требования:

- версия должна быть явно определена;
- способ установки должен быть воспроизводим;
- БД должна быть сохранена перед обновлением;
- PostgreSQL предпочтителен для новых установок, если поддерживается;
- web port/path должны быть определены и проверены;
- не публиковать панель больше, чем требуется;
- учитывать reverse proxy/localhost binding, если используется.

## NaiveProxy

Используется Caddy fork/build с forwardproxy.

Требования:

- проверка нужного module;
- basic auth credentials только в secrets;
- TLS;
- DNS preflight;
- проверка 443 conflict;
- file_server/site cover, если выбран;
- функциональный end-to-end тест proxy.

## Caddy

Перед перезапуском:

```bash
caddy validate --config /etc/caddy/Caddyfile
```

или эквивалент для установленной сборки.

Не заменять работающую конфигурацию без backup/validation.

## WARP

Опционально.

Особое внимание:

- RAM;
- swap;
- disk;
- service health;
- routing;
- DNS;
- влияние на исходящий IP и существующие proxy routes.

## Monitoring

Монитор должен быть лёгким.

Нежелательно запускать тяжёлые процессы ради каждого health check.

Проверки должны иметь timeout.

Telegram send failures не должны подвешивать сам monitor.

## Journald

На небольших VPS обязательно контролировать объём journal, чтобы логи не заполняли диск.

Пример целевой политики определяется конфигурацией проекта, а не жёстко прошивается без возможности изменения.
