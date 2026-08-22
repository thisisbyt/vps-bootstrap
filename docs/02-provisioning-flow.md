# Provisioning flow

## v0.1.3 implementation status

v0.1.3 расширяет безопасную базовую цепочку управляемыми phases `swap` и `ssh_hardening`:

```text
bootstrap.sh
    ↓
Python CLI
    ↓
preflight
    ↓
runtime directories / logging / config / state
    ↓
resume verification
    ↓
swap
    ↓
ssh_hardening
```

До `bootstrap.sh` в production flow находится отдельный шаг доставки:

```text
versioned runtime artifact
    ↓
SHA256 verification
    ↓
extract
    ↓
sudo bash bootstrap.sh
```

Artifact собирается из development repository по allowlist и не содержит `AGENTS.md`, `docs/`, `tests/`, `.git/`, `.github/` или `tools/`.

В v0.1.3 `Full v0.1.3 setup` выполняет:

- preflight;
- создание `/etc/vps-bootstrap/config`;
- создание `/etc/vps-bootstrap/secrets`;
- создание `/var/lib/vps-bootstrap`;
- создание `/var/log/vps-bootstrap`;
- создание non-secret config;
- managed time synchronization: фактическая синхронизация обязательна для успешной verification;
- managed swap: сохраняет существующий валидный swap или создаёт `/swapfile` только после discovery/validation;
- managed SSH hardening: учитывает Ubuntu 24.04 `ssh.socket`, проверяет configured/effective/actual state и использует безопасную двухпортовую миграцию;
- подготовку journald example в config area без применения;
- проверку наличия Ansible foundation.

В v0.1.3 не реализуются полноценные UFW/Fail2ban phases, hostname, sysctl networking, TLS и владельцы портов 80/443.

UFW в v0.1.3 только обнаруживается внутри SSH phase. Если UFW active и новый SSH port не разрешён, отключение старого SSH port блокируется или требует отдельного безопасного allow.

Hardening v0.1.1 дополнительно фиксирует:

- stable install layout в `/opt/vps-bootstrap`, независимый от исходного checkout;
- permissions verification/repair для `/etc/vps-bootstrap`, `/etc/vps-bootstrap/secrets`, `/var/lib/vps-bootstrap`, `/var/log/vps-bootstrap`;
- безопасные права state file `0640`;
- managed config drift repair с timestamped backup;
- разделение General DNS, General HTTPS connectivity и GitHub release/source availability.

Real VPS fixes v0.1.2 дополнительно фиксирует:

- `time_sync` больше не verified через `lambda: True`;
- preflight разделяет `System time looks sane`, `NTP service active/inactive`, `Clock synchronized/not synchronized`;
- base/full setup диагностирует NTP providers и использует managed chrony fallback, если штатная синхронизация не работает;
- install update в `/opt/vps-bootstrap` использует staged release и atomic symlink switch.
- production install использует runtime artifact вместо копирования всего repository на VPS.

Resume обязан перепроверять фазы со статусом `done`. Если verification проходит, выводится:

```text
SKIP <phase> [already configured]
```

Если verification обнаруживает drift, выводится:

```text
RECHECK / REPAIR <phase>
```

## Фаза 0. Bootstrap

Цель: получить минимальную среду выполнения.

Bootstrap запускается из распакованного runtime artifact. Каталог распаковки нужен только для первого запуска; после успешной установки `/usr/local/bin/vps-bootstrap` работает через `/opt/vps-bootstrap/current`.

Проверки:

- Ubuntu;
- поддерживаемая версия ОС;
- root/sudo;
- наличие `apt`;
- доступ к package repositories;
- отсутствие конфликтующего `apt/dpkg` lock;
- корректное время;
- DNS;
- Internet connectivity.

Устанавливаются только необходимые bootstrap dependencies.

## Фаза 1. Preflight

До изменения сервера собрать факты:

- hostname;
- OS/version;
- architecture;
- CPU;
- RAM;
- swap;
- filesystem;
- свободное место;
- public IPv4;
- IPv6;
- default route;
- DNS resolution;
- NTP/time sync;
- открытые/listening ports;
- текущий SSH port;
- существующий UFW;
- существующий Fail2ban;
- наличие Docker;
- наличие Xray;
- наличие 3x-ui;
- наличие Caddy;
- наличие WARP;
- наличие PostgreSQL;
- наличие предыдущего `vps-bootstrap`.

Показать краткий отчёт пользователю.

### Preflight time check

Preflight является read-only. Он отдельно показывает:

```text
[OK] System time looks sane
[OK/WARN] NTP service active/inactive
[OK/WARN] Clock synchronized/not synchronized
```

Если системное время выглядит разумным, отсутствие фактической синхронизации на preflight является WARN.

### Managed time synchronization during base setup

Base/full setup должен обеспечить фактическую синхронизацию:

1. Проверить `NTPSynchronized=yes` или эквивалентный достоверный status.
2. Если часы уже synchronized, не менять working provider.
3. Если service active, но synchronization нет, проверить несколько NTP providers из `versions.yml`.
4. Настроить managed chrony fallback через штатный Ubuntu apt.
5. Проверить `timedatectl`, `chronyc tracking`, `chronyc sources -v`.
6. Не считать active service достаточным доказательством.

## Фаза 2. Выбор профиля

Пример:

```text
1. Base system only
2. Xray + 3x-ui
3. NaiveProxy
4. Xray + 3x-ui + NaiveProxy
5. Monitoring only
6. Full installation (с выбором впн 2 3 или 4 варианта)
7. Custom
```

## Фаза 3. Сбор пользовательских данных

Запрашивать только то, что нельзя безопасно определить автоматически.

Примеры:

- желаемый SSH port;
- 3x-ui web panel port;
- домен;
- нужен ли IPv6;
- использовать ли PostgreSQL;
- пароль/генерация пароля;
- Telegram Bot Token;
- Telegram Chat ID;
- устанавливать ли WARP, в каком режиме;
- профиль proxy;
- какие порты разрешить;
- какой компонент занимает 443;
- использовать ли существующую конфигурацию.

Перед подтверждением вывести summary без секретов.

## Фаза 4. Базовая система

Ожидаемые задачи:

- `apt update`;
- опционально controlled upgrade;
- базовые пакеты;
- timezone;
- NTP/time sync;
- hostname, если пользователь меняет;
- swap, если требуется;
- system limits, если требуется;
- journald limits;
- log rotation;
- базовые sysctl-настройки, только обоснованные и документированные.

## Фаза 5. SSH

Безопасный порядок:

1. определить текущий SSH port;
2. проверить новый порт;
3. разрешить новый порт в firewall;
4. проверить конфиг `sshd`;
5. учесть что сейчас в новых системах порт надо еще менять в sudo systemctl edit ssh.socket;
5. применить;
6. убедиться, что sshd слушает новый порт;
7. только после этого предлагать удалить старое firewall rule;
8. при удалённой настройке по возможности попросить пользователя открыть вторую SSH-сессию для проверки.

Никогда не закрывать текущий SSH-доступ до проверки нового.

### v0.1.3 SSH hardening

SSH phase различает:

- configured state: файлы `sshd_config` и drop-ins;
- effective state: вывод `sshd -T`;
- systemd listener state: `ssh.service` или `ssh.socket`;
- actual TCP LISTEN: stable `ss -H -lntp` output parsed as listener address, port and owner process.

На Ubuntu 24.04 может использоваться `ssh.socket`. В этом режиме изменение `Port` в `sshd_config.d` само по себе не доказывает смену listener. Нужно выполнить `sshd -t`, `systemctl daemon-reload`, корректно применить `ssh.socket`, затем проверить `systemctl show/cat ssh.socket` и фактический `ss`.

При смене порта используется двухпортовая миграция:

```text
old_port + new_port
    -> verify new SSH/systemd listener
    -> user opens second SSH session on the new port
    -> only after explicit confirmation final port is applied
    -> auth hardening uses publickey-only validation only when explicitly requested
```

For port-only migration, the second session uses the current authentication policy:

```text
ssh -p NEW_PORT USER@SERVER_IP
```

Transition config keeps the current authentication policy. `PasswordAuthentication no`,
`KbdInteractiveAuthentication no` and stricter `PermitRootLogin` are written only
after the user explicitly requests auth hardening and confirms a second login made with:

```text
ssh -o PreferredAuthentications=publickey -o PasswordAuthentication=no -p NEW_PORT USER@SERVER_IP
```

`sudo vps-bootstrap ssh` reopens the SSH wizard explicitly even after `ssh_hardening`
was previously `done` or `skipped`. It always performs fresh discovery and keeps the
same two-port migration and rollback rules. `full` and `resume` remain conservative:
they verify/skip completed SSH state and do not reopen a skipped SSH wizard.

Before the first managed SSH write/restart, state is flushed to disk with
`interrupted_migration=true` and a migration stage such as `planned`,
`transition_applying`, `transition_active`, `awaiting_second_session` or
`finalizing`. Resume must preserve the old port by default and must not silently
complete finalization after a crash.

Пользователь должен увидеть предупреждение:

```text
НЕ ЗАКРЫВАЙТЕ ТЕКУЩУЮ SSH-СЕССИЮ
```

Локальный listener не доказывает доступность через внешний provider firewall/security group. Если такой firewall есть, пользователь должен разрешить новый TCP port в панели провайдера до подтверждения.

Если обнаружены custom systemd overrides или effective config не совпадает с ожидаемым managed drop-in, автоматическая миграция блокируется и требуется ручной разбор.

## Фаза 6. Firewall

- UFW;
- default deny incoming;
- default allow outgoing;
- разрешить SSH;
- разрешить только необходимые proxy/web ports;
- учитывать TCP/UDP отдельно;
- не открывать PostgreSQL наружу по умолчанию;
- выводить итоговый `ufw status numbered`.

Перед `ufw enable` проверить, что текущий SSH port разрешён.

## Фаза 7. Fail2ban

- установка;
- отдельный jail/local config;
- SSH jail;
- проверка `fail2ban-client status`;
- проверка конкретного jail;
- не задавать чрезмерно агрессивные значения без необходимости.

## Фаза 8. Xray / 3x-ui

Перед установкой:

- проверить занятые порты;
- определить существующую установку;
- сохранить backup;
- определить выбранную версию;
- проверить совместимость.


После установки:

- процесс запущен;
- systemd service active;
- нужные порты listening;
- конфигурация валидна;
- панель доступна по ожидаемому интерфейсу;
- БД доступна;
- Xray core запускается;
- нет критических ошибок в journal.

## Фаза 9. NaiveProxy / Caddy

Перед установкой:

- проверить DNS домена;
- проверить, куда указывает A/AAAA;
- проверить 80/443;
- определить конфликт с Xray;
- определить выбранную архитектуру совместного использования портов.

После установки:

- Caddy binary корректный;
- forwardproxy module присутствует;
- Caddyfile валиден;
- TLS получен;
- сайт-заглушка работает;
- authentication работает;
- proxy endpoint проходит тест;
- probe resistance/другие настройки проверены, если используются.

## Фаза 11. WARP

WARP — опциональный компонент.

Проверить:

- ресурсы сервера;
- диск;
- память;
- состояние сервиса;
- маршрутизацию;
- не ломает ли WARP доступ к 3x-ui/Xray/Naive/SSH.
- ставим WARP как сокс прокси

Не делать WARP обязательным для базовой установки.

## Фаза 12. Monitoring

Ожидаемые функции:

- CPU/load;
- RAM;
- swap;
- root filesystem;
- inode usage при необходимости;
- состояние критических systemd services;
- проверка listening ports;
- внешняя/локальная проверка endpoint;
- Telegram alerts;
- test message при настройке.

Рекомендуемый путь:

```text
/usr/local/bin/vps-monitor
```

Запуск через systemd timer предпочтительнее cron, если нет причин использовать cron.

## Фаза 13. Backup

Минимум:

- 3x-ui database;
- PostgreSQL dump, если PostgreSQL;
- Xray configs;
- Caddyfile;
- TLS-related config без приватных ключей в Git;
- monitoring config;
- installer runtime config;
- список установленных/зафиксированных версий.

Backup должен быть отделён от Git repository.

## Фаза 14. Final audit

Установка считается завершённой только после финального аудита.

Итог должен показывать:

```text
OS                OK
DNS               OK
Time sync         OK
SSH               OK
UFW               OK
Fail2ban          OK
PostgreSQL        OK/SKIP
3x-ui             OK/SKIP
Xray              OK/SKIP
NaiveProxy        OK/SKIP
TLS               OK/SKIP
WARP              OK/SKIP
Monitoring        OK/SKIP
Telegram          OK/SKIP
Backup            OK
Warnings          N
Errors            N
```
