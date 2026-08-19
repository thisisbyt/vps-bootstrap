# Provisioning flow

## v0.1.2 implementation status

Первая рабочая версия ограничена безопасной базовой цепочкой:

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

Artifact собирается из development repository по allowlist и не содержит `AGENTS.md`, `docs/`, `tests/`, `.git/`, `.github/`, `site/` или `tools/`.

В v0.1.2 `Full v0.1.2 setup` выполняет:

- preflight;
- создание `/etc/vps-bootstrap/config`;
- создание `/etc/vps-bootstrap/secrets`;
- создание `/var/lib/vps-bootstrap`;
- создание `/var/log/vps-bootstrap`;
- создание non-secret config;
- managed time synchronization: фактическая синхронизация обязательна для успешной verification;
- подготовку journald example в config area без применения;
- проверку наличия Ansible foundation.

В v0.1.2 не изменяются SSH, firewall, Fail2ban, hostname, swap, sysctl networking, TLS и владельцы портов 80/443.

Единственный новый managed component в v0.1.2 — `chrony`, и только как fallback для time synchronization.

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
