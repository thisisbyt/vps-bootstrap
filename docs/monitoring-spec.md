# Monitoring specification

## 1. Назначение

Этот документ фиксирует целевую архитектуру мониторинга VPS для проекта **VPS Bootstrap**.

Мониторинг должен быть лёгким по CPU/RAM, независимым от 3x-ui, устойчивым к временной недоступности Telegram, не раскрывать секреты в логах и одинаково воспроизводиться на новых VPS.

Предпочтительная модель — короткоживущий скрипт + `systemd timer`, а не тяжёлый постоянно работающий daemon.

## 2. Канонические пути

```text
/usr/local/bin/tg-notify
/usr/local/bin/vps-monitor

/etc/tg-notify.env
/etc/vps-monitor.env

/var/lib/vps-monitor/

/etc/systemd/system/
    vps-monitor.service
    vps-monitor.timer
    vps-monitor-daily.service
    vps-monitor-daily.timer
    vps-monitor-boot.service
```

Названия unit-файлов могут быть уточнены при реализации, но разделение ответственности должно сохраниться.

## 3. `tg-notify`

`/usr/local/bin/tg-notify` — отдельная утилита отправки Telegram-сообщений.

Она отвечает только за:
- загрузку Telegram credentials;
- безопасную отправку сообщения;
- connect/total timeout;
- обработку сетевой ошибки;
- понятный exit code.

Она не должна знать, какие сервисы мониторятся и какие thresholds используются.

Telegram failure не должен подвешивать monitoring.

## 4. Telegram secrets

Хранить в:

```text
/etc/tg-notify.env
```

Формат:

```bash
BOT_TOKEN='...'
CHAT_ID='...'
```

Права:

```bash
sudo chown root:root /etc/tg-notify.env
sudo chmod 600 /etc/tg-notify.env
```

`BOT_TOKEN` и `CHAT_ID` не должны попадать в Git, systemd unit, stdout, install log или command line.

Установщик запрашивает их интерактивно. Bot Token желательно вводить скрыто.

## 5. Настройки monitor

Хранить отдельно:

```text
/etc/vps-monitor.env
```

Минимально:

```bash
SERVER_NAME='Example-NL'
```

`SERVER_NAME` — человеческое имя сервера и **не заменяет hostname**.

Пример:

```text
Server: Example-NL
Host: example-vps-01
```

В этом же файле могут храниться несекретные monitoring thresholds и расписание.

Рекомендуемые права:

```bash
sudo chown root:root /etc/vps-monitor.env
sudo chmod 600 /etc/vps-monitor.env
```

## 6. State

Runtime state хранить в:

```text
/var/lib/vps-monitor/
```

Он используется для:
- запоминания активных проблем;
- suppression повторных одинаковых alerts;
- определения recovery;
- timestamps/последнего состояния.

State не хранить в `/tmp`, Git checkout или home пользователя.

## 7. Режимы monitor

Основной executable:

```text
/usr/local/bin/vps-monitor
```

Целевые режимы:

```bash
vps-monitor check
vps-monitor daily
vps-monitor boot
```

Допускается эквивалентный CLI.

### Boot

После загрузки VPS отправляется одно короткое уведомление о том, что сервер снова доступен.

Boot notification не должен превращаться в полный daily report и не должен блокировать загрузку при недоступности Telegram.

### Emergency check

Выполняется **каждые 2 минуты**.

Это дешёвый health-check. В нём нельзя каждый раз вычислять версии компонентов и запускать тяжёлую диагностику.

### Daily report

Один раз в сутки отправляется информационный отчёт **независимо от наличия проблем**.

Точное время должно быть настраиваемым.

## 8. Emergency checks

Частый проход проверяет минимум:

### 3x-ui

Reference service:

```text
x-ui.service
```

Пример лёгкой проверки:

```bash
systemctl is-active --quiet x-ui.service
```

Но имя сервиса не должно безусловно hardcode-иться навсегда: provisioning должен передавать фактическое имя managed service.

### Xray

В одном из текущих reference-сценариев использовался процесс:

```text
xray-linux-amd64
```

Но имя binary/process зависит от installation mode. Monitor должен использовать metadata, созданную provisioning-модулем.

В emergency pass достаточно service/process health check. Версию здесь не получать.

### WARP

Если установлен:

```text
warp-svc.service
```

Если WARP не выбран — состояние `SKIP/not installed`, а не ошибка.

### Fail2Ban

Если установлен:

```text
fail2ban.service
```

В двухминутном проходе проверяется только health сервиса. Глубокая статистика относится к daily report.

### CPU

CPU должен входить в emergency monitoring.

Базовый порог уведомления:

```text
CPU_ALERT_PERCENT=80
```

Однако одиночный кратковременный скачок CPU выше 80% **не должен немедленно отправлять Telegram-alert**.

Чтобы избежать ложных тревог, alert отправляется только если:

```text
CPU >= 80%
```

наблюдается **3 последовательных emergency-проверки**.

При текущем интервале проверки 2 минуты это означает примерно 6 минут устойчивой высокой загрузки.

Логика состояния:

```text
CPU < 80%
    normal

CPU >= 80% один раз
    counter = 1
    alert не отправлять

CPU >= 80% второй раз подряд
    counter = 2
    alert не отправлять

CPU >= 80% третий раз подряд
    counter = 3
    отправить alert
    состояние = CPU_HIGH

CPU_HIGH и CPU >= 80%
    повторный одинаковый alert не отправлять

CPU_HIGH и CPU < 80% две проверки подряд
    отправить recovery
    сбросить состояние
```

Пример alert:

```text
VPS ALERT

Server: Example-NL
Host: example-vps-01

✗ CPU: 87% for ~6 min
```

Пример recovery:

```text
VPS RECOVERY

Server: Example-NL
Host: example-vps-01

✓ CPU returned to normal: 42%
```

CPU percentage должен измеряться лёгким способом без запуска тяжёлых диагностических инструментов.

State/counter высокой CPU-нагрузки хранится в:

```text
/var/lib/vps-monitor/
```

### RAM

Проверяется использование памяти.

Thresholds должны быть конфигурируемыми, например:

```text
RAM_WARN_PERCENT
RAM_CRIT_PERCENT
```

Не выдумывать значения молча, если они ещё не зафиксированы проектом.

### Disk

Проверяется основной filesystem VPS.

В пользовательском сообщении метрика называется:

```text
Disk
```

а не `Disk /`.

Disk check обязателен: в реальной эксплуатации уже встречалось заполнение root filesystem до 100%.

Thresholds конфигурируемые:

```text
DISK_WARN_PERCENT
DISK_CRIT_PERCENT
```

## 9. Что запрещено делать каждые 2 минуты

В emergency pass без необходимости не выполнять:
- получение версии Xray;
- получение версии 3x-ui;
- получение версии WARP;
- полный Fail2Ban status;
- `apt update`;
- package inventory;
- тяжёлые network diagnostics;
- подробный journal dump;
- внешние API кроме необходимой отправки alert.

Версии относятся к daily report.

## 10. Anti-spam

Одна и та же проблема не должна отправляться каждые 2 минуты.

Логика:

```text
OK -> ERROR
    отправить alert

ERROR -> ERROR
    не повторять тот же alert

ERROR -> OK
    отправить recovery

OK -> OK
    ничего не отправлять
```

Разные проблемы хранят state независимо.

## 11. Recovery notifications

После восстановления ранее сломанного состояния отправляется отдельное сообщение.

Пример:

```text
VPS RECOVERY

Server: Example-NL
Host: example-vps-01

✓ Xray is running again
```

## 12. Формат emergency alert

Сообщение должно сразу показывать:
- `Server`;
- `Host`;
- проблему;
- фактическое значение для метрики.

Пример:

```text
VPS ALERT

Server: Example-NL
Host: example-vps-01

✗ Xray is not running
```

или:

```text
VPS ALERT

Server: Example-NL
Host: example-vps-01

✗ Disk: 94%
```

## 13. Daily report

Daily report должен быть визуально спокойным: использовать секции и `✓/✗`, а не множество крупных emoji-кружков.

Сначала:

```text
Server: <human-readable server name>
Host: <system hostname>
```

### Порядок системных метрик

Согласованный порядок:

```text
Uptime
CPU
RAM
Swap
Disk
```

Правила:
- `Uptime` идёт первым;
- `Load` в Telegram daily report **не показывается**;
- метрика называется `Disk`, без технического `/`.

### Services

Минимально:

```text
3x-ui
Xray
WARP
Fail2Ban
```

Пример:

```text
Services
✓ 3x-ui
✓ Xray
✓ WARP
✓ Fail2Ban
```

Опциональный отсутствующий компонент отображается как `SKIP/not installed`, а не авария.

### Versions

В daily report показывать версии:

```text
3x-ui
Xray
WARP
```

Версии определяются только в daily/full report.

Способ получения версии должен зависеть от реального installation mode; нельзя навсегда предполагать фиксированный путь, Docker/native install или имя binary.

### Fail2Ban statistics

Daily report должен показывать полезную статистику, а не только `active`.

Минимум, если доступно:
- SSH jail;
- Currently banned;
- Total banned.

Имя jail должно браться из фактической конфигурации.

## 14. Канонический порядок Daily report

```text
VPS Daily Report

Server: Example-NL
Host: example-vps-01

System
Uptime: ...
CPU: ...
RAM: ...
Swap: ...
Disk: ...

Services
✓ 3x-ui
✓ Xray
✓ WARP
✓ Fail2Ban

Versions
3x-ui: ...
Xray: ...
WARP: ...

Fail2Ban
Currently banned: ...
Total banned: ...
```

Финальное форматирование можно улучшать, но coding-agent не должен:
- возвращать `Load`;
- переименовывать `Disk` в `Disk /`;
- убирать `Uptime`;
- объединять `Server` и `Host`;
- вычислять версии в двухминутном emergency pass.

## 15. Logging

Не логировать:
- Bot Token;
- Telegram API URL с token;
- credentials;
- private keys;
- subscription URL/token;
- DB password.

Для диагностики можно логировать:
- timestamp;
- mode запуска;
- результаты checks;
- Telegram send success/failure;
- state transition;
- execution time.

## 16. Performance

Monitor должен оставаться короткоживущим процессом.

После существенных изменений измерять:

```bash
sudo /usr/bin/time -v /usr/local/bin/vps-monitor check
```

Особенно следить за:

```text
Elapsed time
Maximum resident set size
CPU time
```

Не добавлять тяжёлую зависимость без необходимости.

## 17. systemd

Для VPS Bootstrap предпочтительны `systemd service + systemd timer`, а не cron.

Причины:
- `systemctl status`;
- `journalctl`;
- зависимости от сети;
- controlled timeout;
- предсказуемое boot behavior;
- единообразное управление.

Emergency timer: каждые 2 минуты.

Daily timer: раз в сутки, время конфигурируемое.

Boot unit: после `network-online.target`, но Telegram failure не блокирует boot.

## 18. Интеграция в provisioning

Monitoring module должен:

1. спросить, нужен ли Telegram monitoring;
2. спросить `SERVER_NAME`;
3. спросить `BOT_TOKEN`;
4. спросить `CHAT_ID`;
5. проверить credentials тестовым сообщением;
6. установить `tg-notify`;
7. установить `vps-monitor`;
8. создать `/etc/tg-notify.env`;
9. создать `/etc/vps-monitor.env`;
10. создать `/var/lib/vps-monitor`;
11. создать systemd units/timers;
12. выполнить `systemctl daemon-reload`;
13. enable/start timers;
14. вручную запустить emergency check;
15. вручную сформировать daily report;
16. измерить runtime;
17. показать финальный status.

Monitoring считается настроенным только после успешной тестовой отправки Telegram-сообщения.

## 19. Final validation

Проверить timers:

```bash
systemctl status vps-monitor.timer --no-pager
systemctl status vps-monitor-daily.timer --no-pager
systemctl list-timers --all
```

Проверить monitor:

```bash
sudo /usr/local/bin/vps-monitor check
sudo /usr/local/bin/vps-monitor daily
```

Измерить runtime:

```bash
sudo /usr/bin/time -v /usr/local/bin/vps-monitor check
```

Если при реализации выбраны другие unit names, installer должен выводить соответствующие реальные команды.

## 20. Обязательные решения для coding-agent

При реализации не менять без отдельного решения пользователя:

1. `SERVER_NAME` хранится отдельно от hostname.
2. `Uptime` идёт первым.
3. `Load` в daily Telegram report не показывается.
4. Метрика называется `Disk`, не `Disk /`.
5. Daily report отправляется каждый день независимо от наличия проблем.
6. Daily report содержит CPU.
7. Daily report содержит Fail2Ban statistics.
8. Daily report содержит версии 3x-ui, Xray и WARP.
9. Версии не вычисляются в двухминутном emergency pass.
10. Частый проход содержит только критические health checks.
11. CPU является emergency check: базовый порог `CPU_ALERT_PERCENT=80`.
12. CPU alert отправляется только после 3 последовательных проверок >= 80%, чтобы не реагировать на кратковременный пик.
13. CPU recovery отправляется после 2 последовательных проверок < 80%.
14. Для статусов использовать спокойную подачу `✓/✗`.
15. Telegram network calls всегда имеют timeout.
16. State хранится в `/var/lib/vps-monitor`.
17. Telegram secrets хранятся отдельно от source code.
18. Одинаковая авария не отправляется каждые 2 минуты.
19. После восстановления отправляется recovery notification.
20. Отсутствующий опциональный компонент не считается ошибкой.
21. Реальные service/process names должны приходить из provisioning metadata, а не навсегда hardcode-иться из старой установки.

## 21. Пока оставлять конфигурируемым

Если значения не зафиксированы отдельно в проекте, не выдумывать их молча:

- при необходимости пользовательский override для `CPU_ALERT_PERCENT` (project default = 80%);
- RAM warning threshold;
- RAM critical threshold;
- Disk warning threshold;
- Disk critical threshold;
- точное время daily report;
- service/process names будущих версий 3x-ui/Xray;
- наличие WARP.

## 22. Будущее расширение

Архитектура должна позволять позже добавить:
- TLS certificate expiry;
- HTTP endpoint probe;
- Xray inbound probe;
- NaiveProxy/Caddy status;
- PostgreSQL status;
- backup freshness;
- inode usage;
- reboot-required;
- security update status.

Такие проверки не должны автоматически попадать в двухминутный emergency pass, если они тяжёлые или не критичные.
