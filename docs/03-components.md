# Компоненты

## v0.1.2 scope

В v0.1.2 реализованы только bootstrap, Python CLI, preflight, state/resume, safe logging, base setup foundation, managed time synchronization fallback и Ansible skeleton.

Xray, 3x-ui, PostgreSQL, NaiveProxy, Caddy, WARP и Telegram monitoring имеют архитектурные места, но не устанавливаются.

Единственный новый managed system component в v0.1.2 — `chrony`, и только если фактическая синхронизация времени отсутствует.

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
