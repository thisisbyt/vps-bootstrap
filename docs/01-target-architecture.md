# Целевая архитектура

## Верхнеуровневая схема

```text
Versioned runtime artifact
      |
      v
Fresh Ubuntu VPS
      |
      v
bootstrap.sh
      |
      +-- apt install base dependencies
      |
      v
Python CLI / Wizard
      |
      +-- collect user choices
      +-- collect/generate secrets
      +-- build runtime config
      +-- save non-secret state
      |
      v
Provisioning engine
(Ansible roles + helper modules)
      |
      +-- system
      +-- security
      +-- database
      +-- xray / 3x-ui
      +-- naiveproxy / caddy
      +-- warp
      +-- monitoring
      +-- backups
      |
      v
Verification layer
      |
      v
Final audit
```

## Почему нужен bootstrap.sh

На свежей Ubuntu нельзя считать гарантированно установленными:

- Python;
- pip;
- venv;
- Git;
- Ansible;
- curl;
- wget;
- jq;
- unzip;
- DNS-утилиты.

Поэтому первая точка входа должна зависеть только от Bash и стандартных средств Ubuntu.

Bootstrap должен быть минимальным и максимально стабильным.

## Source, artifact и installed product

Проект разделяет три слоя:

```text
Development repository
    -> Release artifact
    -> Installed VPS Bootstrap
```

Development repository содержит `AGENTS.md`, `docs/`, `tests/`, `tools/`, `.github/workflows/` и runtime sources.

Release artifact содержит только explicit allowlist из `packaging/runtime-manifest.txt`:

```text
bootstrap.sh
requirements.txt
versions.yml
app/
ansible/
templates/
```

Installed VPS Bootstrap живёт в `/opt/vps-bootstrap/releases/<release>/`, переключается через `/opt/vps-bootstrap/current` и запускается wrapper-командой `/usr/local/bin/vps-bootstrap`.

Production VPS не должен получать Git history, development docs, tests или Codex/agent instructions.

## Пример ответственности bootstrap

- проверка запуска от root/sudo;
- определение Ubuntu/version;
- `apt-get update`;
- установка `ca-certificates`;
- установка `curl`;
- установка `git`, если он нужен для получения репозитория;
- установка `python3`;
- установка `python3-venv`;
- создание virtualenv;
- установка pinned Python dependencies;
- передача управления Python CLI.

Для production install Git не является способом доставки проекта. Доставка идёт через immutable versioned release artifact с SHA256 verification.

## Базовые пакеты

Не устанавливать всё подряд. Пакеты должны быть привязаны к функциям проекта.

Предварительный baseline:

```text
ca-certificates
curl
git
python3
python3-venv
python3-pip
jq
unzip
tar
gzip
openssl
gnupg
lsb-release
iproute2
dnsutils
procps
util-linux
```

По необходимости:

```text
rsync
socat
net-tools
lsof
sqlite3        # только если действительно используется SQLite
postgresql-*   # только при выбранном PostgreSQL-модуле
```

Перед добавлением пакета в baseline нужно понимать, зачем он нужен.

## Python environment

Предпочтительно использовать отдельный venv, например:

```text
/opt/vps-bootstrap/current/venv
```

Не засорять system Python пакетами через глобальный `pip install`, если этого можно избежать.

## State

Runtime state должен находиться вне Git checkout, например:

```text
/var/lib/vps-bootstrap/state.json
/etc/vps-bootstrap/config.yml
/etc/vps-bootstrap/secrets.env
/var/log/vps-bootstrap/
```

Пример прав:

```text
/etc/vps-bootstrap/              root:root 0750
/etc/vps-bootstrap/secrets.env   root:root 0600
```

State и secrets — разные сущности.

## База 3x-ui

Для новых установок:

- предпочитать PostgreSQL, если выбранная версия 3x-ui его поддерживает;
- не предполагать конкретный способ конфигурации БД без проверки версии;
- создавать отдельного DB user;
- использовать отдельную DB;
- генерировать сильный пароль;
- не публиковать PostgreSQL наружу без явной необходимости;
- слушать localhost/private interface, если архитектура не требует иного;
- выполнять backup до обновлений панели/схемы БД.

SQLite может поддерживаться как отдельный compatibility mode, но не является предпочтительным выбором для новых установок.
